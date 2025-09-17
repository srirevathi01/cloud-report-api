from fastapi import APIRouter, Query, HTTPException, Request
import boto3, json
from typing import List, Dict, Optional
from botocore.exceptions import ClientError

router = APIRouter()

@router.get("/storage")
def list_storage(service: Optional[str] = Query(None), region: Optional[str] = Query("us-east-1")):
    services = {}
    
    if service == "s3" or service is None:
        services["s3"] = list_s3_buckets(region)
    
    if service == "efs" or service is None:
        services["efs"] = list_efs_file_systems(region)
    
    if service == "ebs" or service is None:
        services["ebs"] = list_ebs_volumes(region)

    return services

def list_s3_buckets(region: str) -> List[str]:
    s3 = boto3.client("s3")
    result = []
    try:
        buckets = s3.list_buckets()
        for bucket in buckets['Buckets']:
            try:
                location = s3.get_bucket_location(Bucket=bucket['Name'])['LocationConstraint']
                if location is None:
                    location = "us-east-1"
                if location == region:
                    result.append(bucket['Name'])
            except Exception:
                continue
    except Exception as e:
        return [f"Error listing S3 buckets: {str(e)}"]
    return result

def list_efs_file_systems(region: str) -> List[str]:
    efs = boto3.client('efs', region_name=region)
    try:
        fs = efs.describe_file_systems()
        return [fs_item['FileSystemId'] for fs_item in fs['FileSystems']]
    except Exception as e:
        return [f"Error listing EFS: {str(e)}"]

def list_ebs_volumes(region: str) -> List[Dict]:
    ec2 = boto3.client('ec2', region_name=region)
    try:
        volumes = ec2.describe_volumes()
        return [
            {
                "VolumeId": vol["VolumeId"],
                "State": vol["State"],
                "AvailabilityZone": vol["AvailabilityZone"]
            }
            for vol in volumes['Volumes']
        ]
    except Exception as e:
        return [{"Error": str(e)}]

@router.post("/audit")
async def service_audit(request: Request):
    audit_details = {}
    body = await request.json()
    print(body)
    exit()
    bucket = body.get("bucket_name", "").strip()
    region = body.get("region_name", "").strip()
    service = body.get("service", "").strip()
    if not bucket or not region:
        raise HTTPException(status_code=400, detail="'bucket_name','region_name' and 'service' are required.")
    if service == "s3" or service is None:
        audit_details = audit_bucket(bucket, region)
    
    return audit_details

def safe_call(func, error_msg, *args, **kwargs):
    try:
        return func(*args, **kwargs), None
    except ClientError:
        return None, error_msg

def audit_bucket(bucket, region):
    s3 = boto3.client("s3")

    compliant = []
    non_compliant = []
    unknown = []

    def record(result, ok_msg, fail_msg, check_fn):
        if result is None:
            unknown.append(fail_msg)
        elif check_fn(result):
            compliant.append(ok_msg)
        else:
            non_compliant.append(fail_msg)

    # 1. Public Access
    data, err = safe_call(s3.get_bucket_policy_status, "Could not determine bucket public access policy.", Bucket=bucket)
    record(data, "Bucket policy does not allow public access.", "Bucket policy allows public access.", 
        lambda r: not r.get("PolicyStatus", {}).get("IsPublic", True))

    # 2. Default Encryption
    data, err = safe_call(s3.get_bucket_encryption, "Default encryption is NOT enabled.", Bucket=bucket)
    record(data, "Default encryption is enabled.", "Default encryption is NOT enabled.", 
        lambda r: bool(r))

    # 3. ACLs
    data, err = safe_call(s3.get_bucket_acl, "Could not check ACLs.", Bucket=bucket)
    record(data, "No public ACLs.", "Bucket has public ACL permissions.", 
        lambda r: all(g.get("Grantee", {}).get("URI") not in [
            "http://acs.amazonaws.com/groups/global/AllUsers",
            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
        ] for g in r.get("Grants", [])))

    # 4. Policy Wildcards
    data, err = safe_call(s3.get_bucket_policy, "No bucket policy found or unable to fetch.", Bucket=bucket)
    def has_no_wildcards(policy):
        try:
            doc = json.loads(policy["Policy"])
            for stmt in doc.get("Statement", []):
                if stmt.get("Principal") == "*" or stmt.get("Action") == "*":
                    return False
            return True
        except:
            return False
    record(data, "Bucket policy avoids wildcards.", "Bucket policy uses wildcard * — security risk.", has_no_wildcards)

    # 5. Versioning
    data, err = safe_call(s3.get_bucket_versioning, "Could not check versioning.", Bucket=bucket)
    record(data, "Versioning is enabled.", "Versioning is NOT enabled.", 
        lambda r: r.get("Status") == "Enabled")

    # 6. Logging
    data, err = safe_call(s3.get_bucket_logging, "Could not check access logging.", Bucket=bucket)
    record(data, "Access logging is enabled.", "Access logging is NOT enabled.", 
        lambda r: "LoggingEnabled" in r)

    # 7. MFA Delete
    data, err = safe_call(s3.get_bucket_versioning, "Could not determine MFA Delete status.", Bucket=bucket)
    record(data, "MFA Delete is enabled.", "MFA Delete is NOT enabled.", 
        lambda r: r.get("MFADelete") == "Enabled")

    # 8. Ownership Controls
    data, err = safe_call(s3.get_bucket_ownership_controls, "Could not check object ownership.", Bucket=bucket)
    record(data, "Object ownership is enforced (ACLs disabled).", "Object ownership is not enforced.", 
        lambda r: any(rule.get("ObjectOwnership") == "BucketOwnerEnforced" for rule in r.get("OwnershipControls", {}).get("Rules", [])))

    return {
        "bucket": bucket,
        "region": region,
        "result": {
            "compliant": compliant,
            "non_compliant": non_compliant,
            "unknown": unknown
        }
    }