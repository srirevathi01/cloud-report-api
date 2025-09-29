#listing databases using API

from fastapi import APIRouter, Query , HTTPException, Request
import boto3
from pydantic import BaseModel
from botocore.exceptions import BotoCoreError, ClientError

router = APIRouter()

class ResourceIds(BaseModel):
    ids: list[str] 
    
#To list all databases
@router.get("/databases")
def list_database_services( request: Request, account_id: str = Query(None)):
    
    return {
        "RDS/AURORA",
        "dynamodb",
        "elasticache"
        }
    
#For a specific database service (rds/aurora,dynamodb,elasticache)    
@router.get("/databases/{service_name}")
def list_service_resources(
    service_name: str,
    request: Request,
    account_id: str = Query(None), region : str ="us-east-1"
):
   
    try:
        # Temporary credentials from middleware
        session = request.state.session

        #to list RDS
        if service_name == "rds":
            rds = session.client(
                "rds",
                region_name = region,
            )
            instances = rds.describe_db_instances()["DBInstances"]
            return {
                "service_name": "RDS/Aurora",
                "instances": [
                    {
                        "DBInstanceIdentifier": db["DBInstanceIdentifier"],
                        "Engine": db["Engine"],
                        "Status": db["DBInstanceStatus"]
                    }
                    for db in instances
                ],
                "total": len(instances)
            }
            
        #to list dynamodb
        elif service_name == "dynamodb":
            dynamodb = session.client(
                "dynamodb",
                region_name=region,
            )
            tables = dynamodb.list_tables()["TableNames"]
            return {
                "service_name": "DynamoDB",
                "table": tables,
                "total": len(tables)
            }
            tables
        #to list elasticache
        elif service_name == "elasticache":
            elasticache = session.client(
                "elasticache",
                region_name=region,
            )
            clusters = elasticache.describe_cache_clusters()["CacheClusters"]
            return {
                "service_name": "ElastiCache",
                "clusters": [
                    {
                        "ClusterId": c["CacheClusterId"],
                        "Engine": c["Engine"],
                        "Status": c["CacheClusterStatus"]
                    }
                    for c in clusters
                ],
                "total": len(clusters)
            }

        else:
            raise HTTPException(
                status_code=400,
                detail="Supported services: rds, dynamodb, elasticache"
            )

    except (BotoCoreError, ClientError) as e:
        raise HTTPException(status_code=500, detail=str(e))


#POST/ to list exact data details

@router.post("/databases/{service_name}")
def describe_specific_resources(
    service_name: str,
    request: Request,
    resource_ids: ResourceIds,      
    account_id: str = Query(None),
    region: str = "us-east-1",
):
    
    try:
        session = request.state.session
        if service_name == "rds":
            rds = session.client(
                "rds",
                region_name=region,
            )
            details = rds.describe_db_instances(
                DBInstanceIdentifier=resource_ids.ids[0]
            ) if len(resource_ids.ids) == 1 else rds.describe_db_instances(
                Filters=[{"Name": "db-instance-id", "Values": resource_ids.ids}]
            )
            return {"service": "RDS/Aurora", "resources": details["DBInstances"]}

        elif service_name == "dynamodb":
            dynamodb = session.client(
                "dynamodb",
                region_name=region,
            )

            tables_info = []
            for t in resource_ids.ids:
                t_desc = dynamodb.describe_table(TableName=t)["Table"]
                tables_info.append({
                    "TableName": t_desc["TableName"],
                    "Status": t_desc["TableStatus"], 
                    "SizeBytes": t_desc["TableSizeBytes"],
                    "ItemCount": t_desc["ItemCount"] 
                     })
                
            return {"service": "DynamoDB", "resources": tables_info}
        

        elif service_name == "elasticache":
            elasticache = session.client(
                "elasticache",
                region_name=region,
            )
            
            clusters_info = []
            for cid in resource_ids.ids:
                clusters_info.append(
                    elasticache.describe_cache_clusters(
                        CacheClusterId=cid, ShowCacheNodeInfo=True
                    )["CacheClusters"][0]
                )
            return {"service": "ElastiCache", "resources": clusters_info}
        
        elif service == "cloudtrail":
            client = session.client("cloudtrail", region_name=region)
            events = client.lookup_events(
                StartTime=start,
                EndTime=end,
                MaxResults=50
            )
            simplified = [
                {
                    "event_time": e["EventTime"],
                    "event_name": e["EventName"],
                    "username": e.get("Username"),
                    "source_ip": e.get("SourceIPAddress"),
                }
                for e in events.get("Events", [])
            ]
            return {"service": "cloudtrail", "logs": simplified}
        elif service == "vpc-flow":
            ec2 = session.client("ec2", region_name=region)
            flow_logs = ec2.describe_flow_logs()["FlowLogs"]
            filtered = []
            for f in flow_logs:
                creation_time = f["CreationTime"]
                if not isinstance(creation_time, datetime):
                    try:
                        creation_time = datetime.fromisoformat(str(creation_time))
                        if creation_time.tzinfo is not None:
                            creation_time = creation_time.astimezone(tz=None).replace(tzinfo=None)
                    except Exception:
                        continue
                if creation_time >= start:
                    filtered.append(f)
            return {"service": "vpc-flow", "logs": filtered}
        elif service == "s3-access":
            if not bucket_name:
                raise HTTPException(400, "bucket_name is required")
            s3 = session.client("s3", region_name=region)
            objects = s3.list_objects_v2(Bucket=bucket_name)
            logs = []
            for obj in objects.get("Contents", []):
                lm = obj["LastModified"]
                if lm.tzinfo is not None:
                    lm = lm.astimezone(tz=None).replace(tzinfo=None)
                if start <= lm <= end:
                    logs.append({"key": obj["Key"], "last_modified": obj["LastModified"]})
            return {"service": "s3-access", "logs": logs}
        elif service == "load-balancer":
            if not load_balancer_arn:
                raise HTTPException(400, "load_balancer_arn is required")
            elb = session.client("elbv2", region_name=region)
            tags = elb.describe_tags(ResourceArns=[load_balancer_arn])
            return {
                "service": "load-balancer",
                "logs": {"LoadBalancerArn": load_balancer_arn, "Tags": tags.get("TagDescriptions", [])}
            }
        else:
                raise HTTPException(
                status_code=400,
                detail="Supported services: rds, dynamodb, elasticache",
            )
            
    except (BotoCoreError, ClientError) as e:
        raise HTTPException(status_code=500, detail=str(e))
    