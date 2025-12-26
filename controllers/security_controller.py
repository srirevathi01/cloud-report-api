"""
AWS Security & IAM Services Controller
Handles IAM, KMS, and WAF resources with comprehensive security and compliance recommendations
"""

from fastapi import APIRouter, Request, HTTPException, Query, Body
from pydantic import BaseModel, Field, validator
from botocore.exceptions import ClientError, BotoCoreError
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import logging
import time
import json

router = APIRouter()
logger = logging.getLogger(__name__)

# ============================================================================
# CONSTANTS
# ============================================================================
SECURITY_SERVICES = ["iam", "kms", "waf"]
CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_TTL = 300  # 5 minutes

# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class ResourceIdsRequest(BaseModel):
    """Request model for fetching multiple resource details"""
    resource_ids: List[str] = Field(
        ..., 
        min_items=1, 
        max_items=50,
        description="List of resource IDs to fetch details for",
        example=["user-name", "key-id-123"]
    )
    
    @validator('resource_ids')
    def validate_resource_ids(cls, v):
        if not all(isinstance(rid, str) and rid.strip() for rid in v):
            raise ValueError("All resource IDs must be non-empty strings")
        return v


class StandardResponse(BaseModel):
    """Standard response format for all APIs"""
    status: str = Field(description="Response status: success or error")
    message: str = Field(description="Human-readable message")
    data: Optional[Any] = Field(default=None, description="Response data")
    errors: Optional[List[str]] = Field(default=None, description="List of errors if any")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional metadata")


class IAMUserBasic(BaseModel):
    """Basic IAM user information"""
    UserName: str
    UserId: str
    Arn: str
    CreateDate: str
    PasswordLastUsed: Optional[str] = None


class IAMUserDetail(BaseModel):
    """Detailed IAM user information with security analysis"""
    UserName: str
    UserId: str
    Arn: str
    CreateDate: str
    PasswordLastUsed: Optional[str] = None
    Path: str
    PermissionsBoundary: Optional[Dict[str, str]] = None
    Tags: List[Dict[str, str]] = []
    Groups: List[str] = []
    AttachedPolicies: List[Dict[str, str]] = []
    InlinePolicies: List[str] = []
    AccessKeys: List[Dict[str, Any]] = []
    MFADevices: List[Dict[str, Any]] = []
    LoginProfile: Optional[Dict[str, Any]] = None
    recommendations: List[Dict[str, Any]] = []
    security_findings: List[Dict[str, Any]] = []


class IAMRoleBasic(BaseModel):
    """Basic IAM role information"""
    RoleName: str
    RoleId: str
    Arn: str
    CreateDate: str
    MaxSessionDuration: int


class IAMRoleDetail(BaseModel):
    """Detailed IAM role information with security analysis"""
    RoleName: str
    RoleId: str
    Arn: str
    CreateDate: str
    Path: str
    AssumeRolePolicyDocument: Dict[str, Any]
    MaxSessionDuration: int
    PermissionsBoundary: Optional[Dict[str, str]] = None
    Tags: List[Dict[str, str]] = []
    AttachedPolicies: List[Dict[str, str]] = []
    InlinePolicies: List[str] = []
    LastUsed: Optional[Dict[str, Any]] = None
    recommendations: List[Dict[str, Any]] = []
    security_findings: List[Dict[str, Any]] = []


class KMSKeyBasic(BaseModel):
    """Basic KMS key information"""
    KeyId: str
    KeyArn: str
    KeyState: str
    Enabled: bool
    CreationDate: Optional[str] = None


class KMSKeyDetail(BaseModel):
    """Detailed KMS key information with security analysis"""
    KeyId: str
    KeyArn: str
    AWSAccountId: str
    KeyState: str
    Enabled: bool
    Description: Optional[str] = None
    KeyUsage: str
    KeyManager: str
    CustomerMasterKeySpec: str
    CreationDate: str
    DeletionDate: Optional[str] = None
    Origin: str
    MultiRegion: bool
    KeyRotationEnabled: bool = False
    Aliases: List[str] = []
    Tags: List[Dict[str, str]] = []
    KeyPolicy: Optional[Dict[str, Any]] = None
    Grants: List[Dict[str, Any]] = []
    recommendations: List[Dict[str, Any]] = []
    security_findings: List[Dict[str, Any]] = []


class WAFWebACLBasic(BaseModel):
    """Basic WAF Web ACL information"""
    Name: str
    Id: str
    ARN: str
    Scope: str
    DefaultAction: str


class WAFWebACLDetail(BaseModel):
    """Detailed WAF Web ACL information with security analysis"""
    Name: str
    Id: str
    ARN: str
    Scope: str
    DefaultAction: Dict[str, Any]
    Description: Optional[str] = None
    Rules: List[Dict[str, Any]] = []
    VisibilityConfig: Dict[str, Any]
    Capacity: int
    ManagedByFirewallManager: bool = False
    Tags: List[Dict[str, str]] = []
    AssociatedResources: List[str] = []
    recommendations: List[Dict[str, Any]] = []
    security_findings: List[Dict[str, Any]] = []


# ============================================================================
# CACHE HELPERS
# ============================================================================

def get_cache(account_id: str, region: str, service: str, key: str) -> Optional[Any]:
    """Retrieve data from cache if not expired"""
    cache_key = f"{account_id}:{region}:{service}:{key}"
    cached = CACHE.get(cache_key)
    if cached and (time.time() - cached["timestamp"] < CACHE_TTL):
        logger.debug(f"Cache hit for {cache_key}")
        return cached["data"]
    return None


def set_cache(account_id: str, region: str, service: str, key: str, data: Any):
    """Store data in cache with timestamp"""
    cache_key = f"{account_id}:{region}:{service}:{key}"
    CACHE[cache_key] = {"data": data, "timestamp": time.time()}
    logger.debug(f"Cache set for {cache_key}")


# ============================================================================
# ERROR HANDLING
# ============================================================================

def handle_aws_error(e: Exception, context: str) -> HTTPException:
    """Centralized AWS error handling"""
    if isinstance(e, ClientError):
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        error_msg = e.response.get("Error", {}).get("Message", str(e))
        logger.error(f"AWS Error in {context}: {error_code} - {error_msg}")
        
        status_code = 500
        if error_code in ["AccessDenied", "UnauthorizedOperation", "InvalidClientTokenId"]:
            status_code = 403
        elif error_code in ["InvalidParameterValue", "ValidationError", "InvalidParameterCombination"]:
            status_code = 400
        elif error_code in ["NoSuchEntity", "NotFoundException", "ResourceNotFoundException"]:
            status_code = 404
        
        return HTTPException(status_code=status_code, detail=f"{error_code}: {error_msg}")
    else:
        logger.error(f"Unexpected error in {context}: {str(e)}")
        return HTTPException(status_code=500, detail=str(e))


# ============================================================================
# IAM FUNCTIONS
# ============================================================================

def list_iam_users(session, account_id: str, region: str) -> List[IAMUserBasic]:
    """List all IAM users (global service)"""
    cached = get_cache(account_id, "global", "iam", "users")
    if cached:
        return cached
    
    try:
        iam_client = session.client("iam")
        users = []
        
        paginator = iam_client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                users.append(IAMUserBasic(
                    UserName=user["UserName"],
                    UserId=user["UserId"],
                    Arn=user["Arn"],
                    CreateDate=user["CreateDate"].isoformat(),
                    PasswordLastUsed=user.get("PasswordLastUsed").isoformat() if user.get("PasswordLastUsed") else None
                ))
        
        set_cache(account_id, "global", "iam", "users", users)
        return users
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_iam_users")


def list_iam_roles(session, account_id: str, region: str) -> List[IAMRoleBasic]:
    """List all IAM roles (global service)"""
    cached = get_cache(account_id, "global", "iam", "roles")
    if cached:
        return cached
    
    try:
        iam_client = session.client("iam")
        roles = []
        
        paginator = iam_client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                roles.append(IAMRoleBasic(
                    RoleName=role["RoleName"],
                    RoleId=role["RoleId"],
                    Arn=role["Arn"],
                    CreateDate=role["CreateDate"].isoformat(),
                    MaxSessionDuration=role.get("MaxSessionDuration", 3600)
                ))
        
        set_cache(account_id, "global", "iam", "roles", roles)
        return roles
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_iam_roles")


def analyze_iam_user(iam_client, user_name: str) -> IAMUserDetail:
    """Get detailed IAM user information with security analysis"""
    try:
        response = iam_client.get_user(UserName=user_name)
        user = response["User"]
        
        # Get groups
        groups = []
        try:
            groups_resp = iam_client.list_groups_for_user(UserName=user_name)
            groups = [g["GroupName"] for g in groups_resp.get("Groups", [])]
        except ClientError:
            pass
        
        # Get attached policies
        attached_policies = []
        try:
            policies_resp = iam_client.list_attached_user_policies(UserName=user_name)
            attached_policies = policies_resp.get("AttachedPolicies", [])
        except ClientError:
            pass
        
        # Get inline policies
        inline_policies = []
        try:
            inline_resp = iam_client.list_user_policies(UserName=user_name)
            inline_policies = inline_resp.get("PolicyNames", [])
        except ClientError:
            pass
        
        # Get access keys
        access_keys = []
        try:
            keys_resp = iam_client.list_access_keys(UserName=user_name)
            access_keys = keys_resp.get("AccessKeyMetadata", [])
        except ClientError:
            pass
        
        # Get MFA devices
        mfa_devices = []
        try:
            mfa_resp = iam_client.list_mfa_devices(UserName=user_name)
            mfa_devices = mfa_resp.get("MFADevices", [])
        except ClientError:
            pass
        
        # Get login profile
        login_profile = None
        try:
            login_resp = iam_client.get_login_profile(UserName=user_name)
            login_profile = login_resp.get("LoginProfile")
        except ClientError:
            pass
        
        # Get tags
        tags = []
        try:
            tags_resp = iam_client.list_user_tags(UserName=user_name)
            tags = [{"Key": tag["Key"], "Value": tag["Value"]} for tag in tags_resp.get("Tags", [])]
        except ClientError:
            pass
        
        # Build detailed user info
        detail = IAMUserDetail(
            UserName=user["UserName"],
            UserId=user["UserId"],
            Arn=user["Arn"],
            CreateDate=user["CreateDate"].isoformat(),
            PasswordLastUsed=user.get("PasswordLastUsed").isoformat() if user.get("PasswordLastUsed") else None,
            Path=user.get("Path", "/"),
            PermissionsBoundary=user.get("PermissionsBoundary"),
            Tags=tags,
            Groups=groups,
            AttachedPolicies=attached_policies,
            InlinePolicies=inline_policies,
            AccessKeys=access_keys,
            MFADevices=mfa_devices,
            LoginProfile=login_profile,
            recommendations=[],
            security_findings=[]
        )
        
        # Security Analysis
        if login_profile and not mfa_devices:
            detail.security_findings.append({
                "type": "security",
                "severity": "critical",
                "message": "Console access enabled but MFA not configured",
                "recommendation": "Enable MFA for all users with console access"
            })
        
        # Check for active access keys
        active_keys = [k for k in access_keys if k.get("Status") == "Active"]
        if len(active_keys) > 1:
            detail.security_findings.append({
                "type": "security",
                "severity": "high",
                "message": f"User has {len(active_keys)} active access keys",
                "recommendation": "Maintain only one active access key per user"
            })
        
        # Check for old access keys
        for key in active_keys:
            create_date = key.get("CreateDate")
            if create_date:
                age_days = (datetime.now(create_date.tzinfo) - create_date).days
                if age_days > 90:
                    detail.security_findings.append({
                        "type": "security",
                        "severity": "high",
                        "message": f"Access key {key.get('AccessKeyId')} is {age_days} days old",
                        "recommendation": "Rotate access keys every 90 days"
                    })
        
        # Check for inline policies
        if inline_policies:
            detail.recommendations.append({
                "type": "management",
                "severity": "medium",
                "message": f"User has {len(inline_policies)} inline policy(ies)",
                "recommendation": "Use managed policies instead of inline policies for better management"
            })
        
        # Check for AdministratorAccess
        admin_policies = [p for p in attached_policies if "AdministratorAccess" in p.get("PolicyName", "")]
        if admin_policies:
            detail.security_findings.append({
                "type": "security",
                "severity": "critical",
                "message": "User has AdministratorAccess policy attached",
                "recommendation": "Follow least privilege principle - grant only required permissions"
            })
        
        # Check for unused user
        if detail.PasswordLastUsed:
            last_used = datetime.fromisoformat(detail.PasswordLastUsed.replace("Z", "+00:00"))
            days_unused = (datetime.now(last_used.tzinfo) - last_used).days
            if days_unused > 90:
                detail.recommendations.append({
                    "type": "security",
                    "severity": "medium",
                    "message": f"User inactive for {days_unused} days",
                    "recommendation": "Consider disabling or removing inactive users"
                })
        
        # Check permissions boundary
        if not detail.PermissionsBoundary and (attached_policies or inline_policies):
            detail.recommendations.append({
                "type": "security",
                "severity": "low",
                "message": "No permissions boundary set",
                "recommendation": "Consider using permissions boundaries for additional security"
            })
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_iam_user:{user_name}")


def analyze_iam_role(iam_client, role_name: str) -> IAMRoleDetail:
    """Get detailed IAM role information with security analysis"""
    try:
        response = iam_client.get_role(RoleName=role_name)
        role = response["Role"]
        
        # Get attached policies
        attached_policies = []
        try:
            policies_resp = iam_client.list_attached_role_policies(RoleName=role_name)
            attached_policies = policies_resp.get("AttachedPolicies", [])
        except ClientError:
            pass
        
        # Get inline policies
        inline_policies = []
        try:
            inline_resp = iam_client.list_role_policies(RoleName=role_name)
            inline_policies = inline_resp.get("PolicyNames", [])
        except ClientError:
            pass
        
        # Get tags
        tags = []
        try:
            tags_resp = iam_client.list_role_tags(RoleName=role_name)
            tags = [{"Key": tag["Key"], "Value": tag["Value"]} for tag in tags_resp.get("Tags", [])]
        except ClientError:
            pass
        
        # Parse assume role policy
        assume_role_policy = role.get("AssumeRolePolicyDocument", {})
        if isinstance(assume_role_policy, str):
            try:
                assume_role_policy = json.loads(assume_role_policy)
            except:
                pass
        
        # Build detailed role info
        detail = IAMRoleDetail(
            RoleName=role["RoleName"],
            RoleId=role["RoleId"],
            Arn=role["Arn"],
            CreateDate=role["CreateDate"].isoformat(),
            Path=role.get("Path", "/"),
            AssumeRolePolicyDocument=assume_role_policy,
            MaxSessionDuration=role.get("MaxSessionDuration", 3600),
            PermissionsBoundary=role.get("PermissionsBoundary"),
            Tags=tags,
            AttachedPolicies=attached_policies,
            InlinePolicies=inline_policies,
            LastUsed=role.get("RoleLastUsed"),
            recommendations=[],
            security_findings=[]
        )
        
        # Security Analysis
        # Check for overly permissive trust policy
        statements = assume_role_policy.get("Statement", [])
        for statement in statements:
            principal = statement.get("Principal", {})
            
            # Check for wildcard principals
            if principal == "*" or principal.get("AWS") == "*":
                detail.security_findings.append({
                    "type": "security",
                    "severity": "critical",
                    "message": "Trust policy allows any AWS principal (*)",
                    "recommendation": "Restrict trust policy to specific AWS accounts or services"
                })
            
            # Check for service principals
            service = principal.get("Service")
            if service and isinstance(service, str):
                if service.endswith(".amazonaws.com"):
                    # This is acceptable for AWS service roles
                    pass
        
        # Check for AdministratorAccess
        admin_policies = [p for p in attached_policies if "AdministratorAccess" in p.get("PolicyName", "")]
        if admin_policies:
            detail.security_findings.append({
                "type": "security",
                "severity": "critical",
                "message": "Role has AdministratorAccess policy attached",
                "recommendation": "Follow least privilege principle - grant only required permissions"
            })
        
        # Check for inline policies
        if inline_policies:
            detail.recommendations.append({
                "type": "management",
                "severity": "medium",
                "message": f"Role has {len(inline_policies)} inline policy(ies)",
                "recommendation": "Use managed policies instead of inline policies for better management"
            })
        
        # Check for unused role
        if detail.LastUsed:
            last_used_date = detail.LastUsed.get("LastUsedDate")
            if last_used_date:
                if isinstance(last_used_date, str):
                    last_used_date = datetime.fromisoformat(last_used_date.replace("Z", "+00:00"))
                days_unused = (datetime.now(last_used_date.tzinfo) - last_used_date).days
                if days_unused > 90:
                    detail.recommendations.append({
                        "type": "security",
                        "severity": "medium",
                        "message": f"Role unused for {days_unused} days",
                        "recommendation": "Consider removing unused roles"
                    })
        
        # Check session duration
        if detail.MaxSessionDuration > 43200:  # 12 hours
            detail.recommendations.append({
                "type": "security",
                "severity": "low",
                "message": f"Max session duration is {detail.MaxSessionDuration // 3600} hours",
                "recommendation": "Consider reducing max session duration for better security"
            })
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_iam_role:{role_name}")


# ============================================================================
# KMS FUNCTIONS
# ============================================================================

def list_kms_keys(session, account_id: str, region: str) -> List[KMSKeyBasic]:
    """List all KMS keys in a region using paginator"""
    cached = get_cache(account_id, region, "kms", "keys")
    if cached:
        return cached
    
    try:
        kms_client = session.client("kms", region_name=region)
        keys = []
        
        paginator = kms_client.get_paginator("list_keys")
        for page in paginator.paginate():
            for key in page.get("Keys", []):
                try:
                    # Get key metadata
                    metadata_resp = kms_client.describe_key(KeyId=key["KeyId"])
                    key_metadata = metadata_resp["KeyMetadata"]
                    
                    keys.append(KMSKeyBasic(
                        KeyId=key_metadata["KeyId"],
                        KeyArn=key_metadata["Arn"],
                        KeyState=key_metadata["KeyState"],
                        Enabled=key_metadata.get("Enabled", False),
                        CreationDate=key_metadata.get("CreationDate").isoformat() if key_metadata.get("CreationDate") else None
                    ))
                except ClientError:
                    continue
        
        set_cache(account_id, region, "kms", "keys", keys)
        return keys
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_kms_keys")


def analyze_kms_key(kms_client, key_id: str) -> KMSKeyDetail:
    """Get detailed KMS key information with security analysis"""
    try:
        # Get key metadata
        metadata_resp = kms_client.describe_key(KeyId=key_id)
        key = metadata_resp["KeyMetadata"]
        
        # Get aliases
        aliases = []
        try:
            aliases_resp = kms_client.list_aliases(KeyId=key_id)
            aliases = [a["AliasName"] for a in aliases_resp.get("Aliases", [])]
        except ClientError:
            pass
        
        # Get tags
        tags = []
        try:
            tags_resp = kms_client.list_resource_tags(KeyId=key_id)
            tags = [{"Key": tag["TagKey"], "Value": tag["TagValue"]} for tag in tags_resp.get("Tags", [])]
        except ClientError:
            pass
        
        # Get key policy
        key_policy = None
        try:
            policy_resp = kms_client.get_key_policy(KeyId=key_id, PolicyName="default")
            key_policy = json.loads(policy_resp.get("Policy", "{}"))
        except ClientError:
            pass
        
        # Check key rotation
        key_rotation_enabled = False
        if key.get("KeyManager") == "CUSTOMER":
            try:
                rotation_resp = kms_client.get_key_rotation_status(KeyId=key_id)
                key_rotation_enabled = rotation_resp.get("KeyRotationEnabled", False)
            except ClientError:
                pass
        
        # Get grants
        grants = []
        try:
            paginator = kms_client.get_paginator("list_grants")
            for page in paginator.paginate(KeyId=key_id):
                grants.extend(page.get("Grants", []))
        except ClientError:
            pass
        
        # Build detailed key info
        detail = KMSKeyDetail(
            KeyId=key["KeyId"],
            KeyArn=key["Arn"],
            AWSAccountId=key["AWSAccountId"],
            KeyState=key["KeyState"],
            Enabled=key.get("Enabled", False),
            Description=key.get("Description"),
            KeyUsage=key.get("KeyUsage", "ENCRYPT_DECRYPT"),
            KeyManager=key.get("KeyManager", "CUSTOMER"),
            CustomerMasterKeySpec=key.get("CustomerMasterKeySpec", "SYMMETRIC_DEFAULT"),
            CreationDate=key["CreationDate"].isoformat(),
            DeletionDate=key.get("DeletionDate").isoformat() if key.get("DeletionDate") else None,
            Origin=key.get("Origin", "AWS_KMS"),
            MultiRegion=key.get("MultiRegion", False),
            KeyRotationEnabled=key_rotation_enabled,
            Aliases=aliases,
            Tags=tags,
            KeyPolicy=key_policy,
            Grants=grants,
            recommendations=[],
            security_findings=[]
        )
        
        # Security Analysis
        if detail.KeyManager == "CUSTOMER" and not detail.KeyRotationEnabled:
            detail.security_findings.append({
                "type": "security",
                "severity": "high",
                "message": "Automatic key rotation not enabled",
                "recommendation": "Enable automatic key rotation for better security hygiene"
            })
        
        if detail.KeyState == "PendingDeletion":
            detail.recommendations.append({
                "type": "management",
                "severity": "high",
                "message": f"Key scheduled for deletion on {detail.DeletionDate}",
                "recommendation": "Ensure this key is no longer in use before deletion"
            })
        
        if detail.KeyState == "Disabled":
            detail.recommendations.append({
                "type": "management",
                "severity": "medium",
                "message": "Key is disabled",
                "recommendation": "Consider deleting unused keys to reduce management overhead"
            })
        
        # Check key policy for overly permissive access
        if key_policy:
            statements = key_policy.get("Statement", [])
            for statement in statements:
                principal = statement.get("Principal", {})
                
                if principal == "*":
                    # Check if there are conditions
                    if not statement.get("Condition"):
                        detail.security_findings.append({
                            "type": "security",
                            "severity": "critical",
                            "message": "Key policy allows unrestricted access (*)",
                            "recommendation": "Restrict key policy to specific principals and add conditions"
                        })
                
                # Check for kms:* permissions
                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                
                if "kms:*" in actions:
                    detail.security_findings.append({
                        "type": "security",
                        "severity": "high",
                        "message": "Key policy allows all KMS actions (kms:*)",
                        "recommendation": "Grant specific KMS permissions instead of kms:*"
                    })
        
        # Check for excessive grants
        if len(grants) > 10:
            detail.recommendations.append({
                "type": "management",
                "severity": "low",
                "message": f"Key has {len(grants)} grants",
                "recommendation": "Review and remove unnecessary grants"
            })
        
        # Check if key has no aliases
        if not aliases and detail.KeyManager == "CUSTOMER":
            detail.recommendations.append({
                "type": "management",
                "severity": "low",
                "message": "Key has no aliases",
                "recommendation": "Create aliases for easier key identification and management"
            })
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_kms_key:{key_id}")


# ============================================================================
# WAF FUNCTIONS
# ============================================================================

def list_waf_webacls(session, account_id: str, region: str) -> List[WAFWebACLBasic]:
    """List all WAF Web ACLs in a region"""
    cached = get_cache(account_id, region, "waf", "webacls")
    if cached:
        return cached
    
    try:
        wafv2_client = session.client("wafv2", region_name=region)
        webacls = []
        
        # List regional Web ACLs
        try:
            regional_resp = wafv2_client.list_web_acls(Scope="REGIONAL")
            for acl in regional_resp.get("WebACLs", []):
                default_action = "Allow" if "Allow" in acl.get("DefaultAction", {}) else "Block"
                webacls.append(WAFWebACLBasic(
                    Name=acl["Name"],
                    Id=acl["Id"],
                    ARN=acl["ARN"],
                    Scope="REGIONAL",
                    DefaultAction=default_action
                ))
        except ClientError:
            pass
        
        # List CloudFront Web ACLs (only in us-east-1)
        if region == "us-east-1":
            try:
                cloudfront_resp = wafv2_client.list_web_acls(Scope="CLOUDFRONT")
                for acl in cloudfront_resp.get("WebACLs", []):
                    default_action = "Allow" if "Allow" in acl.get("DefaultAction", {}) else "Block"
                    webacls.append(WAFWebACLBasic(
                        Name=acl["Name"],
                        Id=acl["Id"],
                        ARN=acl["ARN"],
                        Scope="CLOUDFRONT",
                        DefaultAction=default_action
                    ))
            except ClientError:
                pass
        
        set_cache(account_id, region, "waf", "webacls", webacls)
        return webacls
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_waf_webacls")


def analyze_waf_webacl(wafv2_client, name: str, scope: str, acl_id: str) -> WAFWebACLDetail:
    """Get detailed WAF Web ACL information with security analysis"""
    try:
        response = wafv2_client.get_web_acl(Name=name, Scope=scope, Id=acl_id)
        acl = response["WebACL"]
        
        # Get tags
        tags = []
        try:
            tags_resp = wafv2_client.list_tags_for_resource(ResourceARN=acl["ARN"])
            tag_info = tags_resp.get("TagInfoForResource", {})
            tags = [{"Key": tag["Key"], "Value": tag["Value"]} for tag in tag_info.get("TagList", [])]
        except ClientError:
            pass
        
        # Get associated resources
        associated_resources = []
        try:
            resources_resp = wafv2_client.list_resources_for_web_acl(WebACLArn=acl["ARN"])
            associated_resources = resources_resp.get("ResourceArns", [])
        except ClientError:
            pass
        
        # Build detailed Web ACL info
        detail = WAFWebACLDetail(
            Name=acl["Name"],
            Id=acl["Id"],
            ARN=acl["ARN"],
            Scope=scope,
            DefaultAction=acl["DefaultAction"],
            Description=acl.get("Description"),
            Rules=acl.get("Rules", []),
            VisibilityConfig=acl.get("VisibilityConfig", {}),
            Capacity=acl.get("Capacity", 0),
            ManagedByFirewallManager=acl.get("ManagedByFirewallManager", False),
            Tags=tags,
            AssociatedResources=associated_resources,
            recommendations=[],
            security_findings=[]
        )
        
        # Security Analysis
        if not detail.Rules:
            detail.security_findings.append({
                "type": "security",
                "severity": "critical",
                "message": "Web ACL has no rules configured",
                "recommendation": "Add rules to protect against common web exploits"
            })
        
        # Check default action
        if "Allow" in detail.DefaultAction:
            detail.recommendations.append({
                "type": "security",
                "severity": "medium",
                "message": "Default action is Allow",
                "recommendation": "Consider using Block as default action with explicit allow rules"
            })
        
        # Check for rate limiting rules
        has_rate_limit = any(r.get("Statement", {}).get("RateBasedStatement") for r in detail.Rules)
        if not has_rate_limit:
            detail.recommendations.append({
                "type": "security",
                "severity": "medium",
                "message": "No rate limiting rules configured",
                "recommendation": "Add rate-based rules to protect against DDoS and brute force attacks"
            })
        
        # Check for managed rule groups
        managed_rules = [r for r in detail.Rules 
                        if r.get("Statement", {}).get("ManagedRuleGroupStatement")]
        if not managed_rules:
            detail.recommendations.append({
                "type": "security",
                "severity": "high",
                "message": "No AWS managed rule groups enabled",
                "recommendation": "Enable AWS managed rule groups (Core Rule Set, Known Bad Inputs, etc.)"
            })
        
        # Check visibility config
        if not detail.VisibilityConfig.get("CloudWatchMetricsEnabled"):
            detail.recommendations.append({
                "type": "monitoring",
                "severity": "medium",
                "message": "CloudWatch metrics not enabled",
                "recommendation": "Enable CloudWatch metrics for monitoring and alerting"
            })
        
        if not detail.VisibilityConfig.get("SampledRequestsEnabled"):
            detail.recommendations.append({
                "type": "monitoring",
                "severity": "low",
                "message": "Sampled requests not enabled",
                "recommendation": "Enable sampled requests for debugging and analysis"
            })
        
        # Check if Web ACL is associated with resources
        if not associated_resources:
            detail.recommendations.append({
                "type": "management",
                "severity": "high",
                "message": "Web ACL not associated with any resources",
                "recommendation": "Associate Web ACL with ALB, API Gateway, or CloudFront distribution"
            })
        
        # Check capacity usage
        if detail.Capacity > 1000:
            detail.recommendations.append({
                "type": "management",
                "severity": "low",
                "message": f"Web ACL using {detail.Capacity} WCU (max 5000)",
                "recommendation": "Monitor capacity usage as you add more rules"
            })
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_waf_webacl:{name}")


# ============================================================================
# API ROUTES
# ============================================================================

@router.get(
    "/security/{service}",
    response_model=StandardResponse,
    summary="List all resources for a security service",
    description="Returns a list of all resources (IAM users/roles, KMS keys, or WAF Web ACLs)",
    responses={
        200: {
            "description": "Successful response",
            "content": {
                "application/json": {
                    "examples": {
                        "iam_users": {
                            "summary": "IAM Users Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved 15 IAM users",
                                "data": [
                                    {
                                        "UserName": "john.doe",
                                        "UserId": "AIDAI23XXXXXXX",
                                        "Arn": "arn:aws:iam::123456789012:user/john.doe",
                                        "CreateDate": "2024-01-15T10:30:00Z",
                                        "PasswordLastUsed": "2024-10-15T08:20:00Z"
                                    }
                                ],
                                "metadata": {
                                    "total_count": 15,
                                    "service": "iam",
                                    "resource_type": "users"
                                }
                            }
                        },
                        "iam_roles": {
                            "summary": "IAM Roles Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved 25 IAM roles",
                                "data": [
                                    {
                                        "RoleName": "EC2-S3-Access-Role",
                                        "RoleId": "AROAI23XXXXXXX",
                                        "Arn": "arn:aws:iam::123456789012:role/EC2-S3-Access-Role",
                                        "CreateDate": "2024-01-10T14:00:00Z",
                                        "MaxSessionDuration": 3600
                                    }
                                ]
                            }
                        },
                        "kms": {
                            "summary": "KMS Keys Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved 8 KMS keys",
                                "data": [
                                    {
                                        "KeyId": "1234abcd-12ab-34cd-56ef-1234567890ab",
                                        "KeyArn": "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
                                        "KeyState": "Enabled",
                                        "Enabled": True,
                                        "CreationDate": "2024-01-15T10:30:00Z"
                                    }
                                ],
                                "metadata": {
                                    "total_count": 8,
                                    "service": "kms",
                                    "region": "us-east-1"
                                }
                            }
                        },
                        "waf": {
                            "summary": "WAF Web ACLs Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved 3 WAF Web ACLs",
                                "data": [
                                    {
                                        "Name": "ProductionWebACL",
                                        "Id": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
                                        "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/ProductionWebACL/a1b2c3d4",
                                        "Scope": "REGIONAL",
                                        "DefaultAction": "Block"
                                    }
                                ]
                            }
                        }
                    }
                }
            }
        }
    }
)
async def list_security_resources(
    request: Request,
    service: str,
    account_id: str = Query(..., description="AWS Account ID", example="123456789012"),
    region: str = Query("us-east-1", description="AWS Region", example="us-east-1"),
    resource_type: str = Query("users", description="For IAM: 'users' or 'roles'", example="users")
):
    """List all resources for a specific security service (iam, kms, or waf)"""
    
    if service not in SECURITY_SERVICES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid service '{service}'. Supported services: {', '.join(SECURITY_SERVICES)}"
        )
    
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(status_code=401, detail="AWS session not found")
    
    try:
        if service == "iam":
            if resource_type == "users":
                resources = list_iam_users(session, account_id, region)
            elif resource_type == "roles":
                resources = list_iam_roles(session, account_id, region)
            else:
                raise HTTPException(status_code=400, detail="For IAM, resource_type must be 'users' or 'roles'")
            data = [r.dict() for r in resources]
            metadata = {"total_count": len(resources), "service": service, "resource_type": resource_type}
        elif service == "kms":
            resources = list_kms_keys(session, account_id, region)
            data = [key.dict() for key in resources]
            metadata = {"total_count": len(resources), "service": service, "region": region}
        elif service == "waf":
            resources = list_waf_webacls(session, account_id, region)
            data = [acl.dict() for acl in resources]
            metadata = {"total_count": len(resources), "service": service, "region": region}
        
        return StandardResponse(
            status="success",
            message=f"Retrieved {len(resources)} {service} resources",
            data=data,
            metadata=metadata
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error in list_security_resources for {service}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/security/{service}",
    response_model=StandardResponse,
    summary="Get detailed resource information for a security service",
    description="Returns detailed information and security analysis for specified resources (IAM users/roles, KMS keys, or WAF Web ACLs)",
    responses={
        200: {
            "description": "Successful response",
            "content": {
                "application/json": {
                    "examples": {
                        "iam_user": {
                            "summary": "IAM User Details Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved details for 1 iam resources",
                                "data": [
                                    {
                                        "UserName": "john.doe",
                                        "Groups": ["Developers"],
                                        "AttachedPolicies": [{"PolicyName": "PowerUserAccess"}],
                                        "AccessKeys": [{"Status": "Active", "CreateDate": "2023-01-15T10:30:00Z"}],
                                        "MFADevices": [],
                                        "security_findings": [
                                            {
                                                "type": "security",
                                                "severity": "critical",
                                                "message": "Console access enabled but MFA not configured"
                                            },
                                            {
                                                "type": "security",
                                                "severity": "high",
                                                "message": "Access key is 650 days old"
                                            }
                                        ]
                                    }
                                ]
                            }
                        },
                        "kms": {
                            "summary": "KMS Key Details Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved details for 1 kms resources",
                                "data": [
                                    {
                                        "KeyId": "1234abcd-12ab-34cd-56ef-1234567890ab",
                                        "KeyState": "Enabled",
                                        "KeyRotationEnabled": False,
                                        "security_findings": [
                                            {
                                                "type": "security",
                                                "severity": "high",
                                                "message": "Automatic key rotation not enabled"
                                            }
                                        ]
                                    }
                                ]
                            }
                        }
                    }
                }
            }
        }
    }
)
async def get_security_details(
    request: Request,
    service: str,
    payload: ResourceIdsRequest = Body(...),
    account_id: str = Query(..., description="AWS Account ID"),
    region: str = Query("us-east-1", description="AWS Region"),
    resource_type: str = Query("users", description="For IAM: 'users' or 'roles'"),
    scope: str = Query("REGIONAL", description="For WAF: 'REGIONAL' or 'CLOUDFRONT'")
):
    """Get detailed information for multiple resources of a specific security service"""
    
    if service not in SECURITY_SERVICES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid service '{service}'. Supported services: {', '.join(SECURITY_SERVICES)}"
        )
    
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(status_code=401, detail="AWS session not found")
    
    try:
        details = []
        errors = []
        
        if service == "iam":
            iam_client = session.client("iam")
            if resource_type == "users":
                for user_name in payload.resource_ids:
                    try:
                        detail = analyze_iam_user(iam_client, user_name)
                        details.append(detail.dict())
                    except HTTPException as he:
                        errors.append(f"{user_name}: {he.detail}")
                    except Exception as e:
                        errors.append(f"{user_name}: {str(e)}")
            elif resource_type == "roles":
                for role_name in payload.resource_ids:
                    try:
                        detail = analyze_iam_role(iam_client, role_name)
                        details.append(detail.dict())
                    except HTTPException as he:
                        errors.append(f"{role_name}: {he.detail}")
                    except Exception as e:
                        errors.append(f"{role_name}: {str(e)}")
        
        elif service == "kms":
            kms_client = session.client("kms", region_name=region)
            for key_id in payload.resource_ids:
                try:
                    detail = analyze_kms_key(kms_client, key_id)
                    details.append(detail.dict())
                except HTTPException as he:
                    errors.append(f"{key_id}: {he.detail}")
                except Exception as e:
                    errors.append(f"{key_id}: {str(e)}")
        
        elif service == "waf":
            wafv2_client = session.client("wafv2", region_name=region)
            # For WAF, resource_ids should be in format "name|id"
            for resource_id in payload.resource_ids:
                try:
                    parts = resource_id.split("|")
                    if len(parts) != 2:
                        errors.append(f"{resource_id}: Invalid format. Use 'name|id'")
                        continue
                    name, acl_id = parts
                    detail = analyze_waf_webacl(wafv2_client, name, scope, acl_id)
                    details.append(detail.dict())
                except HTTPException as he:
                    errors.append(f"{resource_id}: {he.detail}")
                except Exception as e:
                    errors.append(f"{resource_id}: {str(e)}")
        
        metadata = {
            "requested_count": len(payload.resource_ids),
            "successful_count": len(details),
            "failed_count": len(errors),
            "service": service,
            "account_id": account_id
        }
        
        if service != "iam":
            metadata["region"] = region
        if service == "iam":
            metadata["resource_type"] = resource_type
        
        return StandardResponse(
            status="success" if details else "error",
            message=f"Retrieved details for {len(details)} {service} resources",
            data=details,
            errors=errors if errors else None,
            metadata=metadata
        )
    except Exception as e:
        logger.exception(f"Unexpected error in get_security_details for {service}")
        raise HTTPException(status_code=500, detail=str(e))