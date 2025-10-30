"""
AWS Networking Services Controller
Handles VPC, Route53, API Gateway, and ELB resources with comprehensive security and configuration recommendations
"""

from fastapi import APIRouter, Request, HTTPException, Query, Body
from pydantic import BaseModel, Field, validator
from botocore.exceptions import ClientError, BotoCoreError
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging
import time

router = APIRouter()
logger = logging.getLogger(__name__)

# ============================================================================
# CONSTANTS
# ============================================================================
NETWORKING_SERVICES = ["vpc", "route53", "apigateway", "elb"]
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
        example=["vpc-1234567890abcdef0", "my-api-gateway"]
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


class VPCBasic(BaseModel):
    """Basic VPC information"""
    VpcId: str
    CidrBlock: str
    State: str
    IsDefault: bool = False
    Tags: List[Dict[str, str]] = []


class VPCDetail(BaseModel):
    """Detailed VPC information with security analysis"""
    VpcId: str
    CidrBlock: str
    State: str
    IsDefault: bool
    DhcpOptionsId: str
    InstanceTenancy: str
    EnableDnsSupport: bool
    EnableDnsHostnames: bool
    CidrBlockAssociationSet: List[Dict[str, Any]] = []
    Ipv6CidrBlockAssociationSet: List[Dict[str, Any]] = []
    Subnets: List[Dict[str, Any]] = []
    InternetGateways: List[str] = []
    NatGateways: List[Dict[str, Any]] = []
    RouteTables: List[Dict[str, Any]] = []
    SecurityGroups: List[Dict[str, Any]] = []
    NetworkAcls: List[Dict[str, Any]] = []
    VpcFlowLogsEnabled: bool = False
    Tags: List[Dict[str, str]] = []
    recommendations: List[Dict[str, Any]] = []
    security_findings: List[Dict[str, Any]] = []


class Route53HostedZoneBasic(BaseModel):
    """Basic Route53 hosted zone information"""
    Id: str
    Name: str
    CallerReference: str
    ResourceRecordSetCount: Optional[int] = None
    Config: Optional[Dict[str, Any]] = None


class Route53HostedZoneDetail(BaseModel):
    """Detailed Route53 hosted zone information with security analysis"""
    Id: str
    Name: str
    CallerReference: str
    Config: Dict[str, Any]
    ResourceRecordSetCount: int
    RecordSets: List[Dict[str, Any]] = []
    DelegationSet: Optional[Dict[str, Any]] = None
    DnssecStatus: Optional[str] = None
    Tags: List[Dict[str, str]] = []
    recommendations: List[Dict[str, Any]] = []
    security_findings: List[Dict[str, Any]] = []


class APIGatewayBasic(BaseModel):
    """Basic API Gateway information"""
    id: str
    name: str
    description: Optional[str] = None
    createdDate: Optional[str] = None
    apiKeySource: Optional[str] = None
    endpointConfiguration: Optional[Dict[str, Any]] = None


class APIGatewayDetail(BaseModel):
    """Detailed API Gateway information with security analysis"""
    id: str
    name: str
    description: Optional[str] = None
    createdDate: str
    version: Optional[str] = None
    apiKeySource: str
    endpointConfiguration: Dict[str, Any]
    tags: Dict[str, str] = {}
    Stages: List[Dict[str, Any]] = []
    Resources: List[Dict[str, Any]] = []
    Authorizers: List[Dict[str, Any]] = []
    recommendations: List[Dict[str, Any]] = []
    security_findings: List[Dict[str, Any]] = []


class ELBBasic(BaseModel):
    """Basic ELB information"""
    LoadBalancerArn: str
    LoadBalancerName: str
    DNSName: str
    Type: str
    Scheme: str
    State: Dict[str, str]


class ELBDetail(BaseModel):
    """Detailed ELB information with security analysis"""
    LoadBalancerArn: str
    LoadBalancerName: str
    DNSName: str
    CanonicalHostedZoneId: str
    CreatedTime: str
    LoadBalancerType: str
    Scheme: str
    VpcId: str
    State: Dict[str, str]
    Type: str
    AvailabilityZones: List[Dict[str, Any]] = []
    SecurityGroups: List[str] = []
    IpAddressType: str
    Listeners: List[Dict[str, Any]] = []
    TargetGroups: List[Dict[str, Any]] = []
    Attributes: Dict[str, str] = {}
    Tags: List[Dict[str, str]] = []
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
        elif error_code in ["InvalidVpcID.NotFound", "NoSuchHostedZone", "NotFoundException"]:
            status_code = 404
        
        return HTTPException(status_code=status_code, detail=f"{error_code}: {error_msg}")
    else:
        logger.error(f"Unexpected error in {context}: {str(e)}")
        return HTTPException(status_code=500, detail=str(e))


# ============================================================================
# VPC FUNCTIONS
# ============================================================================

def list_vpcs(session, account_id: str, region: str) -> List[VPCBasic]:
    """List all VPCs in a region using paginator"""
    cached = get_cache(account_id, region, "vpc", "vpcs")
    if cached:
        return cached
    
    try:
        ec2_client = session.client("ec2", region_name=region)
        vpcs = []
        
        paginator = ec2_client.get_paginator("describe_vpcs")
        for page in paginator.paginate():
            for vpc in page.get("Vpcs", []):
                tags = [{"Key": tag["Key"], "Value": tag["Value"]} for tag in vpc.get("Tags", [])]
                
                vpcs.append(VPCBasic(
                    VpcId=vpc["VpcId"],
                    CidrBlock=vpc["CidrBlock"],
                    State=vpc["State"],
                    IsDefault=vpc.get("IsDefault", False),
                    Tags=tags
                ))
        
        set_cache(account_id, region, "vpc", "vpcs", vpcs)
        return vpcs
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_vpcs")


def analyze_vpc(ec2_client, vpc_id: str) -> VPCDetail:
    """Get detailed VPC information with security analysis"""
    try:
        response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
        
        if not response["Vpcs"]:
            raise HTTPException(status_code=404, detail=f"VPC {vpc_id} not found")
        
        vpc = response["Vpcs"][0]
        
        # Get DNS attributes
        dns_support_resp = ec2_client.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsSupport")
        dns_hostnames_resp = ec2_client.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsHostnames")
        
        dns_support = dns_support_resp.get("EnableDnsSupport", {}).get("Value", False)
        dns_hostnames = dns_hostnames_resp.get("EnableDnsHostnames", {}).get("Value", False)
        
        # Get tags
        tags = [{"Key": tag["Key"], "Value": tag["Value"]} for tag in vpc.get("Tags", [])]
        
        # Initialize detail object
        detail = VPCDetail(
            VpcId=vpc["VpcId"],
            CidrBlock=vpc["CidrBlock"],
            State=vpc["State"],
            IsDefault=vpc.get("IsDefault", False),
            DhcpOptionsId=vpc.get("DhcpOptionsId", ""),
            InstanceTenancy=vpc.get("InstanceTenancy", "default"),
            EnableDnsSupport=dns_support,
            EnableDnsHostnames=dns_hostnames,
            CidrBlockAssociationSet=vpc.get("CidrBlockAssociationSet", []),
            Ipv6CidrBlockAssociationSet=vpc.get("Ipv6CidrBlockAssociationSet", []),
            Tags=tags,
            Subnets=[],
            InternetGateways=[],
            NatGateways=[],
            RouteTables=[],
            SecurityGroups=[],
            NetworkAcls=[],
            VpcFlowLogsEnabled=False,
            recommendations=[],
            security_findings=[]
        )
        
        # Get subnets
        try:
            subnets_resp = ec2_client.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
            detail.Subnets = subnets_resp.get("Subnets", [])
        except ClientError:
            pass
        
        # Get Internet Gateways
        try:
            igw_resp = ec2_client.describe_internet_gateways(Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}])
            detail.InternetGateways = [igw["InternetGatewayId"] for igw in igw_resp.get("InternetGateways", [])]
        except ClientError:
            pass
        
        # Get NAT Gateways
        try:
            nat_resp = ec2_client.describe_nat_gateways(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
            detail.NatGateways = nat_resp.get("NatGateways", [])
        except ClientError:
            pass
        
        # Get Route Tables
        try:
            rt_resp = ec2_client.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
            detail.RouteTables = rt_resp.get("RouteTables", [])
        except ClientError:
            pass
        
        # Get Security Groups
        try:
            sg_resp = ec2_client.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
            detail.SecurityGroups = sg_resp.get("SecurityGroups", [])
        except ClientError:
            pass
        
        # Get Network ACLs
        try:
            nacl_resp = ec2_client.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
            detail.NetworkAcls = nacl_resp.get("NetworkAcls", [])
        except ClientError:
            pass
        
        # Check VPC Flow Logs
        try:
            flow_logs_resp = ec2_client.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [vpc_id]}])
            detail.VpcFlowLogsEnabled = len(flow_logs_resp.get("FlowLogs", [])) > 0
        except ClientError:
            pass
        
        # Security Analysis
        if not detail.EnableDnsSupport:
            detail.security_findings.append({
                "type": "configuration",
                "severity": "high",
                "message": "DNS resolution not enabled for VPC",
                "recommendation": "Enable DNS support for proper name resolution"
            })
        
        if not detail.EnableDnsHostnames:
            detail.recommendations.append({
                "type": "configuration",
                "severity": "medium",
                "message": "DNS hostnames not enabled",
                "recommendation": "Enable DNS hostnames for EC2 instances to receive public DNS names"
            })
        
        if not detail.VpcFlowLogsEnabled:
            detail.security_findings.append({
                "type": "security",
                "severity": "high",
                "message": "VPC Flow Logs not enabled",
                "recommendation": "Enable VPC Flow Logs for network traffic monitoring and security analysis"
            })
        
        if detail.IsDefault:
            detail.recommendations.append({
                "type": "management",
                "severity": "low",
                "message": "Using default VPC",
                "recommendation": "Consider creating custom VPCs for better network isolation and control"
            })
        
        # Check for overly permissive security groups
        for sg in detail.SecurityGroups:
            for perm in sg.get("IpPermissions", []):
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        from_port = perm.get("FromPort", "All")
                        to_port = perm.get("ToPort", "All")
                        detail.security_findings.append({
                            "type": "security",
                            "severity": "critical",
                            "message": f"Security group {sg.get('GroupId')} allows unrestricted access (0.0.0.0/0) on ports {from_port}-{to_port}",
                            "recommendation": "Restrict security group rules to specific IP ranges"
                        })
                        break
        
        # Check for overly permissive Network ACLs
        for nacl in detail.NetworkAcls:
            for entry in nacl.get("Entries", []):
                if not entry.get("Egress"):  # Ingress rules
                    cidr = entry.get("CidrBlock", "")
                    if cidr == "0.0.0.0/0" and entry.get("RuleAction") == "allow":
                        detail.recommendations.append({
                            "type": "security",
                            "severity": "medium",
                            "message": f"Network ACL {nacl.get('NetworkAclId')} has permissive allow rule for 0.0.0.0/0",
                            "recommendation": "Review and restrict Network ACL rules"
                        })
                        break
        
        # Check for unused NAT Gateways (cost optimization)
        if detail.NatGateways:
            for nat in detail.NatGateways:
                if nat.get("State") == "available":
                    # Check if any route table uses this NAT gateway
                    nat_id = nat.get("NatGatewayId")
                    used = False
                    for rt in detail.RouteTables:
                        for route in rt.get("Routes", []):
                            if route.get("NatGatewayId") == nat_id:
                                used = True
                                break
                        if used:
                            break
                    
                    if not used:
                        detail.recommendations.append({
                            "type": "cost_optimization",
                            "severity": "high",
                            "message": f"NAT Gateway {nat_id} is not used by any route table",
                            "recommendation": "Remove unused NAT Gateway to reduce costs"
                        })
        
        # Check subnet availability
        if len(detail.Subnets) < 2:
            detail.recommendations.append({
                "type": "availability",
                "severity": "high",
                "message": "VPC has fewer than 2 subnets",
                "recommendation": "Create subnets in multiple availability zones for high availability"
            })
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_vpc:{vpc_id}")


# ============================================================================
# ROUTE53 FUNCTIONS
# ============================================================================

def list_route53_zones(session, account_id: str, region: str) -> List[Route53HostedZoneBasic]:
    """List all Route53 hosted zones (global service)"""
    cached = get_cache(account_id, "global", "route53", "zones")
    if cached:
        return cached
    
    try:
        route53_client = session.client("route53")
        zones = []
        
        paginator = route53_client.get_paginator("list_hosted_zones")
        for page in paginator.paginate():
            for zone in page.get("HostedZones", []):
                zones.append(Route53HostedZoneBasic(
                    Id=zone["Id"].split("/")[-1],
                    Name=zone["Name"],
                    CallerReference=zone["CallerReference"],
                    ResourceRecordSetCount=zone.get("ResourceRecordSetCount"),
                    Config=zone.get("Config")
                ))
        
        set_cache(account_id, "global", "route53", "zones", zones)
        return zones
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_route53_zones")


def analyze_route53_zone(route53_client, zone_id: str) -> Route53HostedZoneDetail:
    """Get detailed Route53 hosted zone information with security analysis"""
    try:
        # Add /hostedzone/ prefix if not present
        if not zone_id.startswith("/hostedzone/"):
            zone_id = f"/hostedzone/{zone_id}"
        
        response = route53_client.get_hosted_zone(Id=zone_id)
        zone = response["HostedZone"]
        
        # Get tags
        tags = []
        try:
            tags_resp = route53_client.list_tags_for_resource(ResourceType="hostedzone", ResourceId=zone_id.split("/")[-1])
            tags = [{"Key": tag["Key"], "Value": tag["Value"]} for tag in tags_resp.get("Tags", [])]
        except ClientError:
            pass
        
        # Get record sets
        record_sets = []
        try:
            paginator = route53_client.get_paginator("list_resource_record_sets")
            for page in paginator.paginate(HostedZoneId=zone_id):
                record_sets.extend(page.get("ResourceRecordSets", []))
        except ClientError:
            pass
        
        # Check DNSSEC status
        dnssec_status = None
        try:
            dnssec_resp = route53_client.get_dnssec(HostedZoneId=zone_id)
            dnssec_status = dnssec_resp.get("Status", {}).get("ServeSignature")
        except ClientError:
            pass
        
        # Build detailed zone info
        detail = Route53HostedZoneDetail(
            Id=zone["Id"].split("/")[-1],
            Name=zone["Name"],
            CallerReference=zone["CallerReference"],
            Config=zone.get("Config", {}),
            ResourceRecordSetCount=zone.get("ResourceRecordSetCount", 0),
            RecordSets=record_sets,
            DelegationSet=response.get("DelegationSet"),
            DnssecStatus=dnssec_status,
            Tags=tags,
            recommendations=[],
            security_findings=[]
        )
        
        # Security Analysis
        if not detail.Config.get("PrivateZone") and dnssec_status != "SIGNING":
            detail.security_findings.append({
                "type": "security",
                "severity": "high",
                "message": "DNSSEC not enabled for public hosted zone",
                "recommendation": "Enable DNSSEC to protect against DNS spoofing attacks"
            })
        
        if not detail.Config.get("PrivateZone"):
            detail.recommendations.append({
                "type": "security",
                "severity": "medium",
                "message": "Public hosted zone detected",
                "recommendation": "Ensure DNS records don't expose sensitive internal endpoints"
            })
        
        # Check for wildcard records
        wildcard_records = [r for r in detail.RecordSets if r.get("Name", "").startswith("*.")]
        if wildcard_records:
            detail.recommendations.append({
                "type": "security",
                "severity": "medium",
                "message": f"Found {len(wildcard_records)} wildcard DNS record(s)",
                "recommendation": "Review wildcard records to ensure they're intentional and secure"
            })
        
        # Check for high TTL values
        high_ttl_records = [r for r in detail.RecordSets if r.get("TTL", 0) > 86400]
        if high_ttl_records:
            detail.recommendations.append({
                "type": "performance",
                "severity": "low",
                "message": f"Found {len(high_ttl_records)} record(s) with TTL > 24 hours",
                "recommendation": "Consider lowering TTL for records that may need quick updates"
            })
        
        # Check for records without health checks (for critical services)
        a_records = [r for r in detail.RecordSets if r.get("Type") in ["A", "AAAA"] and not r.get("HealthCheckId")]
        if len(a_records) > 5:
            detail.recommendations.append({
                "type": "availability",
                "severity": "low",
                "message": "Multiple A/AAAA records without health checks",
                "recommendation": "Consider adding Route53 health checks for critical endpoints"
            })
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_route53_zone:{zone_id}")


# ============================================================================
# API GATEWAY FUNCTIONS
# ============================================================================

def list_api_gateways(session, account_id: str, region: str) -> List[APIGatewayBasic]:
    """List all API Gateways in a region using paginator"""
    cached = get_cache(account_id, region, "apigateway", "apis")
    if cached:
        return cached
    
    try:
        apigw_client = session.client("apigateway", region_name=region)
        apis = []
        
        paginator = apigw_client.get_paginator("get_rest_apis")
        for page in paginator.paginate():
            for api in page.get("items", []):
                apis.append(APIGatewayBasic(
                    id=api["id"],
                    name=api["name"],
                    description=api.get("description"),
                    createdDate=api.get("createdDate").isoformat() if api.get("createdDate") else None,
                    apiKeySource=api.get("apiKeySource"),
                    endpointConfiguration=api.get("endpointConfiguration")
                ))
        
        set_cache(account_id, region, "apigateway", "apis", apis)
        return apis
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_api_gateways")


def analyze_api_gateway(apigw_client, api_id: str) -> APIGatewayDetail:
    """Get detailed API Gateway information with security analysis"""
    try:
        response = apigw_client.get_rest_api(restApiId=api_id)
        
        # Get stages
        stages = []
        try:
            stages_resp = apigw_client.get_stages(restApiId=api_id)
            stages = stages_resp.get("item", [])
        except ClientError:
            pass
        
        # Get resources
        resources = []
        try:
            resources_resp = apigw_client.get_resources(restApiId=api_id)
            resources = resources_resp.get("items", [])
        except ClientError:
            pass
        
        # Get authorizers
        authorizers = []
        try:
            authorizers_resp = apigw_client.get_authorizers(restApiId=api_id)
            authorizers = authorizers_resp.get("items", [])
        except ClientError:
            pass
        
        # Build detailed API info
        detail = APIGatewayDetail(
            id=response["id"],
            name=response["name"],
            description=response.get("description"),
            createdDate=response["createdDate"].isoformat(),
            version=response.get("version"),
            apiKeySource=response.get("apiKeySource", "HEADER"),
            endpointConfiguration=response.get("endpointConfiguration", {}),
            tags=response.get("tags", {}),
            Stages=stages,
            Resources=resources,
            Authorizers=authorizers,
            recommendations=[],
            security_findings=[]
        )
        
        # Security Analysis
        endpoint_types = detail.endpointConfiguration.get("types", [])
        if "EDGE" in endpoint_types:
            detail.recommendations.append({
                "type": "architecture",
                "severity": "low",
                "message": "Using EDGE endpoint type",
                "recommendation": "Consider REGIONAL or PRIVATE endpoint for better control and lower latency"
            })
        
        # Check for stages without logging
        for stage in detail.Stages:
            method_settings = stage.get("methodSettings", {})
            if not method_settings or not any(s.get("loggingLevel") for s in method_settings.values()):
                detail.recommendations.append({
                    "type": "monitoring",
                    "severity": "medium",
                    "message": f"Stage '{stage.get('stageName')}' doesn't have CloudWatch logging enabled",
                    "recommendation": "Enable CloudWatch Logs for API monitoring and troubleshooting"
                })
            
            if not stage.get("tracingEnabled"):
                detail.recommendations.append({
                    "type": "monitoring",
                    "severity": "low",
                    "message": f"Stage '{stage.get('stageName')}' doesn't have X-Ray tracing enabled",
                    "recommendation": "Enable X-Ray tracing for distributed tracing"
                })
        
        # Check for methods without authorization
        unauthenticated_methods = []
        for resource in detail.Resources:
            methods = resource.get("resourceMethods", {})
            for method_name, method_data in methods.items():
                try:
                    method_resp = apigw_client.get_method(
                        restApiId=api_id,
                        resourceId=resource["id"],
                        httpMethod=method_name
                    )
                    auth_type = method_resp.get("authorizationType")
                    if auth_type in [None, "NONE"]:
                        unauthenticated_methods.append(f"{method_name} {resource.get('path')}")
                except ClientError:
                    continue
        
        if unauthenticated_methods:
            detail.security_findings.append({
                "type": "security",
                "severity": "high",
                "message": f"Found {len(unauthenticated_methods)} method(s) without authorization",
                "recommendation": "Implement authorization using API keys, IAM, Lambda authorizers, or Cognito"
            })
        
        # Check if API key is required but no usage plan
        if detail.apiKeySource == "HEADER":
            try:
                usage_plans = apigw_client.get_usage_plans()
                if not usage_plans.get("items"):
                    detail.recommendations.append({
                        "type": "management",
                        "severity": "low",
                        "message": "API key source configured but no usage plans found",
                        "recommendation": "Create usage plans to manage API access and throttling"
                    })
            except ClientError:
                pass
        
        # Check for default stages in production
        prod_stages = [s for s in detail.Stages if s.get("stageName") in ["prod", "production"]]
        for stage in prod_stages:
            if not stage.get("cacheClusterEnabled"):
                detail.recommendations.append({
                    "type": "performance",
                    "severity": "medium",
                    "message": f"Production stage '{stage.get('stageName')}' doesn't have caching enabled",
                    "recommendation": "Enable caching to improve API performance and reduce backend load"
                })
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_api_gateway:{api_id}")


# ============================================================================
# ELB FUNCTIONS
# ============================================================================

def list_load_balancers(session, account_id: str, region: str) -> List[ELBBasic]:
    """List all load balancers (ALB/NLB/GLB) in a region using paginator"""
    cached = get_cache(account_id, region, "elb", "load_balancers")
    if cached:
        return cached
    
    try:
        elbv2_client = session.client("elbv2", region_name=region)
        load_balancers = []
        
        paginator = elbv2_client.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                load_balancers.append(ELBBasic(
                    LoadBalancerArn=lb["LoadBalancerArn"],
                    LoadBalancerName=lb["LoadBalancerName"],
                    DNSName=lb["DNSName"],
                    Type=lb["Type"],
                    Scheme=lb["Scheme"],
                    State=lb["State"]
                ))
        
        set_cache(account_id, region, "elb", "load_balancers", load_balancers)
        return load_balancers
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_load_balancers")


def analyze_load_balancer(elbv2_client, lb_arn: str) -> ELBDetail:
    """Get detailed load balancer information with security analysis"""
    try:
        response = elbv2_client.describe_load_balancers(LoadBalancerArns=[lb_arn])
        
        if not response["LoadBalancers"]:
            raise HTTPException(status_code=404, detail=f"Load balancer {lb_arn} not found")
        
        lb = response["LoadBalancers"][0]
        
        # Get listeners
        listeners = []
        try:
            listeners_resp = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)
            listeners = listeners_resp.get("Listeners", [])
        except ClientError:
            pass
        
        # Get target groups
        target_groups = []
        try:
            tg_resp = elbv2_client.describe_target_groups(LoadBalancerArn=lb_arn)
            target_groups = tg_resp.get("TargetGroups", [])
        except ClientError:
            pass
        
        # Get attributes
        attributes = {}
        try:
            attr_resp = elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
            attributes = {attr["Key"]: attr["Value"] for attr in attr_resp.get("Attributes", [])}
        except ClientError:
            pass
        
        # Get tags
        tags = []
        try:
            tags_resp = elbv2_client.describe_tags(ResourceArns=[lb_arn])
            for tag_desc in tags_resp.get("TagDescriptions", []):
                tags = [{"Key": tag["Key"], "Value": tag["Value"]} for tag in tag_desc.get("Tags", [])]
        except ClientError:
            pass
        
        # Build detailed load balancer info
        detail = ELBDetail(
            LoadBalancerArn=lb["LoadBalancerArn"],
            LoadBalancerName=lb["LoadBalancerName"],
            DNSName=lb["DNSName"],
            CanonicalHostedZoneId=lb["CanonicalHostedZoneId"],
            CreatedTime=lb["CreatedTime"].isoformat(),
            LoadBalancerType=lb["Type"],
            Scheme=lb["Scheme"],
            VpcId=lb["VpcId"],
            State=lb["State"],
            Type=lb["Type"],
            AvailabilityZones=lb.get("AvailabilityZones", []),
            SecurityGroups=lb.get("SecurityGroups", []),
            IpAddressType=lb.get("IpAddressType", "ipv4"),
            Listeners=listeners,
            TargetGroups=target_groups,
            Attributes=attributes,
            Tags=tags,
            recommendations=[],
            security_findings=[]
        )
        
        # Security Analysis
        if detail.Scheme == "internet-facing":
            detail.recommendations.append({
                "type": "security",
                "severity": "medium",
                "message": "Load balancer is internet-facing",
                "recommendation": "Ensure proper security controls (WAF, security groups) are in place"
            })
        
        # Check for HTTP listeners
        for listener in detail.Listeners:
            protocol = listener.get("Protocol", "")
            if protocol == "HTTP":
                detail.security_findings.append({
                    "type": "security",
                    "severity": "critical",
                    "message": "HTTP listener detected (unencrypted traffic)",
                    "recommendation": "Use HTTPS and redirect HTTP to HTTPS"
                })
            
            if protocol == "HTTPS":
                # Check SSL policy
                ssl_policy = listener.get("SslPolicy")
                if ssl_policy and "ELBSecurityPolicy-2016" in ssl_policy:
                    detail.recommendations.append({
                        "type": "security",
                        "severity": "medium",
                        "message": f"Using older SSL policy: {ssl_policy}",
                        "recommendation": "Update to latest TLS policy (ELBSecurityPolicy-TLS13-1-2-2021-06)"
                    })
        
        # Check access logs
        if attributes.get("access_logs.s3.enabled") != "true":
            detail.recommendations.append({
                "type": "monitoring",
                "severity": "high",
                "message": "Access logs not enabled",
                "recommendation": "Enable access logs to S3 for audit and troubleshooting"
            })
        
        # Check deletion protection
        if attributes.get("deletion_protection.enabled") != "true":
            detail.recommendations.append({
                "type": "data_protection",
                "severity": "medium",
                "message": "Deletion protection not enabled",
                "recommendation": "Enable deletion protection to prevent accidental deletion"
            })
        
        # Check cross-zone load balancing
        if detail.Type == "application" and attributes.get("load_balancing.cross_zone.enabled") != "true":
            detail.recommendations.append({
                "type": "availability",
                "severity": "low",
                "message": "Cross-zone load balancing not enabled",
                "recommendation": "Enable cross-zone load balancing for better traffic distribution"
            })
        
        # Check availability zones
        if len(detail.AvailabilityZones) < 2:
            detail.security_findings.append({
                "type": "availability",
                "severity": "high",
                "message": "Load balancer deployed in less than 2 availability zones",
                "recommendation": "Deploy across multiple AZs for high availability"
            })
        
        # Check target group health
        for tg in detail.TargetGroups:
            try:
                health_resp = elbv2_client.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])
                healthy_targets = [t for t in health_resp.get("TargetHealthDescriptions", []) 
                                 if t.get("TargetHealth", {}).get("State") == "healthy"]
                
                if not healthy_targets:
                    detail.security_findings.append({
                        "type": "availability",
                        "severity": "critical",
                        "message": f"Target group {tg['TargetGroupName']} has no healthy targets",
                        "recommendation": "Investigate and fix unhealthy targets immediately"
                    })
            except ClientError:
                pass
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_load_balancer:{lb_arn}")


# ============================================================================
# API ROUTES
# ============================================================================

@router.get(
    "/networking/{service}",
    response_model=StandardResponse,
    summary="List all resources for a networking service",
    description="Returns a list of all resources (VPCs, Route53 zones, API Gateways, or Load Balancers) in the specified region",
    responses={
        200: {
            "description": "Successful response",
            "content": {
                "application/json": {
                    "examples": {
                        "vpc": {
                            "summary": "VPCs Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved 3 VPC resources",
                                "data": [
                                    {
                                        "VpcId": "vpc-1234567890abcdef0",
                                        "CidrBlock": "10.0.0.0/16",
                                        "State": "available",
                                        "IsDefault": False,
                                        "Tags": [{"Key": "Name", "Value": "Production VPC"}]
                                    }
                                ],
                                "metadata": {
                                    "total_count": 3,
                                    "service": "vpc",
                                    "account_id": "123456789012",
                                    "region": "us-east-1"
                                }
                            }
                        },
                        "route53": {
                            "summary": "Route53 Hosted Zones Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved 5 Route53 hosted zones",
                                "data": [
                                    {
                                        "Id": "Z1234567890ABC",
                                        "Name": "example.com.",
                                        "CallerReference": "unique-ref-123",
                                        "ResourceRecordSetCount": 25
                                    }
                                ],
                                "metadata": {
                                    "total_count": 5,
                                    "service": "route53"
                                }
                            }
                        },
                        "apigateway": {
                            "summary": "API Gateways Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved 2 API Gateway resources",
                                "data": [
                                    {
                                        "id": "abc123xyz",
                                        "name": "Production API",
                                        "description": "Main production API",
                                        "createdDate": "2024-01-15T10:30:00Z",
                                        "endpointConfiguration": {"types": ["REGIONAL"]}
                                    }
                                ],
                                "metadata": {
                                    "total_count": 2,
                                    "service": "apigateway",
                                    "region": "us-east-1"
                                }
                            }
                        },
                        "elb": {
                            "summary": "Load Balancers Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved 4 ELB resources",
                                "data": [
                                    {
                                        "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890abcdef",
                                        "LoadBalancerName": "production-alb",
                                        "DNSName": "my-alb-1234567890.us-east-1.elb.amazonaws.com",
                                        "Type": "application",
                                        "Scheme": "internet-facing",
                                        "State": {"Code": "active"}
                                    }
                                ],
                                "metadata": {
                                    "total_count": 4,
                                    "service": "elb",
                                    "region": "us-east-1"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
)
async def list_networking_resources(
    request: Request,
    service: str,
    account_id: str = Query(..., description="AWS Account ID", example="123456789012"),
    region: str = Query("us-east-1", description="AWS Region", example="us-east-1")
):
    """List all resources for a specific networking service (vpc, route53, apigateway, or elb)"""
    
    if service not in NETWORKING_SERVICES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid service '{service}'. Supported services: {', '.join(NETWORKING_SERVICES)}"
        )
    
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(status_code=401, detail="AWS session not found")
    
    try:
        if service == "vpc":
            resources = list_vpcs(session, account_id, region)
            data = [vpc.dict() for vpc in resources]
        elif service == "route53":
            resources = list_route53_zones(session, account_id, region)
            data = [zone.dict() for zone in resources]
        elif service == "apigateway":
            resources = list_api_gateways(session, account_id, region)
            data = [api.dict() for api in resources]
        elif service == "elb":
            resources = list_load_balancers(session, account_id, region)
            data = [lb.dict() for lb in resources]
        
        metadata = {
            "total_count": len(resources),
            "service": service,
            "account_id": account_id
        }
        
        # Route53 is global, others are regional
        if service != "route53":
            metadata["region"] = region
        
        return StandardResponse(
            status="success",
            message=f"Retrieved {len(resources)} {service} resources",
            data=data,
            metadata=metadata
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error in list_networking_resources for {service}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/networking/{service}",
    response_model=StandardResponse,
    summary="Get detailed resource information for a networking service",
    description="Returns detailed information and security analysis for specified resources (VPCs, Route53 zones, API Gateways, or Load Balancers)",
    responses={
        200: {
            "description": "Successful response",
            "content": {
                "application/json": {
                    "examples": {
                        "vpc": {
                            "summary": "VPC Details Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved details for 1 vpc resources",
                                "data": [
                                    {
                                        "VpcId": "vpc-1234567890abcdef0",
                                        "CidrBlock": "10.0.0.0/16",
                                        "EnableDnsSupport": True,
                                        "EnableDnsHostnames": False,
                                        "VpcFlowLogsEnabled": False,
                                        "security_findings": [
                                            {
                                                "type": "security",
                                                "severity": "high",
                                                "message": "VPC Flow Logs not enabled"
                                            },
                                            {
                                                "type": "security",
                                                "severity": "critical",
                                                "message": "Security group sg-123abc allows unrestricted access"
                                            }
                                        ],
                                        "recommendations": [
                                            {
                                                "type": "configuration",
                                                "severity": "medium",
                                                "message": "DNS hostnames not enabled"
                                            }
                                        ]
                                    }
                                ]
                            }
                        },
                        "elb": {
                            "summary": "Load Balancer Details Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved details for 1 elb resources",
                                "data": [
                                    {
                                        "LoadBalancerName": "production-alb",
                                        "Type": "application",
                                        "Scheme": "internet-facing",
                                        "security_findings": [
                                            {
                                                "type": "security",
                                                "severity": "critical",
                                                "message": "HTTP listener detected (unencrypted traffic)"
                                            },
                                            {
                                                "type": "availability",
                                                "severity": "high",
                                                "message": "Load balancer deployed in less than 2 AZs"
                                            }
                                        ],
                                        "recommendations": [
                                            {
                                                "type": "monitoring",
                                                "severity": "high",
                                                "message": "Access logs not enabled"
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
async def get_networking_details(
    request: Request,
    service: str,
    payload: ResourceIdsRequest = Body(...),
    account_id: str = Query(..., description="AWS Account ID"),
    region: str = Query("us-east-1", description="AWS Region")
):
    """Get detailed information for multiple resources of a specific networking service"""
    
    if service not in NETWORKING_SERVICES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid service '{service}'. Supported services: {', '.join(NETWORKING_SERVICES)}"
        )
    
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(status_code=401, detail="AWS session not found")
    
    try:
        details = []
        errors = []
        
        if service == "vpc":
            ec2_client = session.client("ec2", region_name=region)
            for vpc_id in payload.resource_ids:
                try:
                    detail = analyze_vpc(ec2_client, vpc_id)
                    details.append(detail.dict())
                except HTTPException as he:
                    errors.append(f"{vpc_id}: {he.detail}")
                except Exception as e:
                    errors.append(f"{vpc_id}: {str(e)}")
        
        elif service == "route53":
            route53_client = session.client("route53")
            for zone_id in payload.resource_ids:
                try:
                    detail = analyze_route53_zone(route53_client, zone_id)
                    details.append(detail.dict())
                except HTTPException as he:
                    errors.append(f"{zone_id}: {he.detail}")
                except Exception as e:
                    errors.append(f"{zone_id}: {str(e)}")
        
        elif service == "apigateway":
            apigw_client = session.client("apigateway", region_name=region)
            for api_id in payload.resource_ids:
                try:
                    detail = analyze_api_gateway(apigw_client, api_id)
                    details.append(detail.dict())
                except HTTPException as he:
                    errors.append(f"{api_id}: {he.detail}")
                except Exception as e:
                    errors.append(f"{api_id}: {str(e)}")
        
        elif service == "elb":
            elbv2_client = session.client("elbv2", region_name=region)
            for lb_arn in payload.resource_ids:
                try:
                    detail = analyze_load_balancer(elbv2_client, lb_arn)
                    details.append(detail.dict())
                except HTTPException as he:
                    errors.append(f"{lb_arn}: {he.detail}")
                except Exception as e:
                    errors.append(f"{lb_arn}: {str(e)}")
        
        metadata = {
            "requested_count": len(payload.resource_ids),
            "successful_count": len(details),
            "failed_count": len(errors),
            "service": service,
            "account_id": account_id
        }
        
        if service != "route53":
            metadata["region"] = region
        
        return StandardResponse(
            status="success" if details else "error",
            message=f"Retrieved details for {len(details)} {service} resources",
            data=details,
            errors=errors if errors else None,
            metadata=metadata
        )
    except Exception as e:
        logger.exception(f"Unexpected error in get_networking_details for {service}")
        raise HTTPException(status_code=500, detail=str(e))