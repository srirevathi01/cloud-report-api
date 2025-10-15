from fastapi import APIRouter, Request, Query, HTTPException
from botocore.exceptions import ClientError, BotoCoreError
from typing import Dict, Any, List, Optional, Union
from pydantic import BaseModel
from datetime import datetime, timedelta
import logging
import boto3
import requests

router = APIRouter()
logger = logging.getLogger(__name__)

# Supported services
NETWORKING_SERVICES = ["vpc", "route53", "apigateway", "elb"]

# In-memory cache
NETWORK_CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_TTL = timedelta(minutes=5)


# ------------------ MODELS ------------------

class NetworkingListResponse(BaseModel):
    account_id: str
    region: str
    vpc: List[str]
    route53: List[str]
    apigateway: List[str]
    elb: List[str]

class NetworkingResourceDetailResponse(BaseModel):
    account_id: str
    region: str
    service: str
    resource_id: str
    configuration: Dict[str, Any]
    recommendations: List[Dict[str, Any]]

class NetworkingServiceListResponse(BaseModel):
    account_id: str
    region: str
    service: str
    resources: List[str]
    subnets: Optional[List[str]] = None
    internet_gateways: Optional[List[str]] = None
    security_groups: Optional[List[str]] = None
    elastic_ips: Optional[List[str]] = None
    nat_gateways: Optional[List[str]] = None
    network_interfaces: Optional[List[str]] = None
    target_groups: Optional[List[str]] = None
    transit_gateways: Optional[List[str]] = None
    bandwidth_usage: Optional[Dict[str, Any]] = None

class Route53ServiceListResponse(NetworkingServiceListResponse):
    hosted_zones: Optional[List[str]] = None
    dnssec_enabled: Optional[Dict[str, bool]] = None
    record_counts: Optional[Dict[str, int]] = None
    wildcard_records: Optional[Dict[str, List[str]]] = None
    health_checks: Optional[List[str]] = None
    open_tcp_endpoints: Optional[List[str]] = None

class ApigatewayServiceListResponse(NetworkingServiceListResponse):
    api_details: Optional[Dict[str, Any]] = None  # Holds the extras per API ID


# ------------------ CACHE HELPERS ------------------

def _cache_key(account_id: str, region: str, service: str) -> str:
    return f"{account_id}:{region}:{service}"


def get_cache(account_id: str, region: str, service: str) -> Optional[Any]:
    key = _cache_key(account_id, region, service)
    cached = NETWORK_CACHE.get(key)
    if cached and cached["expiry"] > datetime.utcnow():
        return cached["data"]
    return None


def set_cache(account_id: str, region: str, service: str, data: Any):
    key = _cache_key(account_id, region, service)
    NETWORK_CACHE[key] = {
        "data": data,
        "expiry": datetime.utcnow() + CACHE_TTL
    }


# ------------------ UTILS ------------------

def _safe_client(session, service_name: str, region: Optional[str] = None):
    """Return boto3 client using session; fall back to boto3.client if session missing."""
    if session:
        return session.client(service_name, region_name=region) if region else session.client(service_name)
    return boto3.client(service_name, region_name=region) if region else boto3.client(service_name)


# ------------------ RECOMMENDATIONS / BEST PRACTICES ------------------

def _vpc_best_practices(ec2_client, vpc: Dict[str, Any], vpc_id: str) -> List[Dict[str, Any]]:
    recs: List[Dict[str, Any]] = []

    # Basic: DNS hostnames/support
    try:
        dns_hostnames = ec2_client.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsHostnames").get("EnableDnsHostnames", {}).get("Value")
        dns_support = ec2_client.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsSupport").get("EnableDnsSupport", {}).get("Value")
        if not dns_support:
            recs.append({"type": "configuration", "severity": "high", "message": "VPC DNS support disabled (enableDnsSupport=false)."})
        if not dns_hostnames:
            recs.append({"type": "configuration", "severity": "medium", "message": "VPC DNS hostnames disabled (enableDnsHostnames=false)."})
    except Exception:
        recs.append({"type": "configuration", "severity": "info", "message": "Unable to verify DNS attributes for VPC."})

    # Flow logs
    try:
        fl = ec2_client.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [vpc_id]}]).get("FlowLogs", [])
        if not fl:
            recs.append({"type": "security", "severity": "high", "message": "VPC Flow Logs not configured. Enable for audit and forensics."})
    except Exception:
        recs.append({"type": "security", "severity": "info", "message": "Unable to determine VPC Flow Logs status."})

    # Internet Gateway and route table checks
    try:
        rts = ec2_client.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]).get("RouteTables", [])
        igw_attached = False
        for rt in rts:
            for route in rt.get("Routes", []):
                if route.get("GatewayId", "").startswith("igw-"):
                    igw_attached = True
        if not igw_attached:
            recs.append({"type": "availability", "severity": "medium", "message": "No Internet Gateway routes detected — VPC may be isolated."})
    except Exception:
        recs.append({"type": "availability", "severity": "info", "message": "Unable to inspect route tables."})

    # NAT Gateway presence (for private subnets)
    try:
        nat = ec2_client.describe_nat_gateways(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]).get("NatGateways", [])
        if not nat:
            recs.append({"type": "cost_optimization", "severity": "low", "message": "No NAT Gateways detected — if you have private subnets needing internet access, consider NAT Gateway or NAT instances."})
    except Exception:
        recs.append({"type": "availability", "severity": "info", "message": "Unable to evaluate NAT Gateways."})

    # Subnet classification: public vs private, check route to IGW
    try:
        subnets = ec2_client.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]).get("Subnets", [])
        public_subnet_ids = set()
        for subnet in subnets:
            # find associated route tables with route to igw
            subnet_id = subnet.get("SubnetId")
            rts = ec2_client.describe_route_tables(Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]).get("RouteTables", [])
            is_public = False
            for rt in rts:
                for route in rt.get("Routes", []):
                    if route.get("GatewayId", "").startswith("igw-"):
                        is_public = True
            if is_public:
                public_subnet_ids.add(subnet_id)
        if not public_subnet_ids:
            # Optional: mark if no public subnets found
            recs.append({"type": "availability", "severity": "info", "message": "No public subnets detected; confirm this matches design."})
    except Exception:
        recs.append({"type": "configuration", "severity": "info", "message": "Unable to classify subnets."})

    # Security group wide-open rules
    try:
        sgs = ec2_client.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]).get("SecurityGroups", [])
        for sg in sgs:
            for perm in sg.get("IpPermissions", []):
                # IPv4 ranges
                for r in perm.get("IpRanges", []):
                    if r.get("CidrIp") == "0.0.0.0/0":
                        from_port = perm.get("FromPort")
                        to_port = perm.get("ToPort")
                        protocol = perm.get("IpProtocol")
                        recs.append({
                            "type": "security",
                            "severity": "critical",
                            "message": f"Security group {sg.get('GroupId')} allows {protocol} {from_port}-{to_port} from 0.0.0.0/0."
                        })
                # IPv6 ranges
                for r in perm.get("Ipv6Ranges", []):
                    if r.get("CidrIpv6") == "::/0":
                        recs.append({
                            "type": "security",
                            "severity": "critical",
                            "message": f"Security group {sg.get('GroupId')} allows access from ::/0 (IPv6)."
                        })
    except Exception:
        recs.append({"type": "security", "severity": "info", "message": "Unable to fully inspect security groups."})

    # Network ACL wide-open checks
    try:
        nacls = ec2_client.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]).get("NetworkAcls", [])
        for nacl in nacls:
            for entry in nacl.get("Entries", []):
                if entry.get("Egress") is False:
                    cidr = entry.get("CidrBlock") or entry.get("Ipv6CidrBlock")
                    if cidr in ("0.0.0.0/0", "::/0") and entry.get("RuleAction", "").lower() == "allow":
                        recs.append({
                            "type": "security",
                            "severity": "high",
                            "message": f"NACL {nacl.get('NetworkAclId')} contains allow rule {entry.get('RuleNumber')} for {cidr}."
                        })
    except Exception:
        recs.append({"type": "security", "severity": "info", "message": "Unable to inspect network ACLs."})

    # Default VPC warning
    if vpc.get("IsDefault"):
        recs.append({"type": "management", "severity": "low", "message": "Default VPC detected — consider custom VPCs for isolation and governance."})

    return recs


def _route53_best_practices(r53_client, zone: Dict[str, Any], zone_id: str) -> List[Dict[str, Any]]:
    recs: List[Dict[str, Any]] = []
    config = zone.get("Config", {})

    # Public vs Private
    if not config.get("PrivateZone", False):
        recs.append({"type": "security", "severity": "medium", "message": "Hosted zone is public. Verify records do not expose sensitive endpoints."})

    # DNSSEC check (best-effort)
    try:
        dnssec_resp = r53_client.get_dnssec(HostedZoneId=zone_id)
        status = dnssec_resp.get("Status", {})
        if status.get("ServeSignature") != "SIGNING":
            recs.append({"type": "security", "severity": "high", "message": "DNSSEC not enabled (ServeSignature != SIGNING)."})
    except ClientError:
        recs.append({"type": "security", "severity": "info", "message": "Unable to verify DNSSEC status via get_dnssec (may not be supported in account)."})

    # Record set checks (wildcards, TTL extremes)
    try:
        rrsets = r53_client.list_resource_record_sets(HostedZoneId=zone_id, MaxItems="100").get("ResourceRecordSets", [])
        for rec in rrsets:
            name = rec.get("Name")
            # wildcard record
            if name and name.startswith("*."):
                recs.append({"type": "security", "severity": "medium", "message": f"Wildcard record {name} found — ensure intended."})
            ttl = rec.get("TTL")
            if ttl and ttl > 86400:
                recs.append({"type": "performance", "severity": "low", "message": f"Record {name} TTL is very high ({ttl})."})
            if rec.get("Type") in ("A", "AAAA") and not rec.get("AliasTarget"):
                # no alias - if this points to an endpoint without TLS, it's a note (hard to detect automatically)
                pass
    except Exception:
        recs.append({"type": "management", "severity": "info", "message": "Unable to inspect resource record sets."})

    return recs


def _apigw_best_practices(ag_client, api: Dict[str, Any], api_id: str) -> List[Dict[str, Any]]:
    recs: List[Dict[str, Any]] = []
    # Endpoint & TLS
    types = api.get("endpointConfiguration", {}).get("types", [])
    if not types:
        recs.append({"type": "configuration", "severity": "info", "message": "No endpoint configuration types returned."})
    else:
        if "EDGE" in types:
            recs.append({"type": "architecture", "severity": "low", "message": "EDGE endpoint present — consider REGIONAL or PRIVATE for better locality/security."})

    # Check stage logging and throttling
    try:
        stages = ag_client.get_stages(restApiId=api_id).get("item", [])
        if not stages:
            recs.append({"type": "observability", "severity": "info", "message": "No stages found for API Gateway."})
        else:
            for st in stages:
                method_settings = st.get("methodSettings") or {}
                # if no methodSettings, logging likely not configured
                if not method_settings:
                    recs.append({"type": "observability", "severity": "medium", "message": f"Stage {st.get('stageName')} has no methodSettings — check access logging and throttling."})
                # check tracing
                if not st.get("tracingEnabled"):
                    recs.append({"type": "observability", "severity": "low", "message": f"Stage {st.get('stageName')} has X-Ray tracing disabled."})
    except Exception:
        recs.append({"type": "observability", "severity": "info", "message": "Unable to inspect stages for API Gateway."})

    # Check for unauthenticated methods
    try:
        resources = ag_client.get_resources(restApiId=api_id).get("items", [])
        for res in resources:
            methods = res.get("resourceMethods") or {}
            for method in methods.keys():
                try:
                    mconf = ag_client.get_method(restApiId=api_id, resourceId=res["id"], httpMethod=method)
                    auth = mconf.get("authorizationType")
                    if auth in (None, "NONE"):
                        recs.append({"type": "security", "severity": "high", "message": f"Method {method} on path {res.get('path')} has no authorization."})
                except Exception:
                    continue
    except Exception:
        recs.append({"type": "security", "severity": "info", "message": "Unable to inspect API methods for authorization requirements."})

    # WAF/Shield mention (can't always detect via API easily)
    recs.append({"type": "security", "severity": "info", "message": "If API is public, attach AWS WAF and Shield Advanced where appropriate."})
    return recs


def _elb_best_practices(elb_client, lb: Dict[str, Any], lb_arn: str) -> List[Dict[str, Any]]:
    recs: List[Dict[str, Any]] = []
    scheme = lb.get("Scheme")
    if scheme and scheme != "internal":
        recs.append({"type": "security", "severity": "medium", "message": "Load balancer is internet-facing. Confirm purpose and protections (WAF)."})
    # Listener and certificate checks
    try:
        listeners = elb_client.describe_listeners(LoadBalancerArn=lb_arn).get("Listeners", [])
        if not listeners:
            recs.append({"type": "configuration", "severity": "info", "message": "No listeners found for the load balancer."})
        for l in listeners:
            proto = (l.get("Protocol") or "").upper()
            if proto == "HTTP":
                recs.append({"type": "security", "severity": "critical", "message": "HTTP listener present — use HTTPS and redirect HTTP to HTTPS."})
            if proto == "HTTPS":
                certs = l.get("Certificates", []) or []
                for c in certs:
                    arn = c.get("CertificateArn", "")
                    if arn and "acm" not in arn.lower():
                        recs.append({"type": "security", "severity": "medium", "message": "Listener uses non-ACM certificate; consider ACM or managed certificates."})
    except Exception:
        recs.append({"type": "security", "severity": "info", "message": "Unable to inspect ELB listeners."})

    # Attributes: access logs, idle timeout, cross-zone
    try:
        attrs = elb_client.describe_load_balancer_attributes(LoadBalancerArn=lb_arn).get("Attributes", [])
        attrs_map = {a["Key"]: a["Value"] for a in attrs}
        if attrs_map.get("access_logs.s3.enabled") != "true":
            recs.append({"type": "monitoring", "severity": "high", "message": "ELB access logs not enabled."})
        if attrs_map.get("load_balancing.cross_zone.enabled") != "true":
            recs.append({"type": "performance", "severity": "low", "message": "Cross-zone load balancing not enabled."})
        if attrs_map.get("idle_timeout.timeout_seconds") in (None, ""):
            recs.append({"type": "performance", "severity": "low", "message": "Idle timeout not configured."})
    except Exception:
        recs.append({"type": "monitoring", "severity": "info", "message": "Unable to fetch ELB attributes."})

    # Target group health
    try:
        tgs = elb_client.describe_target_groups(LoadBalancerArn=lb_arn).get("TargetGroups", [])
        for tg in tgs:
            tg_arn = tg.get("TargetGroupArn")
            health = elb_client.describe_target_health(TargetGroupArn=tg_arn).get("TargetHealthDescriptions", [])
            if not health:
                recs.append({"type": "availability", "severity": "medium", "message": f"Target group {tg_arn} has no healthy targets."})
    except Exception:
        recs.append({"type": "availability", "severity": "info", "message": "Unable to evaluate target group health."})

    return recs


# ------------------ LIST FUNCTIONS ------------------

def list_vpcs(session, region: str) -> List[str]:
    cached = get_cache("global", region, "vpc")
    if cached:
        return cached
    try:
        ec2 = _safe_client(session, "ec2", region)
        paginator = ec2.get_paginator("describe_vpcs")
        vpc_ids: List[str] = []
        for page in paginator.paginate():
            for v in page.get("Vpcs", []):
                vid = v.get("VpcId")
                if vid:
                    vpc_ids.append(vid)
        set_cache("global", region, "vpc", vpc_ids)
        return vpc_ids
    except (ClientError, BotoCoreError) as e:
        logger.exception("Error listing VPCs")
        raise HTTPException(status_code=500, detail=str(e))


def list_route53(session) -> List[str]:
    cached = get_cache("global", "global", "route53")
    if cached:
        return cached
    try:
        r53 = _safe_client(session, "route53")
        paginator = r53.get_paginator("list_hosted_zones")
        zones: List[str] = []
        for page in paginator.paginate():
            for z in page.get("HostedZones", []):
                zones.append(z.get("Id").split("/")[-1])
        set_cache("global", "global", "route53", zones)
        return zones
    except (ClientError, BotoCoreError) as e:
        logger.exception("Error listing Route53 hosted zones")
        raise HTTPException(status_code=500, detail=str(e))


def list_apigateway(session, region: str) -> List[str]:
    cached = get_cache("global", region, "apigateway")
    if cached:
        return cached
    try:
        ag = _safe_client(session, "apigateway", region)
        paginator = ag.get_paginator("get_rest_apis")
        apis: List[str] = []
        for page in paginator.paginate():
            for a in page.get("items", []):
                aid = a.get("id")
                if aid:
                    apis.append(aid)
        set_cache("global", region, "apigateway", apis)
        return apis
    except (ClientError, BotoCoreError) as e:
        logger.exception("Error listing APec2I Gateway APIs")
        raise HTTPException(status_code=500, detail=str(e))


def list_elbs(session, region: str) -> List[str]:
    cached = get_cache("global", region, "elb")
    if cached:
        return cached
    try:
        elb = _safe_client(session, "elbv2", region)
        paginator = elb.get_paginator("describe_load_balancers")
        lbs: List[str] = []
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                arn = lb.get("LoadBalancerArn")
                if arn:
                    lbs.append(arn)
        set_cache("global", region, "elb", lbs)
        return lbs
    except (ClientError, BotoCoreError) as e:
        logger.exception("Error listing ELBs")
        raise HTTPException(status_code=500, detail=str(e))


# ------------------ DETAIL FUNCTIONS ------------------

def get_vpc_detail(session, region: str, vpc_id: str) -> Dict[str, Any]:
    ec2 = _safe_client(session, "ec2", region)
    try:
        resp = ec2.describe_vpcs(VpcIds=[vpc_id])
        vpcs = resp.get("Vpcs", [])
        if not vpcs:
            raise HTTPException(status_code=404, detail=f"VPC {vpc_id} not found in {region}")
        vpc = vpcs[0]
        recs = _vpc_best_practices(ec2, vpc, vpc_id)
        return {"configuration": vpc, "recommendations": recs}
    except ClientError as e:
        logger.exception("ClientError fetching VPC detail")
        raise HTTPException(status_code=404, detail=str(e))
    except BotoCoreError as e:
        logger.exception("BotoCoreError fetching VPC detail")
        raise HTTPException(status_code=500, detail=str(e))


def _get_route53_extras(session) -> Dict[str, Any]:
    """
    Return extra Route53-related resources:
    - Hosted zones
    - DNSSEC status
    - Record counts / wildcards
    - Health checks
    - Open TCP endpoints (A/AAAA records pointing to public IPs)
    """
    r53 = _safe_client(session, "route53")
    extras: Dict[str, Any] = {
        "hosted_zones": None,
        "dnssec_enabled": None,
        "record_counts": None,
        "wildcard_records": None,
        "health_checks": None,
        "open_tcp_endpoints": None,
    }

    try:
        # Hosted zones
        zones = r53.list_hosted_zones().get("HostedZones", [])
        extras["hosted_zones"] = [z.get("Id").split("/")[-1] for z in zones] or None

        # DNSSEC status per zone
        dnssec_status: Dict[str, bool] = {}
        for z in zones:
            zone_id = z.get("Id").split("/")[-1]
            try:
                resp = r53.get_dnssec(HostedZoneId=zone_id)
                status = resp.get("Status", {}).get("ServeSignature")
                dnssec_status[zone_id] = status == "SIGNING"
            except Exception:
                dnssec_status[zone_id] = False
        extras["dnssec_enabled"] = dnssec_status or None

        # Record counts, wildcard records, and collect public IPs
        record_counts: Dict[str, int] = {}
        wildcards: Dict[str, List[str]] = {}
        tcp_endpoints: List[str] = []

        for z in zones:
            zone_id = z.get("Id").split("/")[-1]
            rrsets = r53.list_resource_record_sets(HostedZoneId=zone_id, MaxItems="1000").get("ResourceRecordSets", [])
            record_counts[zone_id] = len(rrsets)
            wildcards[zone_id] = [r.get("Name") for r in rrsets if r.get("Name", "").startswith("*.")]

            # Collect TCP open endpoints (A/AAAA records pointing to public IPs)
            for r in rrsets:
                if r.get("Type") in ("A", "AAAA") and not r.get("AliasTarget"):
                    for rec in r.get("ResourceRecords", []):
                        ip = rec.get("Value")
                        if ip:
                            tcp_endpoints.append(ip)

        extras["record_counts"] = record_counts or None
        extras["wildcard_records"] = wildcards or None
        extras["open_tcp_endpoints"] = list(set(tcp_endpoints)) or None

        # Health checks
        health_checks = r53.list_health_checks().get("HealthChecks", [])
        extras["health_checks"] = [hc.get("Id") for hc in health_checks] or None

    except Exception:
        # Keep all as None if something fails
        pass

    return extras


def _get_apigateway_extras(session, region: str) -> Dict[str, Any]:
    """
    Return extra API Gateway-related resources:
    - Stages per API
    - Logging enabled
    - X-Ray tracing
    - Unauthenticated methods
    - Endpoint type
    - Custom domains
    """
    ag = _safe_client(session, "apigateway", region)
    extras: Dict[str, Any] = {}
    try:
        apis = ag.get_rest_apis().get("items", [])
        for api in apis:
            api_id = api.get("id")
            api_name = api.get("name")
            stages_resp = ag.get_stages(restApiId=api_id).get("item", [])
            stages_info = {}
            unauth_methods = []

            # Inspect stages
            for st in stages_resp:
                stage_name = st.get("stageName")
                stages_info[stage_name] = {
                    "logging_enabled": bool(st.get("methodSettings")),
                    "tracing_enabled": st.get("tracingEnabled", False)
                }

            # Inspect resource methods for unauthorized access
            resources = ag.get_resources(restApiId=api_id).get("items", [])
            for r in resources:
                for method in r.get("resourceMethods", {}).keys():
                    try:
                        mconf = ag.get_method(restApiId=api_id, resourceId=r["id"], httpMethod=method)
                        if mconf.get("authorizationType") in (None, "NONE"):
                            unauth_methods.append(f"{method} {r.get('path')}")
                    except Exception:
                        continue

            # Endpoint type
            endpoint_types = api.get("endpointConfiguration", {}).get("types", [])

            # Custom domains
            try:
                domains_resp = ag.get_domain_names().get("items", [])
                custom_domains = [d.get("domainName") for d in domains_resp if api_id in str(d.get("regionalDomainName", ""))]
            except Exception:
                custom_domains = []

            extras[api_id] = {
                "api_name": api_name,
                "stages": stages_info or None,
                "unauthenticated_methods": unauth_methods or None,
                "endpoint_type": endpoint_types or None,
                "custom_domains": custom_domains or None,
            }

    except Exception:
        # Keep all as None if something fails
        extras = {}

    return extras


def get_elb_detail(session, region: str, lb_arn: str) -> Dict[str, Any]:
    elb = _safe_client(session, "elbv2", region)
    try:
        resp = elb.describe_load_balancers(LoadBalancerArns=[lb_arn])
        lbs = resp.get("LoadBalancers", [])
        if not lbs:
            raise HTTPException(status_code=404, detail=f"Load balancer {lb_arn} not found")
        lb = lbs[0]
        recs = _elb_best_practices(elb, lb, lb_arn)
        return {"configuration": lb, "recommendations": recs}
    except ClientError as e:
        logger.exception("ClientError fetching ELB detail")
        raise HTTPException(status_code=404, detail=str(e))
    except BotoCoreError as e:
        logger.exception("BotoCoreError fetching ELB detail")
        raise HTTPException(status_code=500, detail=str(e))

# ------------------ EXTRA INFO FOR VPC / ELB ------------------

def _get_vpc_extras(session, region: str) -> Dict[str, Any]:
    """Return extra VPC-related resources like subnets, IGW, SG, EIP, NAT, network interfaces, transit gateways."""
    ec2 = _safe_client(session, "ec2", region)
    extras: Dict[str, Any] = {
        "subnets": None,
        "internet_gateways": None,
        "security_groups": None,
        "elastic_ips": None,
        "network_interfaces": None,
        "nat_gateways": None,
        "transit_gateways": None,
        "bandwidth_usage": None,  # Placeholder, requires CloudWatch metrics
        "target_groups": None,     # Not typical under VPC, can be optional
    }

    # Subnets
    try:
        subnets = ec2.describe_subnets().get("Subnets", [])
        extras["subnets"] = [s.get("SubnetId") for s in subnets] or None
    except Exception:
        extras["subnets"] = None

    # Internet Gateways
    try:
        igws = ec2.describe_internet_gateways().get("InternetGateways", [])
        extras["internet_gateways"] = [i.get("InternetGatewayId") for i in igws] or None
    except Exception:
        extras["internet_gateways"] = None

    # Security Groups
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        extras["security_groups"] = [s.get("GroupId") for s in sgs] or None
    except Exception:
        extras["security_groups"] = None

    # Elastic IPs
    try:
        eips = ec2.describe_addresses().get("Addresses", [])
        extras["elastic_ips"] = [e.get("PublicIp") for e in eips] or None
    except Exception:
        extras["elastic_ips"] = None

    # Network Interfaces
    try:
        nis = ec2.describe_network_interfaces().get("NetworkInterfaces", [])
        extras["network_interfaces"] = [ni.get("NetworkInterfaceId") for ni in nis] or None
    except Exception:
        extras["network_interfaces"] = None

    # NAT Gateways
    try:
        nats = ec2.describe_nat_gateways().get("NatGateways", [])
        extras["nat_gateways"] = [n.get("NatGatewayId") for n in nats] or None
    except Exception:
        extras["nat_gateways"] = None

    # Transit Gateways
    try:
        tgs = ec2.describe_transit_gateways().get("TransitGateways", [])
        extras["transit_gateways"] = [t.get("TransitGatewayId") for t in tgs] or None
    except Exception:
        extras["transit_gateways"] = None

    # Bandwidth Usage (optional, CloudWatch metrics)
    extras["bandwidth_usage"] = None

    # Target groups usually under ELB, so keep None
    extras["target_groups"] = None

    return extras


def _get_elb_extras(session, region: str) -> Dict[str, Any]:
    """Return extra ELB-related resources like subnets, security groups, target groups, bandwidth usage."""
    elb = _safe_client(session, "elbv2", region)
    extras: Dict[str, Any] = {
        "subnets": None,
        "security_groups": None,
        "target_groups": None,
        "listeners": None,
        "bandwidth_usage": None,
    }

    try:
        lbs = elb.describe_load_balancers().get("LoadBalancers", [])
        all_subnets: List[str] = []
        all_sgs: List[str] = []
        all_listeners: List[str] = []

        for lb in lbs:
            lb_arn = lb.get("LoadBalancerArn")
            if not lb_arn:
                continue

            # Subnets & Security Groups from LB
            all_subnets.extend(lb.get("AvailabilityZones", []) and [az.get("SubnetId") for az in lb.get("AvailabilityZones", []) if az.get("SubnetId")])
            all_sgs.extend(lb.get("SecurityGroups", []) or [])

            # Listeners
            try:
                listeners = elb.describe_listeners(LoadBalancerArn=lb_arn).get("Listeners", [])
                all_listeners.extend([l.get("ListenerArn") for l in listeners if l.get("ListenerArn")])
            except Exception:
                continue

            # Target groups
            try:
                tgs = elb.describe_target_groups(LoadBalancerArn=lb_arn).get("TargetGroups", [])
                if tgs:
                    extras["target_groups"] = [tg.get("TargetGroupArn") for tg in tgs if tg.get("TargetGroupArn")]
            except Exception:
                extras["target_groups"] = None

        extras["subnets"] = list(set(all_subnets)) or None
        extras["security_groups"] = list(set(all_sgs)) or None
        extras["listeners"] = list(set(all_listeners)) or None

    except Exception:
        # Keep all as None if something fails
        pass

    # Bandwidth usage placeholder
    extras["bandwidth_usage"] = None

    return extras

# ------------------ ROUTES ------------------

@router.get("/networking", response_model=NetworkingListResponse)
def list_networking_services(
    request: Request,
    account_id: str = Query(..., description="AWS Account ID"),
    region: str = Query("us-east-1", description="AWS Region (default: us-east-1)"),
):
    """
    List all networking resources (IDs only) for the account & region.
    Expects `request.state.session` to be a boto3.Session or similar with .client().
    """
    session = getattr(request.state, "session", None)
    if not session:
        # fallback to default boto3 session if you prefer; currently explicit 401
        raise HTTPException(status_code=401, detail="AWS session not found on request.state. Attach a boto3.Session to request.state.session in middleware.")

    try:
        vpcs = list_vpcs(session, region)
        route53_zones = list_route53(session)
        apis = list_apigateway(session, region)
        lbs = list_elbs(session, region)
        return NetworkingListResponse(
            account_id=account_id,
            region=region,
            vpc=vpcs,
            route53=route53_zones,
            apigateway=apis,
            elb=lbs,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error in list_networking_services")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/networking/{service}", response_model=Union[NetworkingServiceListResponse, Route53ServiceListResponse, ApigatewayServiceListResponse])
def list_service_resources(
    request: Request,
    service: str,
    account_id: str = Query(..., description="AWS Account ID"),
    region: str = Query("us-east-1", description="AWS Region (default: us-east-1)"),
):
    """
    List resources for a specific networking service.
    """
    service = service.lower()
    if service not in NETWORKING_SERVICES:
        raise HTTPException(status_code=404, detail=f"Service {service} not found")

    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(status_code=401, detail="AWS session not found on request.state")

    try:
        resources: List[str] = []
        if service == "vpc":
            resources = list_vpcs(session, region)
        elif service == "route53":
            resources = list_route53(session)
        elif service == "apigateway":
            resources = list_apigateway(session, region)
        elif service == "elb":
            resources = list_elbs(session, region)

        response_data = {
            "account_id": account_id,
            "region": region,
            "service": service,
            "resources": resources,
        }

        if service == "vpc":
            try:
                extras = _get_vpc_extras(session, region)
                response_data.update(extras)
            except Exception:
                pass

        elif service == "elb":
            try:
                extras = _get_elb_extras(session, region)
                response_data.update(extras)
            except Exception:
                pass

        elif service == "route53":
            try:
                extras = _get_route53_extras(session)
                response_data.update(extras)
            except Exception:
                pass
        elif service == "apigateway":
            try:
                extras = _get_apigateway_extras(session, region)
                response_data["api_details"] = extras  # this will hold the extras per API ID
            except Exception:
                pass


        # --------------------------------------------------------------------

        return response_data  # Pydantic allows extra keys dynamically

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error in list_service_resources")
        raise HTTPException(status_code=500, detail=str(e))


class NetworkingServiceListResponse(BaseModel):
    account_id: str
    region: str
    service: str
    resources: List[str]
    subnets: Optional[List[str]] = None
    internet_gateways: Optional[List[str]] = None
    security_groups: Optional[List[str]] = None
    elastic_ips: Optional[List[str]] = None
    nat_gateways: Optional[List[str]] = None
    network_interfaces: Optional[List[str]] = None
    target_groups: Optional[List[str]] = None
    transit_gateways: Optional[List[str]] = None
    bandwidth_usage: Optional[Dict[str, Any]] = None
    api_details: Optional[Dict[str, Any]] = None

@router.post("/networking/{service}/detail", response_model=NetworkingResourceDetailResponse)
def get_resource_detail(
    request: Request,
    service: str,
    payload: Dict[str, str],
    account_id: str = Query(..., description="AWS Account ID"),
    region: str = Query("us-east-1", description="AWS Region (default: us-east-1)"),
):
    """
    Get configuration + recommendations for a specific resource.
    Body: { "resource_id": "<id>" }
    """
    service = service.lower()
    resource_id = payload.get("resource_id")
    if not resource_id:
        raise HTTPException(status_code=400, detail="resource_id is required in payload")

    if service not in NETWORKING_SERVICES:
        raise HTTPException(status_code=404, detail=f"Service {service} not found")

    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(status_code=401, detail="AWS session not found on request.state")

    try:
        if service == "vpc":
            detail = get_vpc_detail(session, region, resource_id)
        elif service == "route53":
            detail = get_route53_detail(session, resource_id)
        elif service == "apigateway":
            detail = get_apigateway_detail(session, region, resource_id)
        elif service == "elb":
            detail = get_elb_detail(session, region, resource_id)
        else:
            raise HTTPException(status_code=400, detail="Unsupported service")

        return NetworkingResourceDetailResponse(
            account_id=account_id,
            region=region,
            service=service,
            resource_id=resource_id,
            configuration=detail["configuration"],
            recommendations=detail["recommendations"],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error in get_resource_detail")
        raise HTTPException(status_code=500, detail=str(e))
    #``