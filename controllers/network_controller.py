from fastapi import APIRouter, Request, Query, HTTPException
#import boto3
from botocore.exceptions import BotoCoreError, ClientError
from pydantic import BaseModel
from datetime import datetime, timedelta


router = APIRouter()

# Bandwidth usage by VPC (24hr and month-to-date)
@router.get("/networking/vpc-bandwidth-usage")
def vpc_bandwidth_usage(
    request: Request,
    region: str = "us-east-1"
):
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(401, "AWS session not found or expired")
    ec2 = session.client("ec2", region_name=region)
    cloudwatch = session.client("cloudwatch", region_name=region)
    try:
        # Get all VPCs
        vpcs = ec2.describe_vpcs()["Vpcs"]
        # Get all EC2 instances and map to VPCs
        reservations = ec2.describe_instances()["Reservations"]
        vpc_instance_map = {}
        for r in reservations:
            for i in r["Instances"]:
                vpc_id = i.get("VpcId")
                if vpc_id:
                    vpc_instance_map.setdefault(vpc_id, []).append(i["InstanceId"])
        now = datetime.utcnow()
        start_24h = now - timedelta(days=1)
        start_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        vpc_usage = {}
        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            instance_ids = vpc_instance_map.get(vpc_id, [])
            total_in_24h = 0
            total_out_24h = 0
            total_in_month = 0
            total_out_month = 0
            for instance_id in instance_ids:
                for metric in ["NetworkIn", "NetworkOut"]:
                    # 24hr
                    stats_24h = cloudwatch.get_metric_statistics(
                        Namespace="AWS/EC2",
                        MetricName=metric,
                        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
                        StartTime=start_24h,
                        EndTime=now,
                        Period=86400,
                        Statistics=["Sum"]
                    )
                    datapoints_24h = stats_24h.get("Datapoints", [])
                    value_24h = datapoints_24h[0]["Sum"] if datapoints_24h else 0
                    # Month
                    stats_month = cloudwatch.get_metric_statistics(
                        Namespace="AWS/EC2",
                        MetricName=metric,
                        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
                        StartTime=start_month,
                        EndTime=now,
                        Period=86400,
                        Statistics=["Sum"]
                    )
                    value_month = sum(dp["Sum"] for dp in stats_month.get("Datapoints", []))
                    if metric == "NetworkIn":
                        total_in_24h += value_24h
                        total_in_month += value_month
                    else:
                        total_out_24h += value_24h
                        total_out_month += value_month
            def to_gb(val):
                return round(val / (1024 ** 3), 2)
            vpc_usage[vpc_id] = {
                "last_24_hours": {
                    "total_network_in_gb": to_gb(total_in_24h),
                    "total_network_out_gb": to_gb(total_out_24h),
                    "total_bandwidth_gb": to_gb(total_in_24h + total_out_24h)
                },
                "month_to_date": {
                    "total_network_in_gb": to_gb(total_in_month),
                    "total_network_out_gb": to_gb(total_out_month),
                    "total_bandwidth_gb": to_gb(total_in_month + total_out_month)
                },
                "instance_count": len(instance_ids),
                "tags": vpc.get("Tags", [])
            }
        return {"region": region, "vpc_bandwidth_usage": vpc_usage}
    except (BotoCoreError, ClientError) as e:
        raise HTTPException(status_code=500, detail=str(e))


# to list networking services
@router.get("/networking")
def list_networking_services():
    return {
        "services": [
            "vpc",
            "subnet",
            "route-table",
            "internet-gateway",
            "security-group",
            "nacl",
            "elastic-ip",
            "load-balancer",
            "target-group",
            "route53",
            "nat-gateway",
            "transit-gateway"
            "bandwidth-usage"
        ]
    }

#Added to get bandwidth usage by region
@router.get("/networking/bandwidth-usage")
def bandwidth_usage_by_region(
    request: Request,
    region: str = "us-east-1"
):
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(401, "AWS session not found or expired")
    ec2 = session.client("ec2", region_name=region)
    cloudwatch = session.client("cloudwatch", region_name=region)
    try:
        # Get all EC2 instance IDs
        reservations = ec2.describe_instances()
        instance_ids = [
            i["InstanceId"]
            for r in reservations["Reservations"]
            for i in r["Instances"]
        ]
        total_in_24h = 0
        total_out_24h = 0
        total_in_month = 0
        total_out_month = 0
        now = datetime.utcnow()
        # 24 hours
        start_24h = now - timedelta(days=1)
        # Month-to-date
        start_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        for instance_id in instance_ids:
            for metric in ["NetworkIn", "NetworkOut"]:
                # 24h
                stats_24h = cloudwatch.get_metric_statistics(
                    Namespace="AWS/EC2",
                    MetricName=metric,
                    Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
                    StartTime=start_24h,
                    EndTime=now,
                    Period=86400,  # 1 day
                    Statistics=["Sum"]
                )
                datapoints_24h = stats_24h.get("Datapoints", [])
                value_24h = datapoints_24h[0]["Sum"] if datapoints_24h else 0
                # Month
                stats_month = cloudwatch.get_metric_statistics(
                    Namespace="AWS/EC2",
                    MetricName=metric,
                    Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
                    StartTime=start_month,
                    EndTime=now,
                    Period=86400,  # 1 day
                    Statistics=["Sum"]
                )
                value_month = sum(dp["Sum"] for dp in stats_month.get("Datapoints", []))
                if metric == "NetworkIn":
                    total_in_24h += value_24h
                    total_in_month += value_month
                else:
                    total_out_24h += value_24h
                    total_out_month += value_month
        # Convert bytes to GB
        def to_gb(val):
            return round(val / (1024 ** 3), 2)
        return {
            "region": region,
            "last_24_hours": {
                "total_network_in_gb": to_gb(total_in_24h),
                "total_network_out_gb": to_gb(total_out_24h),
                "total_bandwidth_gb": to_gb(total_in_24h + total_out_24h)
            },
            "month_to_date": {
                "total_network_in_gb": to_gb(total_in_month),
                "total_network_out_gb": to_gb(total_out_month),
                "total_bandwidth_gb": to_gb(total_in_month + total_out_month)
            }
        }

    except (BotoCoreError, ClientError) as e:
        raise HTTPException(status_code=500, detail=str(e))

# to list network resources
@router.get("/networking/{resource}")
def list_network_resources(
    resource: str,
    request: Request,
    account_id: str = Query(None),
    region: str = "us-east-1",
    vpc_id: str = Query(None)
):
    session = request.state.session
    try:

        if resource in ["vpc", "subnet", "route-table",
                        "internet-gateway", "security-group",
                        "nacl", "elastic-ip", "route53",
                        "nat-gateway", "transit-gateway"]:
            ec2 = session.client(
                "ec2",
                region_name=region
            )

            if resource == "vpc":
                return ec2.describe_vpcs()
            elif resource == "subnet":
                return ec2.describe_subnets()
            elif resource == "route-table":
                return ec2.describe_route_tables()
            elif resource == "internet-gateway":
                return ec2.describe_internet_gateways()
            elif resource == "security-group":
                return ec2.describe_security_groups()
            elif resource == "nacl":
                return ec2.describe_network_acls()
            elif resource == "elastic-ip":
                return ec2.describe_addresses()
            elif resource == "nat-gateway":
                return ec2.describe_nat_gateways()
            elif resource == "transit-gateway":
                return ec2.describe_transit_gateways()
            elif resource == "route53":
                route53 = session.client("route53")
                return route53.list_hosted_zones()
            

        elif resource in ["load-balancer", "target-group"]:
            elb = session.client(
                "elbv2",

                region_name=region
            )
            if resource == "load-balancer":
                return elb.describe_load_balancers()
            else:
                return elb.describe_target_groups()

        else:
            raise HTTPException(400, "Supported: vpc, subnet, route-table, internet-gateway, security-group, nacl, elastic-ip, nat-gateway, transit-gateway, load-balancer, target-group, route53")

    except (BotoCoreError, ClientError) as e:
        raise HTTPException(500, detail=str(e))
    
    
    

    
class ResourceIds(BaseModel):
    ids: list[str]    
        
@router.post("/networking/{resource}")
def describe_specific_network_resource(
    resource: str,
    resource_ids: ResourceIds,
    request: Request,
    region: str = "us-east-1"
):
    session = request.state.session
    ec2 = session.client("ec2", region_name=region)
    elb = session.client("elbv2", region_name=region)

    try:
        simplified = []
        #for vpc
        if resource == "vpc":
            vpcs = ec2.describe_vpcs(VpcIds=resource_ids.ids)["Vpcs"]
            for v in vpcs:
                vpc_id = v["VpcId"]
                
                # List of all subnet IDs in the VPC
                subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
                subnet_ids = [s["SubnetId"] for s in subnets]
                route_tables = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"]
                route_table_ids = [rt["RouteTableId"] for rt in route_tables]
                igws = ec2.describe_internet_gateways(Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}])["InternetGateways"]
                igw_ids = [igw["InternetGatewayId"] for igw in igws]      
                sgs = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
                sg_ids = [sg["GroupId"] for sg in sgs]
                
                simplified.append({
            "VpcId": vpc_id,
            "Subnets": subnet_ids,
            "RouteTables": route_table_ids,
            "InternetGateways": igw_ids,
            "SecurityGroups": sg_ids,
            "Tags": v.get("Tags", [])
        })
        
        #for subnet
        elif resource == "subnet":
            subnets = ec2.describe_subnets(SubnetIds=resource_ids.ids)["Subnets"]
            for s in subnets:
                subnet_id = s["SubnetId"]
                vpc_id = s["VpcId"]
                cidr_block = s["CidrBlock"]
                az = s["AvailabilityZone"]
                
                route_tables = ec2.describe_route_tables(Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}])["RouteTables"]
                if not route_tables:
                    route_tables = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"]
                    main_rt = next((rt for rt in route_tables if any(a.get("Main", False) for a in rt.get("Associations", []))), None)
                    route_table_id = main_rt["RouteTableId"] if main_rt else None
                else:
                    route_table_id = route_tables[0]["RouteTableId"]

                rt = ec2.describe_route_tables(RouteTableIds=[route_table_id])["RouteTables"][0]
                is_public = any(r.get("GatewayId", "").startswith("igw-") for r in rt.get("Routes", []))
                rt_type = "public" if is_public else "private"
                
                # To Find instances in the subnet
                instances = ec2.describe_instances(Filters=[{"Name": "subnet-id", "Values": [subnet_id]}])["Reservations"]
                sg_ids = []
                
                for r in instances:
                    for i in r["Instances"]:
                        sg_ids.extend([sg["GroupId"] for sg in i.get("SecurityGroups", [])])
                # Remove duplicates
                sg_ids = list(set(sg_ids))
        
                simplified.append({
                    "SubnetId": subnet_id,
                    "VpcId": vpc_id,
                    "AvailabilityZone": az,
                    "CidrBlock": cidr_block,
                    "RouteTableId": route_table_id,
                    "RouteTableType": rt_type,
                    "SecurityGroups": sg_ids 
                })

        #for route table
        elif resource == "route-table":
            route_tables = ec2.describe_route_tables(RouteTableIds=resource_ids.ids)["RouteTables"]
            for rt in route_tables:
                subnets = [assoc["SubnetId"] for assoc in rt.get("Associations", []) if "SubnetId" in assoc]                
                is_public = any(
                    r.get("DestinationCidrBlock") == "0.0.0.0/0" and r.get("GatewayId", "").startswith("igw-")
                    for r in rt.get("Routes", [])
            )
            rt_type = "public" if is_public else "private"
            
            # Find default route (0.0.0.0/0)
            default_route = next(
            (f"{r.get('DestinationCidrBlock')} -> {r.get('GatewayId') or r.get('NatGatewayId') or r.get('VpcPeeringConnectionId')}" 
             for r in rt.get("Routes", []) if r.get("DestinationCidrBlock") == "0.0.0.0/0"), 
            None
            )

            simplified.append({
                    "RouteTableId": rt["RouteTableId"],
            "VpcId": rt["VpcId"],
            "RouteTableType": rt_type,
            "Subnets": subnets,
            "DefaultRoute": default_route,
            "Routes": rt.get("Routes", []),
            "PropagatingVgws": rt.get("PropagatingVgws", []),
            "Tags": rt.get("Tags", [])               
            })
            
        #for internet gateway
        elif resource == "internet-gateway":
            igws = ec2.describe_internet_gateways(InternetGatewayIds=resource_ids.ids)["InternetGateways"]
            for igw in igws:
                simplified.append({
                    "InternetGatewayId": igw["InternetGatewayId"],
                    "AttachedVpcs": [vpc["VpcId"] for vpc in igw.get("Attachments", [])]
                })
        #for security group
        elif resource == "security-group":
            sgs = ec2.describe_security_groups(GroupIds=resource_ids.ids)["SecurityGroups"]
            for sg in sgs:
                simplified.append({
                    "GroupId": sg["GroupId"],
                    "VpcId": sg.get("VpcId"),
                    "InboundRules": sg.get("IpPermissions", []),
                    "OutboundRules": sg.get("IpPermissionsEgress", []),
                    "Tags": sg.get("Tags", [])
                })
        #for nacl
        elif resource == "nacl":
            nacls = ec2.describe_network_acls(NetworkAclIds=resource_ids.ids)["NetworkAcls"]
            for n in nacls:
                simplified.append({
                    "NetworkAclId": n["NetworkAclId"],
                    "VpcId": n["VpcId"],
                    "Associations": [a["SubnetId"] for a in n.get("Associations", [])],
                    "Entries": n.get("Entries", [])
                })

        #for ElasticIPelastic IP use full arn (check the region in the arn too)
        elif resource == "elastic-ip":
            addresses = ec2.describe_addresses()["Addresses"]
            for eip in addresses:
                if eip["AllocationId"] in resource_ids.ids:
                    simplified.append({
                        "AllocationId": eip["AllocationId"],
                        "PublicIp": eip.get("PublicIp"),
                        "PrivateIp": eip.get("PrivateIpAddress"),
                        "InstanceId": eip.get("InstanceId"),
                        "NetworkInterfaceId": eip.get("NetworkInterfaceId"),
                        "AssociationId": eip.get("AssociationId"),
                        "Domain": eip.get("Domain"),
                    "Tags": eip.get("Tags", [])
                    })
        #for load balancer
        elif resource == "load-balancer":
            all_lbs = elb.describe_load_balancers()["LoadBalancers"]
            for lb in all_lbs:
                if lb["LoadBalancerName"] in resource_ids.ids or lb["LoadBalancerArn"] in resource_ids.ids:
                    simplified.append({
                    "LoadBalancerArn": lb["LoadBalancerArn"],
                    "Name": lb["LoadBalancerName"],
                    "Type": lb["Type"],
                    "Scheme": lb["Scheme"],
                    "VpcId": lb["VpcId"],
                    "State": lb["State"]["Code"],
                    "DNSName": lb["DNSName"],
                    "IpAddressType": lb["IpAddressType"],
                    "SecurityGroups": lb.get("SecurityGroups", []),
                    "Subnets": [az["SubnetId"] for az in lb.get("AvailabilityZones", [])],
                    "Tags": elb.describe_tags(ResourceArns=[lb["LoadBalancerArn"]])["TagDescriptions"][0].get("Tags", [])

                })
        #for target group
        elif resource == "target-group":
            tgs = elb.describe_target_groups()["TargetGroups"]
            for tg in tgs:
                if tg["TargetGroupArn"] in resource_ids.ids:
                    simplified.append({
                        "TargetGroupArn": tg["TargetGroupArn"],
                        "Name": tg["TargetGroupName"],
                        "Port": tg["Port"],
                        "Protocol": tg["Protocol"],
                        "VpcId": tg["VpcId"]
                    })
                    
        elif resource == "route53":
            route53 = session.client("route53")
            zones = route53.list_hosted_zones()["HostedZones"]
            for z in zones:
                if z["Id"].split("/")[-1] in resource_ids.ids or z["Name"] in resource_ids.ids:
                    simplified.append({
                        "Id": z["Id"],
                        "Name": z["Name"],
                        "CallerReference": z["CallerReference"],
                        "ResourceRecordSetCount": z["ResourceRecordSetCount"],
                        "Config": z.get("Config", {}),
                        "Tags": route53.list_tags_for_resource(ResourceType="hostedzone", ResourceId=z["Id"].split("/")[-1]).get("ResourceTagSet", {}).get("Tags", [])
                    })
                    
        elif resource == "route53":
            route53 = session.client("route53")
            simplified = []
            for hz_id in resource_ids.ids:
                hz = route53.get_hosted_zone(HostedZoneId=hz_id)
                simplified.append({
                    "Id": hz["HostedZone"]["Id"],
                    "Name": hz["HostedZone"]["Name"],
                    "CallerReference": hz["HostedZone"]["CallerReference"],
                    "ResourceRecordSetCount": hz["HostedZone"]["ResourceRecordSetCount"],
                    "Config": hz["HostedZone"].get("Config", {}),
                    "Tags": route53.list_tags_for_resource(ResourceType="hostedzone", ResourceId=hz["HostedZone"]["Id"].split("/")[-1]).get("ResourceTagSet", {}).get("Tags", [])
                })

        #for nat gateway
        elif resource == "nat-gateway":
            nat_gateways = ec2.describe_nat_gateways(NatGatewayIds=resource_ids.ids)["NatGateways"]
            for nat in nat_gateways:
                simplified.append({
                    "NatGatewayId": nat["NatGatewayId"],
                    "VpcId": nat.get("VpcId"),
                    "SubnetId": nat.get("SubnetId"),
                    "State": nat.get("State"),
                    "ConnectivityType": nat.get("ConnectivityType"),
                    "Tags": nat.get("Tags", [])
                })
        elif resource == "transit-gateway":
            tgs = ec2.describe_transit_gateways(TransitGatewayIds=resource_ids.ids)["TransitGateways"]
            for tg in tgs:
                simplified.append({
                    "TransitGatewayId": tg["TransitGatewayId"],
                    "Description": tg.get("Description"),
                    "State": tg.get("State"),
                    "AmazonSideAsn": tg.get("Options", {}).get("AmazonSideAsn"),
                    "AutoAcceptSharedAttachments": tg.get("Options", {}).get("AutoAcceptSharedAttachments"),
                    "DefaultRouteTableAssociation": tg.get("Options", {}).get("DefaultRouteTableAssociation"),
                    "DefaultRouteTablePropagation": tg.get("Options", {}).get("DefaultRouteTablePropagation"),
                    "Tags": tg.get("Tags", [])
                })
        else:
            raise HTTPException(
                status_code=400,
                detail="Supported resources: vpc, subnet, route-table, internet-gateway, security-group, nacl, elastic-ip, nat-gateway, transit-gateway, load-balancer, target-group, route53"
            )

        return {"service": resource, "resources": simplified}

    except (BotoCoreError, ClientError) as e:
        raise HTTPException(status_code=500, detail=str(e))

#added to list security groups with all tcp open to the world
@router.get("/networking/security-groups/all-tcp-open")
def list_security_groups_with_all_tcp_open(
    request: Request,
    region: str = "us-east-1"
):
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(401, "AWS session not found or expired")
    ec2 = session.client("ec2", region_name=region)
    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        result = []
        for sg in sgs:
            for rule in sg.get("IpPermissions", []):
                if (
                    rule.get("IpProtocol") == "tcp"
                    and rule.get("FromPort") == 0
                    and rule.get("ToPort") == 65535
                    and any(ip.get("CidrIp") == "0.0.0.0/0" for ip in rule.get("IpRanges", []))
                ):
                    result.append({
                        "GroupId": sg["GroupId"],
                        "GroupName": sg.get("GroupName"),
                        "VpcId": sg.get("VpcId"),
                        "Description": sg.get("Description"),
                        "Tags": sg.get("Tags", []),
                        "AllTCPInboundOpenRule": rule
                    })
                    break
        return {"SecurityGroupsWithAllTCPOpen": result}
    except (BotoCoreError, ClientError) as e:
        raise HTTPException(status_code=500, detail=str(e))
