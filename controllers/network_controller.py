from fastapi import APIRouter, Request, Query, HTTPException
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from pydantic import BaseModel


router = APIRouter()

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
            "target-group"
        ]
    }

@router.get("/networking/{resource}")
def list_network_resources(
    resource: str,
    request: Request,
    account_id: str = Query(None),
    region: str = "us-east-1"
):
    session = request.state.session
    try:

        if resource in ["vpc", "subnet", "route-table",
                        "internet-gateway", "security-group",
                        "nacl", "elastic-ip"]:
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
            raise HTTPException(400, "Supported: vpc, subnet, route-table, internet-gateway, security-group, nacl, elastic-ip, load-balancer, target-group")

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

        if resource == "vpc":
            vpcs = ec2.describe_vpcs(VpcIds=resource_ids.ids)["Vpcs"]
            for v in vpcs:
                vpc_id = v["VpcId"]
                
                # List of all subnet IDs in the VPC
                subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
                subnet_ids = [s["SubnetId"] for s in subnets]
                
                route_tables = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"]
                route_table_ids = [rt["RouteTableId"] for rt in route_tables]

                #Internet gateways attached to the VPC
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

        
        elif resource == "route-table":
            route_tables = ec2.describe_route_tables(RouteTableIds=resource_ids.ids)["RouteTables"]
            for rt in route_tables:
                #subnet_ids = []
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

        elif resource == "internet-gateway":
            igws = ec2.describe_internet_gateways(InternetGatewayIds=resource_ids.ids)["InternetGateways"]
            for igw in igws:
                simplified.append({
                    "InternetGatewayId": igw["InternetGatewayId"],
                    "AttachedVpcs": [vpc["VpcId"] for vpc in igw.get("Attachments", [])]
                })

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

        elif resource == "nacl":
            nacls = ec2.describe_network_acls(NetworkAclIds=resource_ids.ids)["NetworkAcls"]
            for n in nacls:
                simplified.append({
                    "NetworkAclId": n["NetworkAclId"],
                    "VpcId": n["VpcId"],
                    "Associations": [a["SubnetId"] for a in n.get("Associations", [])],
                    "Entries": n.get("Entries", [])
                })

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

        else:
            raise HTTPException(
                status_code=400,
                detail="Supported resources: vpc, subnet, route-table, internet-gateway, security-group, nacl, elastic-ip, load-balancer, target-group"
            )

        return {"service": resource, "resources": simplified}

    except (BotoCoreError, ClientError) as e:
        raise HTTPException(status_code=500, detail=str(e))