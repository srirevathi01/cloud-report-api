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
@router.get("/databases/{service_name}/list")
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

        else:
            raise HTTPException(
                status_code=400,
                detail="Supported services: rds, dynamodb, elasticache",
            )
            
    except (BotoCoreError, ClientError) as e:
        raise HTTPException(status_code=500, detail=str(e))
    