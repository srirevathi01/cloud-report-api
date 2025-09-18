#listing database on the us-east-1


from fastapi import APIRouter, Query , HTTPException, Request
import boto3
from botocore.exceptions import BotoCoreError, ClientError

router = APIRouter()

#creating the client/service to be loaded

@router.get("/databases")
def list_database_services( request: Request, account_id: str = Query(None)):
    
    return {
        "RDS/AURORA",
        "Dynamodb",
        "elasticache"
    }
    
@router.get("/databases/{service_name}/list")
def list_service_resources(
    service_name: str,
    request: Request,
    account_id: str = Query(None)
):
    """
    List resources for a specific service: rds, dynamodb, or elasticache
    """
    try:
        # Temporary credentials from middleware
        creds = request.state.aws_credentials

        if service_name == "rds":
            rds = boto3.client(
                "rds",
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )
            instances = rds.describe_db_instances()["DBInstances"]
            return {
                "service": "RDS/Aurora",
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

        elif service_name == "dynamodb":
            dynamodb = boto3.client(
                "dynamodb",
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )
            tables = dynamodb.list_tables()["TableNames"]
            return {
                "service": "DynamoDB",
                "tables": tables,
                "total": len(tables)
            }

        elif service_name == "elasticache":
            elasticache = boto3.client(
                "elasticache",
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )
            clusters = elasticache.describe_cache_clusters()["CacheClusters"]
            return {
                "service": "ElastiCache",
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
