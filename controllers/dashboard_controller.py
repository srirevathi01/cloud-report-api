"""
Dashboard Controller - Endpoints for Cloud Monitoring Dashboard
Handles accounts overview, security issues, billing, upgrades, and health status
"""

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from typing import Optional
import boto3
from datetime import datetime, timedelta
from utils.response_formatter import format_response
import logging

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize router
router = APIRouter()


# ===== Pydantic Models =====
class DashboardAccount(BaseModel):
    """Model for dashboard account"""
    account_id: str
    account_name: str
    project_manager: str
    architect_name: str
    onboarded_date: str


class AccountUpdate(BaseModel):
    """Model for account update"""
    account_name: Optional[str] = None
    project_manager: Optional[str] = None
    architect_name: Optional[str] = None
    onboarded_date: Optional[str] = None


# ===== Helper Functions =====
def get_dynamodb_table(table_name: str = 'cloud_central_accounts'):
    """Get DynamoDB table resource"""
    try:
        dynamodb = boto3.resource('dynamodb', region_name='ap-south-1')
        return dynamodb.Table(table_name)
    except Exception as e:
        logger.error(f"Failed to connect to DynamoDB: {str(e)}")
        raise Exception(f"Database connection failed: {str(e)}")


# ===== Accounts Overview Endpoint =====
@router.get(
    "/accounts-overview",
    summary="Get overview of all AWS accounts (total, active, inactive)"
)
def get_accounts_overview(request: Request):
    """
    Get overview of all AWS accounts including total, active, and inactive counts.
    """
    try:
        table = get_dynamodb_table()
        response = table.scan()

        accounts = response.get('Items', [])

        # Handle pagination
        while 'LastEvaluatedKey' in response:
            response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            accounts.extend(response.get('Items', []))

        total_accounts = len(accounts)

        # Count accounts by onboarded date (active = onboarded, inactive = not yet onboarded or archived)
        # For simplicity, consider all accounts as active
        active_accounts = total_accounts
        inactive_accounts = 0

        return {
            "status": "success",
            "data": {
                "totalAccounts": total_accounts,
                "activeAccounts": active_accounts,
                "inactiveAccounts": inactive_accounts
            }
        }

    except Exception as e:
        import traceback
        tb_str = traceback.format_exc()
        logger.error(f"Error fetching accounts overview: {str(e)}\n{tb_str}")
        return format_response(
            status_code=500,
            status_message=f"Failed to fetch accounts overview: {str(e)}",
            data={"traceback": tb_str}
        )


# ===== Security Issues Endpoint =====
@router.get(
    "/security-issues",
    summary="Get security issues grouped by account"
)
def get_security_issues(request: Request):
    """
    Get security issues grouped by account.
    NOTE: This is a sample implementation. Integrate with AWS Security Hub in production.
    """
    try:
        table = get_dynamodb_table()
        response = table.scan()

        accounts = response.get('Items', [])

        # Sample data - In production, integrate with Security Hub
        security_issues = []
        import random

        for account in accounts:
            critical = random.randint(0, 5)
            high = random.randint(0, 10)
            medium = random.randint(5, 20)
            low = random.randint(10, 30)

            security_issues.append({
                "accountName": account.get('account_name', 'Unknown'),
                "accountId": account.get('account_id', ''),
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "total": critical + high + medium + low
            })

        return {
            "status": "success",
            "data": security_issues
        }

    except Exception as e:
        import traceback
        tb_str = traceback.format_exc()
        logger.error(f"Error fetching security issues: {str(e)}\n{tb_str}")
        return format_response(
            status_code=500,
            status_message=f"Failed to fetch security issues: {str(e)}",
            data={"traceback": tb_str}
        )


# ===== Monthly Billing Endpoint =====
@router.get(
    "/monthly-billing",
    summary="Get last month's billing data per account"
)
def get_monthly_billing(request: Request):
    """
    Get last month's billing data per account.
    NOTE: Integrate with AWS Cost Explorer API in production.
    """
    try:
        table = get_dynamodb_table()
        response = table.scan()

        accounts = response.get('Items', [])

        # Sample data - In production, use Cost Explorer API
        billing_data = []
        last_month = (datetime.now() - timedelta(days=30)).strftime('%Y-%m')

        import random
        for account in accounts:
            amount = random.randint(500, 50000)
            previous_amount = random.randint(500, 50000)
            change_percentage = ((amount - previous_amount) / previous_amount) * 100 if previous_amount > 0 else 0

            trend = 'stable'
            if change_percentage > 5:
                trend = 'up'
            elif change_percentage < -5:
                trend = 'down'

            billing_data.append({
                "accountId": account.get('account_id', ''),
                "accountName": account.get('account_name', 'Unknown'),
                "amount": amount,
                "currency": "USD",
                "month": last_month,
                "trend": trend,
                "changePercentage": round(change_percentage, 2)
            })

        return {
            "status": "success",
            "data": billing_data
        }

    except Exception as e:
        import traceback
        tb_str = traceback.format_exc()
        logger.error(f"Error fetching billing data: {str(e)}\n{tb_str}")
        return format_response(
            status_code=500,
            status_message=f"Failed to fetch billing data: {str(e)}",
            data={"traceback": tb_str}
        )


# ===== Pending Upgrades Endpoint =====
@router.get(
    "/pending-upgrades",
    summary="Get pending version upgrades for AWS services"
)
def get_pending_upgrades(request: Request):
    """
    Get pending version upgrades for AWS services.
    NOTE: Integrate with AWS Systems Manager or upgrade tracking system in production.
    """
    try:
        table = get_dynamodb_table()
        response = table.scan()

        accounts = response.get('Items', [])

        # Sample data - In production, fetch from Systems Manager
        upgrades = []
        services = ['RDS PostgreSQL', 'ElastiCache Redis', 'EKS Cluster', 'Lambda Runtime', 'OpenSearch']

        import random
        import uuid

        for account in accounts[:5]:  # Limit to 5 accounts for demo
            for _ in range(random.randint(0, 3)):
                upgrade = {
                    "id": str(uuid.uuid4()),
                    "serviceName": random.choice(services),
                    "accountId": account.get('account_id', ''),
                    "accountName": account.get('account_name', 'Unknown'),
                    "currentVersion": f"{random.randint(10, 14)}.{random.randint(0, 9)}",
                    "targetVersion": f"{random.randint(14, 16)}.{random.randint(0, 9)}",
                    "upgradeStatus": random.choice(['pending', 'in-progress', 'scheduled']),
                    "scheduledDate": (datetime.now() + timedelta(days=random.randint(1, 30))).isoformat(),
                    "priority": random.choice(['high', 'medium', 'low'])
                }
                upgrades.append(upgrade)

        # Sort by priority
        priority_order = {'high': 0, 'medium': 1, 'low': 2}
        upgrades.sort(key=lambda x: priority_order.get(x['priority'], 999))

        return {
            "status": "success",
            "data": upgrades
        }

    except Exception as e:
        import traceback
        tb_str = traceback.format_exc()
        logger.error(f"Error fetching pending upgrades: {str(e)}\n{tb_str}")
        return format_response(
            status_code=500,
            status_message=f"Failed to fetch pending upgrades: {str(e)}",
            data={"traceback": tb_str}
        )


# ===== Global Health Status Endpoint =====
@router.get(
    "/global-health",
    summary="Get global AWS health status"
)
def get_global_health_status(request: Request):
    """
    Get global AWS health status.
    NOTE: Integrate with AWS Health API in production.
    """
    try:
        # Sample data - In production, use AWS Health API
        health_status = {
            "status": "operational",
            "affectedRegions": [],
            "affectedServices": [],
            "message": "All AWS services are operating normally",
            "lastChecked": datetime.now().isoformat()
        }

        return {
            "status": "success",
            "data": health_status
        }

    except Exception as e:
        import traceback
        tb_str = traceback.format_exc()
        logger.error(f"Error fetching global health status: {str(e)}\n{tb_str}")
        return format_response(
            status_code=500,
            status_message=f"Failed to fetch health status: {str(e)}",
            data={"traceback": tb_str}
        )


# ===== Get All Accounts Endpoint =====
@router.get(
    "/accounts",
    summary="Get all AWS accounts from DynamoDB"
)
def get_all_accounts(request: Request):
    """
    Get all AWS accounts from DynamoDB.
    """
    try:
        table = get_dynamodb_table()
        response = table.scan()

        accounts = response.get('Items', [])

        # Handle pagination
        while 'LastEvaluatedKey' in response:
            response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            accounts.extend(response.get('Items', []))

        # Format accounts for frontend
        formatted_accounts = []
        for account in accounts:
            formatted_accounts.append({
                "accountId": account.get('account_id', ''),
                "accountName": account.get('account_name', 'Unknown'),
                "onboardedDate": account.get('onboarded_date', datetime.now().isoformat()),
                "projectManager": account.get('project_manager', 'N/A'),
                "architectName": account.get('architect_name', 'N/A')
            })

        return {
            "status": "success",
            "data": formatted_accounts
        }

    except Exception as e:
        import traceback
        tb_str = traceback.format_exc()
        logger.error(f"Error fetching accounts: {str(e)}\n{tb_str}")
        return format_response(
            status_code=500,
            status_message=f"Failed to fetch accounts: {str(e)}",
            data={"traceback": tb_str}
        )


# ===== Create Account Endpoint =====
@router.post(
    "/accounts",
    summary="Create a new AWS account entry"
)
def create_account(account: DashboardAccount, request: Request):
    """
    Create a new AWS account entry in DynamoDB.
    """
    try:
        table = get_dynamodb_table()

        item = {
            'account_id': account.account_id,
            'account_name': account.account_name,
            'onboarded_date': account.onboarded_date,
            'project_manager': account.project_manager,
            'architect_name': account.architect_name,
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }

        table.put_item(Item=item)

        return {
            "status": "success",
            "message": "Account created successfully",
            "data": item
        }

    except Exception as e:
        import traceback
        tb_str = traceback.format_exc()
        logger.error(f"Error creating account: {str(e)}\n{tb_str}")
        return format_response(
            status_code=500,
            status_message=f"Failed to create account: {str(e)}",
            data={"traceback": tb_str}
        )


# ===== Update Account Endpoint =====
@router.put(
    "/accounts/{account_id}",
    summary="Update an existing AWS account entry"
)
def update_account(account_id: str, account_data: AccountUpdate, request: Request):
    """
    Update an existing AWS account entry in DynamoDB.
    """
    try:
        table = get_dynamodb_table()

        # Build update expression
        update_expression = "SET "
        expression_attribute_values = {}
        expression_attribute_names = {}

        # Add fields to update
        fields_to_update = []
        if account_data.account_name is not None:
            fields_to_update.append(('account_name', account_data.account_name))
        if account_data.project_manager is not None:
            fields_to_update.append(('project_manager', account_data.project_manager))
        if account_data.architect_name is not None:
            fields_to_update.append(('architect_name', account_data.architect_name))
        if account_data.onboarded_date is not None:
            fields_to_update.append(('onboarded_date', account_data.onboarded_date))

        if not fields_to_update:
            raise HTTPException(status_code=400, detail="No fields to update")

        for i, (field, value) in enumerate(fields_to_update):
            attr_name = f"#{field}"
            attr_value = f":{field}"
            update_expression += f"{attr_name} = {attr_value}"
            if i < len(fields_to_update) - 1:
                update_expression += ", "
            expression_attribute_names[attr_name] = field
            expression_attribute_values[attr_value] = value

        # Add updated timestamp
        update_expression += ", #updated_at = :updated_at"
        expression_attribute_names['#updated_at'] = 'updated_at'
        expression_attribute_values[':updated_at'] = datetime.now().isoformat()

        response = table.update_item(
            Key={'account_id': account_id},
            UpdateExpression=update_expression,
            ExpressionAttributeNames=expression_attribute_names,
            ExpressionAttributeValues=expression_attribute_values,
            ReturnValues="ALL_NEW"
        )

        return {
            "status": "success",
            "message": "Account updated successfully",
            "data": response.get('Attributes', {})
        }

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        tb_str = traceback.format_exc()
        logger.error(f"Error updating account: {str(e)}\n{tb_str}")
        return format_response(
            status_code=500,
            status_message=f"Failed to update account: {str(e)}",
            data={"traceback": tb_str}
        )


# ===== Delete Account Endpoint =====
@router.delete(
    "/accounts/{account_id}",
    summary="Delete an AWS account entry"
)
def delete_account(account_id: str, request: Request):
    """
    Delete an AWS account entry from DynamoDB.
    """
    try:
        table = get_dynamodb_table()

        table.delete_item(Key={'account_id': account_id})

        return {
            "status": "success",
            "message": "Account deleted successfully"
        }

    except Exception as e:
        import traceback
        tb_str = traceback.format_exc()
        logger.error(f"Error deleting account: {str(e)}\n{tb_str}")
        return format_response(
            status_code=500,
            status_message=f"Failed to delete account: {str(e)}",
            data={"traceback": tb_str}
        )
