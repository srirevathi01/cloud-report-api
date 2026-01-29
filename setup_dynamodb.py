"""
DynamoDB Setup Script for Cloud Monitoring Dashboard
Creates the CloudAccounts table with sample data
"""

import boto3
from botocore.exceptions import ClientError
import os
from datetime import datetime, timedelta
import uuid

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb', region_name=os.getenv('AWS_REGION', 'us-east-1'))
table_name = os.getenv('DYNAMODB_TABLE_NAME', 'CloudAccounts')


def create_table():
    """
    Create CloudAccounts DynamoDB table
    """
    try:
        print(f"Creating table: {table_name}...")

        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[
                {
                    'AttributeName': 'account_id',
                    'KeyType': 'HASH'  # Partition key
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'account_id',
                    'AttributeType': 'S'
                }
            ],
            BillingMode='PAY_PER_REQUEST'  # On-demand pricing
        )

        # Wait for table to be created
        table.meta.client.get_waiter('table_exists').wait(TableName=table_name)
        print(f"✓ Table '{table_name}' created successfully!")
        return True

    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceInUseException':
            print(f"Table '{table_name}' already exists.")
            return True
        else:
            print(f"✗ Error creating table: {str(e)}")
            return False
    except Exception as e:
        print(f"✗ Unexpected error: {str(e)}")
        return False


def insert_sample_data():
    """
    Insert sample account data into CloudAccounts table
    """
    try:
        table = dynamodb.Table(table_name)

        print(f"\nInserting sample data into '{table_name}'...")

        # Sample accounts
        sample_accounts = [
            {
                'account_id': '123456789012',
                'account_name': 'Production AWS Account',
                'onboarded_date': (datetime.now() - timedelta(days=365)).isoformat(),
                'team_manager': 'John Doe',
                'responsible_person': 'Alice Smith',
                'priority': 'high',
                'status': 'active',
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            },
            {
                'account_id': '234567890123',
                'account_name': 'Development AWS Account',
                'onboarded_date': (datetime.now() - timedelta(days=180)).isoformat(),
                'team_manager': 'Jane Smith',
                'responsible_person': 'Bob Johnson',
                'priority': 'medium',
                'status': 'active',
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            },
            {
                'account_id': '345678901234',
                'account_name': 'Staging AWS Account',
                'onboarded_date': (datetime.now() - timedelta(days=90)).isoformat(),
                'team_manager': 'John Doe',
                'responsible_person': 'Carol Williams',
                'priority': 'medium',
                'status': 'active',
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            },
            {
                'account_id': '456789012345',
                'account_name': 'Testing AWS Account',
                'onboarded_date': (datetime.now() - timedelta(days=60)).isoformat(),
                'team_manager': 'Jane Smith',
                'responsible_person': 'David Brown',
                'priority': 'low',
                'status': 'active',
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            },
            {
                'account_id': '567890123456',
                'account_name': 'Legacy AWS Account',
                'onboarded_date': (datetime.now() - timedelta(days=730)).isoformat(),
                'team_manager': 'John Doe',
                'responsible_person': 'Eve Davis',
                'priority': 'low',
                'status': 'inactive',
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
        ]

        # Insert each account
        for account in sample_accounts:
            table.put_item(Item=account)
            print(f"  ✓ Inserted: {account['account_name']}")

        print(f"\n✓ Successfully inserted {len(sample_accounts)} sample accounts!")
        return True

    except ClientError as e:
        print(f"✗ Error inserting sample data: {str(e)}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {str(e)}")
        return False


def verify_table():
    """
    Verify table creation and data insertion
    """
    try:
        table = dynamodb.Table(table_name)
        response = table.scan()
        item_count = len(response.get('Items', []))

        print(f"\n{'='*60}")
        print(f"Table Verification")
        print(f"{'='*60}")
        print(f"Table Name: {table_name}")
        print(f"Item Count: {item_count}")
        print(f"Table Status: {table.table_status}")
        print(f"{'='*60}\n")

        return True

    except Exception as e:
        print(f"✗ Error verifying table: {str(e)}")
        return False


def main():
    """
    Main function to set up DynamoDB table
    """
    print(f"\n{'='*60}")
    print(f"DynamoDB Setup for Cloud Monitoring Dashboard")
    print(f"{'='*60}\n")

    print(f"AWS Region: {os.getenv('AWS_REGION', 'us-east-1')}")
    print(f"Table Name: {table_name}\n")

    # Create table
    if not create_table():
        print("\n✗ Setup failed. Exiting...")
        return

    # Insert sample data
    if not insert_sample_data():
        print("\n⚠ Warning: Sample data insertion failed, but table was created.")

    # Verify
    verify_table()

    print("✓ Setup completed successfully!")
    print("\nYou can now start the FastAPI application and use the dashboard.\n")


if __name__ == "__main__":
    main()
