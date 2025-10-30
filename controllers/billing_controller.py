"""
AWS Billing Services Controller
Handles AWS Billing and Cost Management with cost analysis, anomaly detection, and optimization recommendations
"""

from fastapi import APIRouter, Request, HTTPException, Query
from pydantic import BaseModel, Field
from botocore.exceptions import ClientError, BotoCoreError
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
import logging
import time

router = APIRouter()
logger = logging.getLogger(__name__)

# ============================================================================
# CONSTANTS
# ============================================================================
BILLING_SERVICES = ["overview", "cost-explorer", "budget"]
CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_TTL = 600  # 10 minutes (billing data doesn't change frequently)

# ============================================================================
# PYDANTIC MODELS (Request/Response Validation)
# ============================================================================

class StandardResponse(BaseModel):
    """Standard response format for all APIs"""
    status: str = Field(description="Response status: success or error")
    message: str = Field(description="Human-readable message")
    data: Optional[Any] = Field(default=None, description="Response data")
    errors: Optional[List[str]] = Field(default=None, description="List of errors if any")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional metadata")


class ServiceCost(BaseModel):
    """Service cost breakdown"""
    service: str
    amount: float
    currency: str
    percentage: float
    trend: Optional[str] = None  # 'up', 'down', 'stable'
    changeAmount: Optional[float] = None
    changePercentage: Optional[float] = None


class MonthlyCost(BaseModel):
    """Monthly cost data"""
    month: str
    amount: float
    currency: str
    services: List[ServiceCost]


class CostAnomaly(BaseModel):
    """Cost anomaly detection"""
    service: str
    currentMonth: float
    previousMonth: float
    changeAmount: float
    changePercentage: float
    severity: str  # 'critical', 'high', 'medium', 'low'
    recommendation: str


class CostOptimization(BaseModel):
    """Cost optimization opportunity"""
    type: str
    service: str
    currentCost: float
    potentialSavings: float
    recommendation: str
    priority: str  # 'high', 'medium', 'low'


class BillingData(BaseModel):
    """Complete billing data response"""
    last6Months: List[MonthlyCost]
    last3MonthsDetailed: List[MonthlyCost]
    currentMonth: MonthlyCost
    anomalies: List[CostAnomaly]
    forecast: List[Dict[str, Any]]
    optimizations: List[CostOptimization]
    totalSpend: float
    averageMonthlySpend: float


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
        elif error_code in ["InvalidParameterValue", "ValidationError"]:
            status_code = 400

        raise HTTPException(status_code=status_code, detail=error_msg)

    logger.error(f"Error in {context}: {str(e)}")
    raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_date_range(months_back: int = 6):
    """Get date range for billing queries"""
    end_date = datetime.now().date()
    # First day of current month
    end_date = end_date.replace(day=1)
    # First day of N months ago
    start_date = end_date - relativedelta(months=months_back)
    return start_date.isoformat(), end_date.isoformat()


def calculate_cost_trend(current: float, previous: float) -> dict:
    """Calculate cost trend between two periods"""
    if previous == 0:
        return {
            "trend": "up" if current > 0 else "stable",
            "changeAmount": current,
            "changePercentage": 100.0 if current > 0 else 0.0
        }

    change = current - previous
    change_pct = (change / previous) * 100

    if abs(change_pct) < 5:
        trend = "stable"
    elif change > 0:
        trend = "up"
    else:
        trend = "down"

    return {
        "trend": trend,
        "changeAmount": change,
        "changePercentage": change_pct
    }


def detect_anomalies(monthly_costs: List[Dict], threshold_percentage: float = 20.0) -> List[CostAnomaly]:
    """Detect cost anomalies in spending patterns"""
    anomalies = []

    if len(monthly_costs) < 2:
        return anomalies

    # Compare last two months
    current_month = monthly_costs[-1]
    previous_month = monthly_costs[-2]

    # Build service cost maps
    current_services = {s['service']: s['amount'] for s in current_month['services']}
    previous_services = {s['service']: s['amount'] for s in previous_month['services']}

    # Check each service for anomalies
    for service in current_services:
        current_cost = current_services.get(service, 0)
        previous_cost = previous_services.get(service, 0)

        if previous_cost == 0:
            if current_cost > 100:  # New service with significant cost
                anomalies.append(CostAnomaly(
                    service=service,
                    currentMonth=current_cost,
                    previousMonth=previous_cost,
                    changeAmount=current_cost,
                    changePercentage=100.0,
                    severity="high" if current_cost > 500 else "medium",
                    recommendation=f"New service {service} incurred ${current_cost:.2f}. Review if this is expected."
                ))
        else:
            change_pct = ((current_cost - previous_cost) / previous_cost) * 100

            if abs(change_pct) >= threshold_percentage:
                severity = "critical" if abs(change_pct) >= 50 else "high" if abs(change_pct) >= 30 else "medium"

                if change_pct > 0:
                    recommendation = f"{service} costs increased by {change_pct:.1f}%. Investigate resource usage, check for unexpected scaling, or review recent deployments."
                else:
                    recommendation = f"{service} costs decreased by {abs(change_pct):.1f}%. Verify services are running as expected."

                anomalies.append(CostAnomaly(
                    service=service,
                    currentMonth=current_cost,
                    previousMonth=previous_cost,
                    changeAmount=current_cost - previous_cost,
                    changePercentage=change_pct,
                    severity=severity,
                    recommendation=recommendation
                ))

    return anomalies


def generate_optimizations(monthly_costs: List[Dict]) -> List[CostOptimization]:
    """Generate cost optimization recommendations"""
    optimizations = []

    if not monthly_costs:
        return optimizations

    current_month = monthly_costs[-1]

    # Example optimizations based on service costs
    for service_cost in current_month['services']:
        service = service_cost['service']
        amount = service_cost['amount']

        # EC2 optimization
        if 'EC2' in service.upper() and amount > 500:
            optimizations.append(CostOptimization(
                type="Right-sizing",
                service=service,
                currentCost=amount,
                potentialSavings=amount * 0.30,  # 30% potential savings
                recommendation="Review EC2 instance utilization. Consider Reserved Instances or Savings Plans for predictable workloads. Right-size underutilized instances.",
                priority="high"
            ))

        # RDS optimization
        if 'RDS' in service.upper() and amount > 300:
            optimizations.append(CostOptimization(
                type="Reserved Capacity",
                service=service,
                currentCost=amount,
                potentialSavings=amount * 0.40,  # 40% potential savings
                recommendation="Purchase RDS Reserved Instances for up to 40% cost savings. Review database instance types and storage configurations.",
                priority="high"
            ))

        # S3 optimization
        if 'S3' in service.upper() and amount > 200:
            optimizations.append(CostOptimization(
                type="Storage Tiering",
                service=service,
                currentCost=amount,
                potentialSavings=amount * 0.25,  # 25% potential savings
                recommendation="Implement S3 Intelligent-Tiering or lifecycle policies to move infrequently accessed data to cheaper storage classes (S3-IA, Glacier).",
                priority="medium"
            ))

        # Lambda optimization
        if 'LAMBDA' in service.upper() and amount > 100:
            optimizations.append(CostOptimization(
                type="Function Optimization",
                service=service,
                currentCost=amount,
                potentialSavings=amount * 0.15,  # 15% potential savings
                recommendation="Optimize Lambda function memory allocation and execution time. Consider using ARM-based Graviton2 processors for better price-performance.",
                priority="medium"
            ))

        # CloudWatch optimization
        if 'CLOUDWATCH' in service.upper() and amount > 50:
            optimizations.append(CostOptimization(
                type="Log Management",
                service=service,
                currentCost=amount,
                potentialSavings=amount * 0.35,  # 35% potential savings
                recommendation="Review CloudWatch Logs retention policies. Export old logs to S3 for long-term archival. Reduce log verbosity where possible.",
                priority="low"
            ))

    # Sort by potential savings (highest first)
    optimizations.sort(key=lambda x: x.potentialSavings, reverse=True)

    return optimizations[:10]  # Return top 10 optimizations


def fetch_cost_and_usage(session, start_date: str, end_date: str, granularity: str = "MONTHLY") -> List[Dict]:
    """Fetch cost and usage data from AWS Cost Explorer"""
    try:
        # Cost Explorer API is only available in us-east-1
        ce_client = session.client('ce', region_name='us-east-1')

        logger.info(f"Fetching cost data from {start_date} to {end_date} with granularity {granularity}")

        response = ce_client.get_cost_and_usage(
            TimePeriod={
                'Start': start_date,
                'End': end_date
            },
            Granularity=granularity,
            Metrics=['UnblendedCost'],
            GroupBy=[
                {
                    'Type': 'DIMENSION',
                    'Key': 'SERVICE'
                }
            ]
        )

        monthly_costs = []

        for result in response.get('ResultsByTime', []):
            month = result['TimePeriod']['Start']
            total_amount = 0
            services = []

            for group in result.get('Groups', []):
                service_name = group['Keys'][0]
                amount = float(group['Metrics']['UnblendedCost']['Amount'])
                total_amount += amount

                if amount > 0.01:  # Filter out negligible costs
                    services.append({
                        'service': service_name,
                        'amount': amount,
                        'currency': group['Metrics']['UnblendedCost']['Unit']
                    })

            # Sort services by cost (highest first)
            services.sort(key=lambda x: x['amount'], reverse=True)

            # Calculate percentages
            for service in services:
                service['percentage'] = (service['amount'] / total_amount * 100) if total_amount > 0 else 0

            monthly_costs.append({
                'month': month,
                'amount': total_amount,
                'currency': 'USD',
                'services': services
            })

        return monthly_costs

    except ClientError as e:
        raise handle_aws_error(e, "fetch_cost_and_usage")


# ============================================================================
# API ROUTES
# ============================================================================

@router.get(
    "/billing/overview",
    response_model=StandardResponse,
    summary="Get comprehensive billing overview",
    description="Returns 6-month billing history, anomalies, and optimization recommendations",
)
async def get_billing_overview(
    request: Request,
    account_id: str = Query(..., description="AWS Account ID", example="123456789012"),
    region: str = Query("us-east-1", description="AWS Region", example="us-east-1")
):
    """Get comprehensive billing overview with cost analysis"""

    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(status_code=401, detail="AWS session not found")

    try:
        # Check cache first
        cached = get_cache(account_id, region, "billing", "overview")
        if cached:
            return cached

        logger.info(f"Fetching billing overview for account {account_id}")

        # Get 6-month data
        start_date_6m, end_date = get_date_range(months_back=6)
        monthly_costs_6m = fetch_cost_and_usage(session, start_date_6m, end_date, "MONTHLY")

        # Get 3-month detailed data
        start_date_3m, _ = get_date_range(months_back=3)
        monthly_costs_3m = fetch_cost_and_usage(session, start_date_3m, end_date, "MONTHLY")

        # Calculate trends for services
        if len(monthly_costs_3m) >= 2:
            current_month_data = monthly_costs_3m[-1]
            previous_month_data = monthly_costs_3m[-2]

            current_services = {s['service']: s['amount'] for s in current_month_data['services']}
            previous_services = {s['service']: s['amount'] for s in previous_month_data['services']}

            for service in current_month_data['services']:
                service_name = service['service']
                current_cost = current_services.get(service_name, 0)
                previous_cost = previous_services.get(service_name, 0)

                trend_data = calculate_cost_trend(current_cost, previous_cost)
                service.update(trend_data)

        # Calculate summary statistics
        total_spend = sum(month['amount'] for month in monthly_costs_6m)
        average_monthly_spend = total_spend / len(monthly_costs_6m) if monthly_costs_6m else 0

        # Detect anomalies
        anomalies = detect_anomalies(monthly_costs_6m)

        # Generate optimizations
        optimizations = generate_optimizations(monthly_costs_6m)

        # Generate forecast (simple projection based on trend)
        forecast = []
        if len(monthly_costs_6m) >= 2:
            recent_trend = (monthly_costs_6m[-1]['amount'] - monthly_costs_6m[-2]['amount']) / monthly_costs_6m[-2]['amount']
            last_amount = monthly_costs_6m[-1]['amount']

            for i in range(1, 4):  # Forecast next 3 months
                forecast_date = datetime.now().date() + relativedelta(months=i)
                forecast_amount = last_amount * (1 + (recent_trend * i))
                forecast.append({
                    'month': forecast_date.strftime('%Y-%m'),
                    'estimatedAmount': round(forecast_amount, 2),
                    'confidenceLevel': 'medium'
                })

        # Build response
        billing_data = {
            'last6Months': monthly_costs_6m,
            'last3MonthsDetailed': monthly_costs_3m,
            'currentMonth': monthly_costs_6m[-1] if monthly_costs_6m else {'month': '', 'amount': 0, 'currency': 'USD', 'services': []},
            'anomalies': [a.dict() for a in anomalies],
            'forecast': forecast,
            'optimizations': [o.dict() for o in optimizations],
            'totalSpend': round(total_spend, 2),
            'averageMonthlySpend': round(average_monthly_spend, 2)
        }

        result = StandardResponse(
            status="success",
            message="Retrieved billing overview successfully",
            data=billing_data,
            metadata={
                "account_id": account_id,
                "region": region,
                "months_analyzed": len(monthly_costs_6m),
                "anomalies_detected": len(anomalies),
                "optimizations_found": len(optimizations),
                "timestamp": datetime.now().isoformat()
            }
        )

        # Cache the result
        set_cache(account_id, region, "billing", "overview", result.dict())

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error in get_billing_overview")
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/billing/cost-explorer",
    response_model=StandardResponse,
    summary="Get cost explorer data with filtering",
    description="Returns cost data with custom date ranges, granularity, and grouping options",
)
async def get_cost_explorer_data(
    request: Request,
    account_id: str = Query(..., description="AWS Account ID"),
    region: str = Query("us-east-1", description="AWS Region"),
    start_date: str = Query(..., description="Start date (YYYY-MM-DD)"),
    end_date: str = Query(..., description="End date (YYYY-MM-DD)"),
    granularity: str = Query("DAILY", description="Granularity: DAILY, MONTHLY, or HOURLY"),
    group_by: str = Query("SERVICE", description="Group by: SERVICE, REGION, USAGE_TYPE, TAG, or ACCOUNT")
):
    """Get cost explorer data with custom filters"""

    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(status_code=401, detail="AWS session not found")

    try:
        # Validate granularity
        valid_granularities = ["DAILY", "MONTHLY", "HOURLY"]
        if granularity not in valid_granularities:
            raise HTTPException(status_code=400, detail=f"Invalid granularity. Must be one of: {', '.join(valid_granularities)}")

        # Check cache
        cache_key = f"{start_date}:{end_date}:{granularity}:{group_by}"
        cached = get_cache(account_id, region, "cost-explorer", cache_key)
        if cached:
            return cached

        logger.info(f"Fetching cost explorer data: {start_date} to {end_date}, {granularity}, group by {group_by}")

        # Cost Explorer API is only available in us-east-1
        ce_client = session.client('ce', region_name='us-east-1')

        # Prepare GroupBy dimension
        group_by_config = []
        if group_by in ["SERVICE", "REGION", "USAGE_TYPE", "ACCOUNT_ID"]:
            group_by_config = [{
                'Type': 'DIMENSION',
                'Key': group_by if group_by != "ACCOUNT" else "LINKED_ACCOUNT"
            }]

        # Fetch cost data
        response = ce_client.get_cost_and_usage(
            TimePeriod={
                'Start': start_date,
                'End': end_date
            },
            Granularity=granularity,
            Metrics=['UnblendedCost'],
            GroupBy=group_by_config
        )

        # Process results
        time_series = []
        all_services = set()

        for result in response.get('ResultsByTime', []):
            date = result['TimePeriod']['Start']
            breakdown = {}
            total_amount = 0

            for group in result.get('Groups', []):
                key = group['Keys'][0] if group['Keys'] else 'Other'
                amount = float(group['Metrics']['UnblendedCost']['Amount'])

                if amount > 0:
                    breakdown[key] = round(amount, 2)
                    all_services.add(key)
                    total_amount += amount

            # Handle case with no groups (total only)
            if not breakdown and 'Total' in result:
                total_amount = float(result['Total']['UnblendedCost']['Amount'])
                breakdown['Total'] = round(total_amount, 2)

            time_series.append({
                'date': date,
                'amount': round(total_amount, 2),
                'breakdown': breakdown
            })

        # Calculate summary statistics
        total_cost = sum(item['amount'] for item in time_series)
        average_cost = total_cost / len(time_series) if time_series else 0

        # Calculate change from previous period
        if len(time_series) >= 2:
            current_period_cost = sum(item['amount'] for item in time_series[len(time_series)//2:])
            previous_period_cost = sum(item['amount'] for item in time_series[:len(time_series)//2])
            change = current_period_cost - previous_period_cost
            change_percentage = (change / previous_period_cost * 100) if previous_period_cost > 0 else 0
        else:
            change = 0
            change_percentage = 0

        # Calculate top services/groups
        service_totals = {}
        for item in time_series:
            for service, amount in item['breakdown'].items():
                service_totals[service] = service_totals.get(service, 0) + amount

        top_services = [
            {
                'service': service,
                'amount': round(amount, 2),
                'percentage': round((amount / total_cost * 100) if total_cost > 0 else 0, 2)
            }
            for service, amount in sorted(service_totals.items(), key=lambda x: x[1], reverse=True)[:10]
        ]

        # Build response
        cost_explorer_data = {
            'timeSeries': time_series,
            'summary': {
                'total': round(total_cost, 2),
                'average': round(average_cost, 2),
                'change': round(change, 2),
                'changePercentage': round(change_percentage, 2)
            },
            'topServices': top_services,
            'filters': {
                'startDate': start_date,
                'endDate': end_date,
                'granularity': granularity,
                'groupBy': group_by
            }
        }

        result = StandardResponse(
            status="success",
            message="Cost explorer data retrieved successfully",
            data=cost_explorer_data,
            metadata={
                "account_id": account_id,
                "region": region,
                "data_points": len(time_series),
                "total_services": len(all_services),
                "timestamp": datetime.now().isoformat()
            }
        )

        # Cache the result
        set_cache(account_id, region, "cost-explorer", cache_key, result.dict())

        return result

    except HTTPException:
        raise
    except ClientError as e:
        raise handle_aws_error(e, "get_cost_explorer_data")
    except Exception as e:
        logger.exception(f"Unexpected error in get_cost_explorer_data")
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/billing/budgets",
    response_model=StandardResponse,
    summary="Get AWS Budgets",
    description="Returns configured AWS budgets and their current status",
)
async def get_budgets(
    request: Request,
    account_id: str = Query(..., description="AWS Account ID"),
    region: str = Query("us-east-1", description="AWS Region")
):
    """Get AWS Budgets data"""

    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(status_code=401, detail="AWS session not found")

    try:
        # Check cache
        cached = get_cache(account_id, region, "budgets", "list")
        if cached:
            return cached

        logger.info(f"Fetching budgets for account {account_id}")

        # Budgets API is only available in us-east-1
        budgets_client = session.client('budgets', region_name='us-east-1')

        response = budgets_client.describe_budgets(AccountId=account_id)

        budgets = []
        for budget in response.get('Budgets', []):
            budget_data = {
                'id': budget.get('BudgetName', 'Unknown'),
                'name': budget.get('BudgetName', 'Unknown'),
                'amount': float(budget.get('BudgetLimit', {}).get('Amount', 0)),
                'spent': float(budget.get('CalculatedSpend', {}).get('ActualSpend', {}).get('Amount', 0)),
                'currency': budget.get('BudgetLimit', {}).get('Unit', 'USD'),
                'period': budget.get('TimeUnit', 'MONTHLY'),
                'alerts': [],  # TODO: Fetch budget alerts
                'status': 'ok'  # Will be calculated based on threshold
            }

            # Calculate status
            if budget_data['amount'] > 0:
                usage_percentage = (budget_data['spent'] / budget_data['amount']) * 100
                if usage_percentage >= 100:
                    budget_data['status'] = 'exceeded'
                elif usage_percentage >= 80:
                    budget_data['status'] = 'warning'

            budgets.append(budget_data)

        result = StandardResponse(
            status="success",
            message="Budgets retrieved successfully",
            data=budgets,
            metadata={
                "account_id": account_id,
                "budget_count": len(budgets),
                "timestamp": datetime.now().isoformat()
            }
        )

        # Cache the result
        set_cache(account_id, region, "budgets", "list", result.dict())

        return result

    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "AccessDeniedException":
            # Return empty list if no access to Budgets API
            logger.warning(f"No access to Budgets API for account {account_id}")
            return StandardResponse(
                status="success",
                message="No budgets found or insufficient permissions",
                data=[],
                metadata={"account_id": account_id}
            )
        raise handle_aws_error(e, "get_budgets")
    except Exception as e:
        logger.exception(f"Unexpected error in get_budgets")
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/billing/reserved-instances",
    response_model=StandardResponse,
    summary="Get Reserved Instances",
    description="Returns Reserved Instance utilization and recommendations",
)
async def get_reserved_instances(
    request: Request,
    account_id: str = Query(..., description="AWS Account ID"),
    region: str = Query("us-east-1", description="AWS Region")
):
    """Get Reserved Instances data with utilization metrics"""

    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(status_code=401, detail="AWS session not found")

    try:
        # Check cache
        cached = get_cache(account_id, region, "reserved-instances", "list")
        if cached:
            return cached

        logger.info(f"Fetching Reserved Instances for account {account_id} in region {region}")

        ec2_client = session.client('ec2', region_name=region)
        ce_client = session.client('ce', region_name='us-east-1')

        # Get Reserved Instances
        ri_response = ec2_client.describe_reserved_instances()

        reserved_instances = []

        for ri in ri_response.get('ReservedInstances', []):
            # Skip retired/payment-failed RIs
            if ri['State'] in ['retired', 'payment-failed']:
                continue

            ri_id = ri['ReservedInstancesId']

            # Get utilization from Cost Explorer (last 30 days)
            utilization_percentage = None
            try:
                end_date = datetime.now().date()
                start_date = end_date - timedelta(days=30)

                util_response = ce_client.get_reservation_utilization(
                    TimePeriod={
                        'Start': start_date.isoformat(),
                        'End': end_date.isoformat()
                    },
                    Filter={
                        'Dimensions': {
                            'Key': 'INSTANCE_TYPE',
                            'Values': [ri['InstanceType']]
                        }
                    }
                )

                if util_response.get('UtilizationsByTime'):
                    total_utilization = util_response['UtilizationsByTime']
                    if total_utilization:
                        utilization = total_utilization[-1].get('Total', {})
                        util_percentage = utilization.get('UtilizationPercentage', '0')
                        utilization_percentage = float(util_percentage)
            except Exception as e:
                logger.warning(f"Could not fetch utilization for RI {ri_id}: {str(e)}")
                # Estimate utilization based on state
                if ri['State'] == 'active':
                    utilization_percentage = 75.0  # Default estimate
                else:
                    utilization_percentage = 0.0

            # Calculate estimated savings (rough estimate: 30-40% savings vs on-demand)
            hours_remaining = 0
            if ri['End']:
                hours_remaining = (ri['End'].replace(tzinfo=None) - datetime.now()).total_seconds() / 3600
                hours_remaining = max(0, hours_remaining)

            estimated_savings = ri['InstanceCount'] * hours_remaining * 0.1  # Rough estimate

            ri_data = {
                'id': ri_id,
                'instanceType': ri['InstanceType'],
                'instanceCount': ri['InstanceCount'],
                'availabilityZone': ri.get('AvailabilityZone', 'Regional'),
                'state': ri['State'],
                'start': ri['Start'].isoformat() if ri.get('Start') else None,
                'end': ri['End'].isoformat() if ri.get('End') else None,
                'duration': ri.get('Duration', 0),
                'offeringType': ri.get('OfferingType', 'N/A'),
                'offeringClass': ri.get('OfferingClass', 'standard'),
                'productDescription': ri.get('ProductDescription', ''),
                'utilizationPercentage': utilization_percentage,
                'estimatedSavings': round(estimated_savings, 2)
            }

            reserved_instances.append(ri_data)

        result = StandardResponse(
            status="success",
            message="Reserved Instances retrieved successfully",
            data=reserved_instances,
            metadata={
                "account_id": account_id,
                "region": region,
                "ri_count": len(reserved_instances),
                "timestamp": datetime.now().isoformat()
            }
        )

        # Cache the result
        set_cache(account_id, region, "reserved-instances", "list", result.dict())

        return result

    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "AccessDeniedException":
            logger.warning(f"No access to Reserved Instances for account {account_id}")
            return StandardResponse(
                status="success",
                message="No Reserved Instances found or insufficient permissions",
                data=[],
                metadata={"account_id": account_id, "region": region}
            )
        raise handle_aws_error(e, "get_reserved_instances")
    except Exception as e:
        logger.exception(f"Unexpected error in get_reserved_instances")
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/billing/savings-plans",
    response_model=StandardResponse,
    summary="Get Savings Plans",
    description="Returns Savings Plans utilization and recommendations",
)
async def get_savings_plans(
    request: Request,
    account_id: str = Query(..., description="AWS Account ID"),
    region: str = Query("us-east-1", description="AWS Region")
):
    """Get Savings Plans data with utilization and savings metrics"""

    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(status_code=401, detail="AWS session not found")

    try:
        # Check cache
        cached = get_cache(account_id, region, "savings-plans", "list")
        if cached:
            return cached

        logger.info(f"Fetching Savings Plans for account {account_id}")

        # Savings Plans API - region agnostic, use us-east-1
        sp_client = session.client('savingsplans', region_name='us-east-1')
        ce_client = session.client('ce', region_name='us-east-1')

        # Get Savings Plans - fetch all, then filter by state in code
        # The API doesn't support 'state' filter, only: region, ec2-instance-family,
        # commitment, upfront, term, savings-plan-type, payment-option, start, end
        sp_response = sp_client.describe_savings_plans(
            states=['active', 'payment-pending', 'retired']
        )

        savings_plans = []

        for sp in sp_response.get('savingsPlans', []):
            sp_id = sp['savingsPlanId']
            plan_type = sp['savingsPlanType']  # Compute, EC2Instance, SageMaker

            # Get utilization from Cost Explorer (last 30 days)
            utilization_percentage = None
            savings_amount = 0
            savings_percentage = 0

            try:
                end_date = datetime.now().date()
                start_date = end_date - timedelta(days=30)

                util_response = ce_client.get_savings_plans_utilization(
                    TimePeriod={
                        'Start': start_date.isoformat(),
                        'End': end_date.isoformat()
                    }
                )

                if util_response.get('Total'):
                    total = util_response['Total']
                    utilization = total.get('Utilization', {})
                    utilization_percentage = float(utilization.get('UtilizationPercentage', '0'))

                    # Get savings
                    savings = total.get('Savings', {})
                    savings_amount = float(savings.get('NetSavings', {}).get('Amount', '0'))

                    # Calculate savings percentage
                    on_demand_cost = float(savings.get('OnDemandCostEquivalent', {}).get('Amount', '0'))
                    if on_demand_cost > 0:
                        savings_percentage = (savings_amount / on_demand_cost) * 100

            except Exception as e:
                logger.warning(f"Could not fetch utilization for Savings Plan {sp_id}: {str(e)}")
                # Estimate utilization based on state
                if sp['state'] == 'active':
                    utilization_percentage = 85.0  # Default estimate
                    savings_percentage = 30.0  # Default estimate
                else:
                    utilization_percentage = 0.0

            # Parse commitment
            commitment = float(sp.get('commitment', '0'))

            # Parse term
            term_duration = sp.get('termDurationInSeconds', 0)
            term = f"{term_duration // (365 * 24 * 3600)} year" if term_duration > 0 else "Unknown"

            sp_data = {
                'id': sp_id,
                'planType': plan_type,
                'status': sp['state'],
                'hourlyCommitment': commitment,
                'start': sp.get('start') if isinstance(sp.get('start'), str) else sp.get('start').isoformat() if sp.get('start') else None,
                'end': sp.get('end') if isinstance(sp.get('end'), str) else sp.get('end').isoformat() if sp.get('end') else None,
                'term': term,
                'paymentOption': sp.get('paymentOption', 'All Upfront'),
                'region': sp.get('region', 'Global'),
                'utilizationPercentage': utilization_percentage,
                'savingsAmount': round(savings_amount, 2),
                'savingsPercentage': round(savings_percentage, 2)
            }

            savings_plans.append(sp_data)

        result = StandardResponse(
            status="success",
            message="Savings Plans retrieved successfully",
            data=savings_plans,
            metadata={
                "account_id": account_id,
                "plans_count": len(savings_plans),
                "timestamp": datetime.now().isoformat()
            }
        )

        # Cache the result
        set_cache(account_id, region, "savings-plans", "list", result.dict())

        return result

    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "AccessDeniedException":
            logger.warning(f"No access to Savings Plans for account {account_id}")
            return StandardResponse(
                status="success",
                message="No Savings Plans found or insufficient permissions",
                data=[],
                metadata={"account_id": account_id}
            )
        raise handle_aws_error(e, "get_savings_plans")
    except Exception as e:
        logger.exception(f"Unexpected error in get_savings_plans")
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/billing/cost-allocation-tags",
    response_model=StandardResponse,
    summary="Get Cost Allocation Tags",
    description="Returns cost allocation tag breakdown",
)
async def get_cost_allocation_tags(
    request: Request,
    account_id: str = Query(..., description="AWS Account ID"),
    region: str = Query("us-east-1", description="AWS Region")
):
    """Get Cost Allocation Tags data"""

    # TODO: Implement Cost Allocation Tags
    # This would use Cost Explorer API with tag grouping

    return StandardResponse(
        status="success",
        message="Cost Allocation Tags feature coming soon",
        data=[],
        metadata={
            "account_id": account_id,
            "region": region,
            "note": "This feature is under development"
        }
    )


@router.get(
    "/billing/{service}",
    response_model=StandardResponse,
    summary="Get billing data for specific service",
    description="Returns billing information for a specific billing service",
)
async def get_billing_service(
    request: Request,
    service: str,
    account_id: str = Query(..., description="AWS Account ID", example="123456789012"),
    region: str = Query("us-east-1", description="AWS Region", example="us-east-1")
):
    """Get billing data for a specific service"""

    if service not in BILLING_SERVICES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid service '{service}'. Supported services: {', '.join(BILLING_SERVICES)}"
        )

    # For now, all services redirect to overview
    # In future, can add service-specific endpoints (budgets, cost explorer, etc.)
    return await get_billing_overview(request, account_id, region)
