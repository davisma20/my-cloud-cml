import logging
from botocore.exceptions import ClientError

REQUIRED_PERMISSIONS = [
    "ec2:DescribeInstances",
    "ec2:DescribeInstanceStatus",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeNetworkAcls",
    "ec2:DescribeSubnets", # Added as NACLs are subnet-associated
    "ec2:DescribeVpcs",    # Added as sometimes useful context
    "iam:SimulatePrincipalPolicy",
    "ssm:SendCommand",
    "ssm:GetCommandInvocation",
    "ec2:GetConsoleOutput",
    "ec2:GetSystemLog" # Added for the new log retrieval method
]

OPTIONAL_PERMISSIONS = [
    # Add any optional permissions if needed later
]

def get_iam_client(session, endpoint_url=None):
    """Returns an IAM client from the session."""
    logger = logging.getLogger('AwsCmlValidator')
    if not session:
        logger.error("Cannot create IAM client: Boto3 session is not available.")
        return None
    logger.debug(f"Creating IAM client with endpoint URL: {endpoint_url if endpoint_url else 'Default'}")
    try:
        return session.client('iam', endpoint_url=endpoint_url)
    except ClientError as e:
        logger.error(f"Failed to create IAM client: {e}")
        return None

def check_iam_permissions(session, required_permissions=REQUIRED_PERMISSIONS, optional_permissions=OPTIONAL_PERMISSIONS, endpoint_url=None):
 ...
