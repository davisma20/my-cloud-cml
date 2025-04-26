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
    """Checks if the current AWS principal has the required IAM permissions."""
    logger = logging.getLogger('AwsCmlValidator')
    logger.info("--- Starting IAM Permission Checks ---")
    iam_client = get_iam_client(session, endpoint_url)
    sts_client = session.client('sts', endpoint_url=endpoint_url)

    if not iam_client or not sts_client:
        logger.error("IAM or STS client not available. Cannot check permissions.")
        return {'status': 'Error', 'details': 'IAM/STS client setup failed', 'all_required_met': False}

    try:
        caller_identity = sts_client.get_caller_identity()
        principal_arn = caller_identity['Arn'] # This is the assumed-role ARN
        logger.info(f"Checking permissions for principal (Assumed Role ARN): {principal_arn}")

        # Check if the principal is the root user (ARN format: arn:aws:iam::<account_id>:root)
        if ':root' in principal_arn:
            logger.warning("Principal is the root user. iam:SimulatePrincipalPolicy cannot simulate root user policies.")
            logger.warning("Skipping permission simulation. Assuming root has necessary permissions, but this is NOT guaranteed.")
            permissions_summary = {perm: 'Allowed (Assumed for Root)' for perm in required_permissions}
            all_required_met = True # Assume true, but specific actions might still fail
            status = 'Checked (Assumed for Root)'

        else:
            # --- Extract Base Role ARN for Simulation --- 
            # SimulatePrincipalPolicy needs the actual Role ARN, not the assumed-role session ARN.
            # Assumed ARN: arn:aws:sts::ACCOUNT_ID:assumed-role/ROLE_NAME/SESSION_NAME
            # Role ARN:    arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME
            try:
                arn_parts = principal_arn.split(':')
                assumed_role_part = arn_parts[5].split('/')
                if assumed_role_part[0] == 'assumed-role':
                    account_id = arn_parts[4]
                    role_name = assumed_role_part[1]
                    policy_source_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
                    logger.info(f"Using Role ARN for simulation: {policy_source_arn}")
                else:
                    # Should not happen for assumed roles, but handle defensively
                    policy_source_arn = principal_arn 
                    logger.warning(f"Could not extract base role ARN from {principal_arn}. Using original ARN for simulation.")
            except IndexError:
                 logger.error(f"Could not parse assumed role ARN: {principal_arn}. Using original ARN for simulation.")
                 policy_source_arn = principal_arn
            # ----------------------------------------------

            # Simulate policy for non-root users using the extracted Role ARN
            results = _simulate_policy(iam_client, policy_source_arn, required_permissions + optional_permissions)
            permissions_summary = {perm: 'Allowed' if results.get(perm) else 'Denied' for perm in required_permissions + optional_permissions}
            
            missing_required = [perm for perm in required_permissions if not results.get(perm)]
            if missing_required:
                logger.error(f"Missing required IAM permissions: {', '.join(missing_required)}")
                all_required_met = False
                status = 'Failed'
            else:
                logger.info("All required IAM permissions are present.")
                all_required_met = True
                status = 'Passed'
            
            denied_optional = [perm for perm in optional_permissions if not results.get(perm)]
            if denied_optional:
                 logger.warning(f"Missing optional IAM permissions: {', '.join(denied_optional)}")

    except ClientError as e:
        logger.error(f"AWS ClientError during permission check: {e}")
        permissions_summary = {'error': str(e)}
        all_required_met = False
        status = 'Error'
    except Exception as e:
        logger.error(f"An unexpected error occurred during permission check: {e}")
        permissions_summary = {'error': str(e)}
        all_required_met = False
        status = 'Error'

    logger.info("--- Finished IAM Permission Checks ---")
    return {'status': status, 'details': permissions_summary, 'all_required_met': all_required_met}

def _simulate_policy(iam_client, principal_arn, action_names):
    """Simulates IAM policy for a list of actions."""
    logger = logging.getLogger('AwsCmlValidator')
    results = {}
    try:
        response = iam_client.simulate_principal_policy(
            PolicySourceArn=principal_arn,
            ActionNames=action_names
        )
        
        logger.debug(f"Simulation response: {response}") # Log raw simulation result

        for result in response.get('EvaluationResults', []):
            action_name = result.get('EvalActionName')
            decision = result.get('EvalDecision')
            results[action_name] = (decision == 'allowed')
            logger.debug(f"Simulation result for {action_name}: {decision}")

    except ClientError as e:
        # Handle specific common errors gracefully
        if 'MalformedPolicyDocument' in str(e):
             logger.error(f"IAM policy simulation failed: Malformed policy document associated with {principal_arn}. Requires manual check.")
        elif 'InvalidInput' in str(e):
             logger.error(f"IAM policy simulation failed: Invalid input. Check ARN {principal_arn} and action names.")
        else:
            logger.error(f"AWS ClientError during policy simulation: {e}")
        # Mark all requested actions as undetermined/denied on simulation error
        for action in action_names:
            results[action] = False
    except Exception as e:
        logger.error(f"An unexpected error occurred during policy simulation: {e}")
        for action in action_names:
            results[action] = False
            
    return results
