import boto3
import logging
from botocore.exceptions import ClientError

def get_role_from_instance_profile(iam_client, instance_profile_arn):
    """Gets the role name from an instance profile ARN."""
    try:
        profile_name = instance_profile_arn.split('/')[-1]
        response = iam_client.get_instance_profile(InstanceProfileName=profile_name)
        roles = response.get('InstanceProfile', {}).get('Roles', [])
        if roles:
            # Assuming only one role per profile for simplicity
            role_name = roles[0]['RoleName']
            logging.debug(f"Found role '{role_name}' for instance profile '{profile_name}'.")
            return role_name
        else:
            logging.warning(f"No roles found for instance profile: {profile_name}")
            return None
    except iam_client.exceptions.NoSuchEntityException:
        logging.error(f"Instance profile '{profile_name}' not found.")
        return None
    except Exception as e:
        logging.error(f"Error getting role from instance profile {instance_profile_arn}: {e}")
        return None

def check_ssm_policy(iam_client, role_name):
    """Checks if the AmazonSSMManagedInstanceCore policy is attached to the role.

    Args:
        iam_client: Initialized Boto3 IAM client.
        role_name (str): The name of the IAM role to check.

    Returns:
        bool: True if the policy is attached, False otherwise.
    """
    required_policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    found_policy = False
    if not role_name:
        logging.error("Cannot check policy for an empty role name.")
        return False
    try:
        # Check managed policies
        logging.debug(f"Checking managed policies attached to role '{role_name}' for '{required_policy_arn}'...")
        paginator = iam_client.get_paginator('list_attached_role_policies')
        for page in paginator.paginate(RoleName=role_name):
            for policy in page.get('AttachedPolicies', []):
                if policy.get('PolicyArn') == required_policy_arn:
                    found_policy = True
                    break
            if found_policy:
                break

        if found_policy:
            logging.info(f"Required policy '{required_policy_arn}' IS attached to role '{role_name}'.")
        else:
            logging.warning(f"Required policy '{required_policy_arn}' IS NOT attached to role '{role_name}'.")
            # Optional: Check inline policies if needed, though SSM policy is typically managed
            # response_inline = iam_client.list_role_policies(RoleName=role_name)
            # logging.info(f"Inline policies for role '{role_name}': {response_inline.get('PolicyNames')}")
        return found_policy

    except iam_client.exceptions.NoSuchEntityException:
        logging.error(f"Role '{role_name}' not found while checking policies.")
        return False
    except Exception as e:
        logging.error(f"Error checking policies for role {role_name}: {e}")
        return False

def get_instance_iam_details(ec2_client, iam_client, instance_id):
    """
    Retrieves detailed IAM information (profile, role, policies) for a given instance.

    Args:
        ec2_client: Initialized Boto3 EC2 client.
        iam_client: Initialized Boto3 IAM client.
        instance_id (str): The ID of the target EC2 instance.

    Returns:
        dict: A dictionary containing IAM details (profile_arn, role_name,
              attached_policies, inline_policies) or error information.
              Returns None if the instance is not found.
    """
    iam_details = {
        "profile_arn": None,
        "role_name": None,
        "attached_policies": [],
        "inline_policies": [],
        "error": None
    }
    try:
        logging.debug(f"Fetching instance details for {instance_id} to get IAM profile.")
        instance_info = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = instance_info.get('Reservations', [])
        if not reservations or not reservations[0].get('Instances'):
            logging.error(f"Instance {instance_id} not found during IAM check.")
            iam_details["error"] = f"Instance {instance_id} not found."
            return None # Instance not found is a distinct case

        instance = reservations[0]['Instances'][0]
        instance_profile_data = instance.get('IamInstanceProfile')

        if not instance_profile_data or 'Arn' not in instance_profile_data:
            logging.warning(f"No IAM Instance Profile attached to instance {instance_id}.")
            iam_details["error"] = "No IAM Instance Profile attached."
            return iam_details # Return details indicating no profile

        iam_details["profile_arn"] = instance_profile_data['Arn']
        logging.debug(f"Instance profile ARN: {iam_details['profile_arn']}")

        # Get role name using existing function
        role_name = get_role_from_instance_profile(iam_client, iam_details["profile_arn"])
        iam_details["role_name"] = role_name

        if not role_name:
            # Error already logged by get_role_from_instance_profile
            iam_details["error"] = f"Could not determine role name from profile {iam_details['profile_arn']}."
            return iam_details # Return details indicating role issue

        # Get attached managed policies
        logging.debug(f"Fetching attached managed policies for role '{role_name}'.")
        try:
            paginator = iam_client.get_paginator('list_attached_role_policies')
            for page in paginator.paginate(RoleName=role_name):
                for policy in page.get('AttachedPolicies', []):
                    iam_details["attached_policies"].append(policy.get('PolicyArn'))
        except ClientError as e:
            logging.error(f"Error listing attached policies for role {role_name}: {e}")
            iam_details["error"] = f"Error listing attached policies: {e}"
            # Continue to check inline policies if possible

        # Get inline policies
        logging.debug(f"Fetching inline policies for role '{role_name}'.")
        try:
            paginator_inline = iam_client.get_paginator('list_role_policies')
            for page in paginator_inline.paginate(RoleName=role_name):
                 iam_details["inline_policies"].extend(page.get('PolicyNames', []))
        except ClientError as e:
            logging.error(f"Error listing inline policies for role {role_name}: {e}")
            # Update error only if no previous error occurred
            if not iam_details["error"]:
                iam_details["error"] = f"Error listing inline policies: {e}"

        if not iam_details["error"]:
             logging.info(f"Successfully retrieved IAM details for role '{role_name}'.")

        return iam_details

    except ClientError as e:
        # Handle Boto3 client errors specifically (e.g., AccessDenied, throttling)
        logging.error(f"AWS API error fetching IAM details for instance {instance_id}: {e}", exc_info=True)
        iam_details["error"] = f"AWS API Error: {e}"
        return iam_details
    except Exception as e:
        # Catch any other unexpected errors
        logging.error(f"Unexpected error fetching IAM details for instance {instance_id}: {e}", exc_info=True)
        iam_details["error"] = f"Unexpected Error: {e}"
        return iam_details

# Example of how to potentially use these functions (will be called from runner script)
# def perform_iam_check(instance_id, region):
#     ec2_client = boto3.client('ec2', region_name=region)
#     iam_client = boto3.client('iam')
#     try:
#         instance_info = ec2_client.describe_instances(InstanceIds=[instance_id])
#         reservations = instance_info.get('Reservations', [])
#         if not reservations or not reservations[0].get('Instances'):
#             logging.error(f"Instance {instance_id} not found.")
#             return False
#         instance = reservations[0]['Instances'][0]
#         instance_profile = instance.get('IamInstanceProfile')
#         if not instance_profile or 'Arn' not in instance_profile:
#             logging.error(f"No IAM Instance Profile attached to instance {instance_id}.")
#             return False
#         instance_profile_arn = instance_profile['Arn']
#         role_name = get_role_from_instance_profile(iam_client, instance_profile_arn)
#         if not role_name:
#             return False # Error already logged
#         return check_ssm_policy(iam_client, role_name)
#     except Exception as e:
#         logging.error(f"Failed during IAM check: {e}")
#         return False
