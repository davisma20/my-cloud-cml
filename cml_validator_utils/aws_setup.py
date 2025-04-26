import boto3
import logging
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

def setup_logging(log_file, debug=False):
    """Sets up logging configuration."""
    log_level = logging.DEBUG if debug else logging.INFO
    # Basic config logs to console
    logging.basicConfig(level=log_level, 
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Create a logger instance for the application
    logger = logging.getLogger('AwsCmlValidator')
    logger.setLevel(log_level) # Ensure the logger respects the debug level

    # Remove existing handlers to avoid duplicates if called multiple times
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # File Handler
    try:
        file_handler = logging.FileHandler(log_file, mode='a') # Append mode
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(log_level)
        logger.addHandler(file_handler)
    except Exception as e:
        logging.error(f"Failed to set up file logging handler for {log_file}: {e}")

    # Console Handler (if not already configured by basicConfig, or to customize)
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(log_level)
    logger.addHandler(console_handler)

    return logger

def initialize_aws_session(region_name=None, profile_name=None):
    """Initializes and returns a boto3 session."""
    try:
        if profile_name:
            session = boto3.Session(profile_name=profile_name, region_name=region_name)
        else:
            session = boto3.Session(region_name=region_name)
        return session
    except (NoCredentialsError, PartialCredentialsError) as e:
        logging.error(f"AWS credentials error: {e}")
    except Exception as e:
        logging.error(f"Failed to initialize AWS session: {e}")
    return None

def get_ec2_client(session, endpoint_url=None):
    """Returns an EC2 client from the session."""
    logger = logging.getLogger('AwsCmlValidator')
    if not session:
        logger.error("Cannot create EC2 client: Boto3 session is not available.")
        return None
    logger.debug(f"Creating EC2 client with endpoint URL: {endpoint_url if endpoint_url else 'Default'}")
    try:
        return session.client('ec2', endpoint_url=endpoint_url)
    except ClientError as e:
        logger.error(f"Failed to create EC2 client: {e}")
        return None

def get_instance_details(ec2_client, instance_id):
    """Retrieves the details of the specified EC2 instance."""
    logger = logging.getLogger('AwsCmlValidator')
    logger.info(f"Fetching details for instance: {instance_id}")
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        if not response['Reservations'] or not response['Reservations'][0]['Instances']:
            logger.error(f"No instance found with ID: {instance_id}")
            return None, None, None, None, None
        
        instance_data = response['Reservations'][0]['Instances'][0]
        logger.debug(f"Raw instance data: {instance_data}") # Log raw data
        
        instance_details = instance_data # Store the full dictionary
        subnet_id = instance_data.get('SubnetId')
        vpc_id = instance_data.get('VpcId')
        security_groups = instance_data.get('SecurityGroups', [])
        security_group_ids = [sg['GroupId'] for sg in security_groups] # Extract only IDs

        if not subnet_id:
            logger.warning("Subnet ID not found in instance details.")
        if not vpc_id:
            logger.warning("VPC ID not found in instance details.")
        if not security_group_ids:
            logger.warning("Security Group IDs not found in instance details.")
            
        logger.info(f"Successfully retrieved details - Subnet: {subnet_id}, VPC: {vpc_id}, SGs: {security_group_ids}")
        return instance_details, subnet_id, vpc_id, security_groups, security_group_ids

    except ClientError as e:
        logger.error(f"Error fetching instance details for {instance_id}: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred fetching instance details: {e}")
        
    return None, None, None, None, None

