import boto3
import sys
import requests
import logging
from ipaddress import ip_network, ip_address
from botocore.exceptions import ClientError

def get_public_ip():
    """Fetches the public IP of the machine running the script."""
    try:
        response = requests.get('https://checkip.amazonaws.com', timeout=5)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        ip = response.text.strip()
        logging.info(f"Automatically detected source IP: {ip}")
        return ip
    except requests.exceptions.RequestException as e:
        logging.error(f"Could not automatically determine public IP: {e}")
        return None

def check_route_table(ec2_client, subnet_id):
    """Checks the route table associated with the subnet for a default route to IGW or NAT GW.
       Note: This checks the INSTANCE'S outbound path, not the inbound path TO the instance.

       Returns:
           bool: True if a valid default route is found, False otherwise.
    """
    logging.info(f"--- Checking Route Table for Subnet: {subnet_id} ---")
    try:
        response = ec2_client.describe_route_tables(
            Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}]
        )
        if not response.get('RouteTables'):
            logging.error(f"No route table found associated with subnet {subnet_id}.")
            return False

        route_table = response['RouteTables'][0]
        rt_id = route_table['RouteTableId']
        logging.info(f"  Route Table ID: {rt_id}")
        default_route_found = False
        for route in route_table.get('Routes', []):
            dest_cidr = route.get('DestinationCidrBlock')
            gateway_id = route.get('GatewayId')
            nat_gateway_id = route.get('NatGatewayId') # Check for NAT Gateway too

            if dest_cidr == '0.0.0.0/0':
                if gateway_id and gateway_id.startswith('igw-'):
                    logging.info(f"    [PASS] Found default route (0.0.0.0/0) in {rt_id} to Internet Gateway: {gateway_id}")
                    default_route_found = True
                    break
                elif nat_gateway_id and nat_gateway_id.startswith('nat-'):
                     logging.info(f"    [PASS] Found default route (0.0.0.0/0) in {rt_id} to NAT Gateway: {nat_gateway_id}")
                     default_route_found = True
                     break
                else:
                    logging.warning(f"    [WARN] Found default route (0.0.0.0/0) in {rt_id} but target is unexpected: {gateway_id or nat_gateway_id}")
                    # Consider if this should be a failure depending on requirements

        if not default_route_found:
            logging.error(f"  [FAIL] No default route (0.0.0.0/0) to IGW or NAT GW found in {rt_id}.")
            return False
        return True

    except Exception as e:
        logging.error(f"  [ERROR] Could not describe route table for subnet {subnet_id}: {e}", exc_info=True)
        return False

def check_security_group_inbound(ec2_client, group_ids, port, source_ip):
    """Checks security group INBOUND rules for the specified port and source IP.

    Returns:
        bool: True if traffic is allowed by at least one associated SG, False otherwise.
    """
    logging.info(f"--- Checking Security Group Inbound for Port {port} from {source_ip} --- Group(s): {', '.join(group_ids)} ---")
    source_cidr = f"{source_ip}/32"
    overall_allowed = False # Default deny unless a rule allows
    try:
        response = ec2_client.describe_security_groups(GroupIds=group_ids)
        for sg in response.get('SecurityGroups', []):
            sg_id = sg['GroupId']
            logging.info(f"  Checking Security Group ID: {sg_id}")
            inbound_allowed_specific_ip = False
            inbound_allowed_any_ip = False

            for rule in sg.get('IpPermissions', []): # Check INBOUND rules
                ip_protocol = rule.get('IpProtocol')
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                ip_ranges = rule.get('IpRanges', [])

                # Check if the rule protocol is TCP ('6') or ALL ('-1')
                if ip_protocol == '6' or ip_protocol == '-1':
                    # Check if the port range includes the target port
                    port_matches = False
                    if from_port is None and to_port is None: # Rule applies to all ports for the protocol
                        port_matches = True
                    elif from_port is not None and to_port is not None and from_port <= port <= to_port:
                        port_matches = True
                    # Handle cases like SSH where FromPort=22, ToPort=22
                    elif from_port is not None and from_port == to_port and from_port == port:
                        port_matches = True

                    if port_matches:
                        logging.debug(f"    Rule matches protocol {ip_protocol} and port {port}: {rule}")
                        for ip_range in ip_ranges:
                            cidr_block = ip_range.get('CidrIp')
                            if cidr_block == source_cidr:
                                logging.info(f"      [PASS] Rule specifically allows source IP {source_cidr} for port {port} in {sg_id}.")
                                inbound_allowed_specific_ip = True
                                break # Specific IP match is enough for this rule
                            elif cidr_block == '0.0.0.0/0':
                                logging.info(f"      [PASS] Rule allows all IPs (0.0.0.0/0) for port {port} in {sg_id}.")
                                inbound_allowed_any_ip = True
                                # Don't break yet, check if a more specific rule exists
                            elif '/' in cidr_block: # Check if source IP is within a range
                                try:
                                     if ip_address(source_ip) in ip_network(cidr_block):
                                         logging.info(f"      [PASS] Rule allows source IP {source_ip} within range {cidr_block} for port {port} in {sg_id}.")
                                         inbound_allowed_any_ip = True # Treat range like 0.0.0.0/0 for precedence
                                except ValueError:
                                    logging.warning(f"      [WARN] Invalid CIDR block in rule: {cidr_block}")

                if inbound_allowed_specific_ip:
                    break # Found specific allow for this SG

            # Determine outcome for this specific Security Group
            if inbound_allowed_specific_ip:
                logging.info(f"    [RESULT SG {sg_id}] PASSED (Specific IP rule found)")
                overall_allowed = True # If any SG allows, overall is allowed
                break # No need to check other SGs if one allows
            elif inbound_allowed_any_ip:
                logging.info(f"    [RESULT SG {sg_id}] PASSED (General IP rule found, no specific match)")
                overall_allowed = True # If any SG allows, overall is allowed
                break # No need to check other SGs if one allows
            else:
                logging.info(f"    [RESULT SG {sg_id}] FAILED (No matching allow rule found)")
                # Keep overall_allowed as False if it was False, don't override a previous True

        if not overall_allowed:
            logging.error(f"  [FAIL] No security group rule found allowing inbound TCP traffic on port {port} from {source_ip}.")
        else:
             logging.info(f"  [PASS] At least one security group allows inbound TCP traffic on port {port} from {source_ip}.")
        return overall_allowed

    except Exception as e:
        logging.error(f"  [ERROR] Could not describe security groups: {e}", exc_info=True)
        return False


def check_network_acl_inbound(ec2_client, subnet_id, port, source_ip):
    """Checks the Network ACL INBOUND rules associated with the subnet.

    Returns:
        bool: True if traffic is allowed, False if denied or error.
    """
    logging.info(f"--- Checking Network ACL Inbound for Subnet {subnet_id}, Port {port}, Source {source_ip} ---")
    source_cidr = f"{source_ip}/32"
    try:
        # Find the Network ACL associated with the subnet
        response = ec2_client.describe_network_acls(
            Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}]
        )

        if not response.get('NetworkAcls'):
            # Check if it's using the default NACL for the VPC
            logging.warning(f"No explicit Network ACL associated with subnet {subnet_id}. Checking default NACL...")
            subnet_response = ec2_client.describe_subnets(SubnetIds=[subnet_id])
            if not subnet_response.get('Subnets'):
                 logging.error(f"Could not find subnet {subnet_id} details to get VPC ID.")
                 return False
            vpc_id = subnet_response['Subnets'][0]['VpcId']
            response = ec2_client.describe_network_acls(
                 Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}, {'Name': 'default', 'Values': ['true']}]
            )
            if not response.get('NetworkAcls'):
                 logging.error(f"Could not find default Network ACL for VPC {vpc_id} associated with subnet {subnet_id}.")
                 return False

        network_acl = response['NetworkAcls'][0]
        nacl_id = network_acl['NetworkAclId']
        logging.info(f"  Network ACL ID: {nacl_id}")

        # Evaluate INBOUND rules in order
        # Rules are evaluated by rule number, lowest first.
        inbound_rules = sorted([e for e in network_acl['Entries'] if not e['Egress']], key=lambda x: x['RuleNumber'])

        allowed = False # Default based on implicit deny
        rule_matched = False
        default_rule_action = 'deny' # Track the final '*' rule

        for rule in inbound_rules:
            rule_number = rule['RuleNumber']
            protocol = rule['Protocol'] # -1=ALL, 6=TCP, 17=UDP, 1=ICMP
            action = rule['RuleAction'] # 'allow' or 'deny'
            cidr_block = rule.get('CidrBlock')
            port_range = rule.get('PortRange') # Optional, applies if protocol needs ports

            # Check for the default rule
            if rule_number == 32767:
                default_rule_action = action
                logging.debug(f"    Default (*) rule action is {action}.")
                continue # Process explicit rules first

            # Check if the rule's protocol matches (TCP=6, ALL=-1)
            protocol_matches = (protocol == '6' or protocol == '-1')
            if not protocol_matches:
                continue

            # Check if the CIDR block matches
            cidr_matches = False
            if cidr_block:
                try:
                    if ip_address(source_ip) in ip_network(cidr_block):
                        cidr_matches = True
                except ValueError:
                    logging.warning(f"    [WARN] Invalid CIDR {cidr_block} in NACL rule {rule_number}")
                    continue # Skip invalid rule
            if not cidr_matches:
                continue

            # Check if the port range matches (if applicable for the rule)
            port_matches = False
            if port_range and port_range.get('From') is not None and port_range.get('To') is not None:
                if port_range['From'] <= port <= port_range['To']:
                    port_matches = True
            elif protocol == '6': # If no port range specified for TCP, it implies ALL ports
                 port_matches = True
            elif protocol == '-1': # ALL protocols implies ALL ports implicitly
                 port_matches = True

            if not port_matches:
                continue

            # If we reach here, the rule matches the traffic
            logging.info(f"    [MATCH] Rule #{rule_number} ({action.upper()}) matches: Protocol={protocol}, CIDR={cidr_block}, PortRange={port_range}")
            allowed = (action == 'allow')
            rule_matched = True
            break # Stop processing rules once the first match is found

        if rule_matched:
            if allowed:
                 logging.info(f"    [RESULT NACL {nacl_id}] PASSED (Explicit ALLOW rule #{rule_number} matched)")
            else:
                 logging.error(f"    [RESULT NACL {nacl_id}] FAILED (Explicit DENY rule #{rule_number} matched)")
        else:
             # No explicit rule matched, apply the default rule action
             allowed = (default_rule_action == 'allow')
             if allowed:
                  logging.info(f"    [RESULT NACL {nacl_id}] PASSED (No explicit rule matched, default rule is ALLOW)")
             else:
                  logging.error(f"    [RESULT NACL {nacl_id}] FAILED (No explicit rule matched, default rule is DENY)")

        if allowed:
            logging.info(f"  [PASS] Network ACL {nacl_id} allows inbound TCP traffic on port {port} from {source_ip}.")
        else:
             logging.error(f"  [FAIL] Network ACL {nacl_id} denies inbound TCP traffic on port {port} from {source_ip}.")
        return allowed

    except Exception as e:
        logging.error(f"  [ERROR] Could not describe/evaluate network ACL for subnet {subnet_id}: {e}", exc_info=True)
        return False

def get_instance_security_groups(ec2_client, instance_id):
    """
    Retrieves the detailed configuration of security groups associated with an instance.

    Args:
        ec2_client: Initialized Boto3 EC2 client.
        instance_id (str): The ID of the target EC2 instance.

    Returns:
        list: A list of dictionaries, each representing a security group's
              configuration, or None if an error occurs or the instance is not found.
    """
    security_groups_details = {
        "groups": [],
        "error": None
    }
    try:
        logging.debug(f"Fetching instance details for {instance_id} to get Security Groups.")
        instance_info = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = instance_info.get('Reservations', [])
        if not reservations or not reservations[0].get('Instances'):
            logging.error(f"Instance {instance_id} not found while getting security groups.")
            security_groups_details["error"] = f"Instance {instance_id} not found."
            return None # Instance not found

        instance = reservations[0]['Instances'][0]
        sg_references = instance.get('SecurityGroups', [])

        if not sg_references:
            logging.warning(f"No Security Groups found attached to instance {instance_id}.")
            security_groups_details["error"] = "No Security Groups attached."
            return security_groups_details # Return indicating no SGs

        group_ids = [sg['GroupId'] for sg in sg_references]
        logging.debug(f"Instance {instance_id} is associated with Security Group IDs: {group_ids}")

        # Get detailed information for these groups
        logging.debug(f"Describing Security Groups: {group_ids}")
        sg_response = ec2_client.describe_security_groups(GroupIds=group_ids)
        security_groups_details["groups"] = sg_response.get('SecurityGroups', [])

        logging.info(f"Successfully retrieved details for {len(security_groups_details['groups'])} security groups.")
        return security_groups_details

    except ClientError as e:
        logging.error(f"AWS API error fetching security groups for instance {instance_id}: {e}", exc_info=True)
        security_groups_details["error"] = f"AWS API Error: {e}"
        return security_groups_details
    except Exception as e:
        logging.error(f"Unexpected error fetching security groups for instance {instance_id}: {e}", exc_info=True)
        security_groups_details["error"] = f"Unexpected Error: {e}"
        return security_groups_details
