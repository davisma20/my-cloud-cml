import logging
from botocore.exceptions import ClientError

# --- Security Group Checks ---

def check_security_groups(ec2_client, security_group_ids):
    """Checks if required outbound rules exist in the instance's Security Groups."""
    logger = logging.getLogger('AwsCmlValidator')
    logger.info("--- Starting Security Group Checks ---")
    results = {
        'status': 'Not Checked',
        'details': {},
        'ids_found': security_group_ids # Store the IDs passed in
    }

    if not security_group_ids:
        logger.warning("No Security Group IDs found for the instance. Skipping SG checks.")
        results['status'] = 'Skipped (No IDs)'
        return results

    logger.info(f"Checking Security Groups: {', '.join(security_group_ids)}")

    sg_http_ok = False
    sg_https_ok = False
    sg_ssh_ok = False # Check for inbound SSH as well

    try:
        response = ec2_client.describe_security_groups(GroupIds=security_group_ids)
        sgs_data = response.get('SecurityGroups', [])
        logger.debug(f"DescribeSecurityGroups response: {sgs_data}")

        for sg in sgs_data:
            sg_id = sg.get('GroupId')
            logger.debug(f"Analyzing rules for Security Group: {sg_id}")
            
            # Check outbound rules
            egress_rules = sg.get('IpPermissionsEgress', [])
            logger.debug(f"Egress rules for {sg_id}: {egress_rules}")
            if _evaluate_sg_rules(egress_rules, protocol='tcp', port=80, cidr='0.0.0.0/0'):
                sg_http_ok = True
                logger.debug(f"Outbound HTTP allowed by {sg_id}")
            if _evaluate_sg_rules(egress_rules, protocol='tcp', port=443, cidr='0.0.0.0/0'):
                sg_https_ok = True
                logger.debug(f"Outbound HTTPS allowed by {sg_id}")

            # Check inbound rules (for SSH)
            ingress_rules = sg.get('IpPermissions', [])
            logger.debug(f"Ingress rules for {sg_id}: {ingress_rules}")
            if _evaluate_sg_rules(ingress_rules, protocol='tcp', port=22, cidr='0.0.0.0/0'): # Typically more specific CIDR, but checking general case
                sg_ssh_ok = True
                logger.debug(f"Inbound SSH allowed by {sg_id}")

            # Optimization: If all rules are found, no need to check other SGs attached
            if sg_http_ok and sg_https_ok and sg_ssh_ok:
                 logger.info(f"All required SG rules found within group {sg_id}. No need to check further SGs.")
                 break # Exit the loop over security groups

        results['status'] = 'Checked'
        results['details']['outbound_http'] = 'Allowed' if sg_http_ok else 'Denied/Missing'
        results['details']['outbound_https'] = 'Allowed' if sg_https_ok else 'Denied/Missing'
        results['details']['inbound_ssh'] = 'Allowed' if sg_ssh_ok else 'Denied/Missing'
        logger.info(f"SG Check Results: HTTP Out={sg_http_ok}, HTTPS Out={sg_https_ok}, SSH In={sg_ssh_ok}")

    except ClientError as e:
        logger.error(f"AWS ClientError checking Security Groups: {e}")
        results['status'] = 'Error'
        results['details']['error'] = str(e)
    except Exception as e:
        logger.error(f"Unexpected error checking Security Groups: {e}")
        results['status'] = 'Error'
        results['details']['error'] = str(e)

    logger.info("--- Finished Security Group Checks ---")
    return results

def _evaluate_sg_rules(rules, protocol, port, cidr):
    """Evaluates Security Group rules for specific traffic. Returns True if allowed."""
    logger = logging.getLogger('AwsCmlValidator')
    for rule in rules:
        ip_protocol = rule.get('IpProtocol') # e.g., 'tcp', 'udp', '-1' for all
        from_port = rule.get('FromPort')
        to_port = rule.get('ToPort')
        ip_ranges = rule.get('IpRanges', []) # List of dicts with 'CidrIp'

        # Check protocol (-1 matches all, including specified protocol)
        protocol_match = (ip_protocol == protocol or ip_protocol == '-1')
        if not protocol_match:
            continue

        # Check port (rule applies if port falls within FromPort and ToPort)
        # Note: If FromPort/ToPort are missing (e.g. for ICMP or all ports), this check might need adjustment.
        # Assuming TCP/UDP where ports are usually defined.
        port_match = False
        if from_port is None and to_port is None: # Rule covers all ports for the protocol
            port_match = True
        elif from_port is not None and to_port is not None:
             port_match = (from_port <= port <= to_port)
        
        if not port_match:
            continue

        # Check CIDR
        cidr_match = False
        for ip_range in ip_ranges:
            if ip_range.get('CidrIp') == cidr:
                cidr_match = True
                break
        
        if cidr_match: # Protocol, Port, and CIDR all match an allow rule
            logger.debug(f"Matching SG rule found: {rule}")
            return True # Traffic is allowed
            
    return False # No matching allow rule found

# --- Network ACL Checks ---

def find_nacl_for_subnet(ec2_client, subnet_id):
    """Finds the Network ACL associated with a given subnet ID."""
    logger = logging.getLogger('AwsCmlValidator')
    logger.info(f"--- Finding Network ACL for Subnet: {subnet_id} ---") 
    nacl_id = None
    nacl_details = None
    status = 'Not Found'

    if not subnet_id:
        logger.error("Subnet ID is required to find NACL.")
        return status, nacl_id, nacl_details

    try:
        # Find NACL explicitly associated with the subnet
        response = ec2_client.describe_network_acls(
            Filters=[
                {'Name': 'association.subnet-id', 'Values': [subnet_id]}
            ]
        )
        logger.debug(f"describe_network_acls response for explicit association: {response}")
        network_acls = response.get('NetworkAcls', [])
        
        if network_acls:
            nacl_details = network_acls[0] # Should only be one explicit association
            nacl_id = nacl_details['NetworkAclId']
            logger.info(f"Found explicit NACL {nacl_id} associated with subnet {subnet_id}.")
            status = 'Found (Explicit)'
        else:
            logger.info(f"No explicit NACL association found for subnet {subnet_id}. Checking VPC default NACL.")
            # If no explicit association, find the default NACL for the VPC
            # First, get the VPC ID from the subnet
            subnets_response = ec2_client.describe_subnets(SubnetIds=[subnet_id])
            if not subnets_response.get('Subnets'):
                logger.error(f"Could not describe subnet {subnet_id} to find VPC ID.")
                return 'Error (Subnet Describe Failed)', nacl_id, nacl_details
                
            vpc_id = subnets_response['Subnets'][0].get('VpcId')
            if not vpc_id:
                 logger.error(f"Could not determine VPC ID for subnet {subnet_id}.")
                 return 'Error (VPC ID Missing)', nacl_id, nacl_details
                 
            logger.info(f"Subnet {subnet_id} belongs to VPC {vpc_id}. Finding default NACL for VPC.")
            
            # Now find the default NACL for that VPC
            default_response = ec2_client.describe_network_acls(
                Filters=[
                    {'Name': 'vpc-id', 'Values': [vpc_id]},
                    {'Name': 'default', 'Values': ['true']}
                ]
            )
            logger.debug(f"describe_network_acls response for default NACL: {default_response}")
            default_nacls = default_response.get('NetworkAcls', [])
            
            if default_nacls:
                nacl_details = default_nacls[0]
                nacl_id = nacl_details['NetworkAclId']
                logger.info(f"Found default NACL {nacl_id} for VPC {vpc_id} (used by subnet {subnet_id}).")
                status = 'Found (Default)'
            else:
                logger.error(f"Could not find default NACL for VPC {vpc_id}.")
                status = 'Error (Default Not Found)'

    except ClientError as e:
        logger.error(f"AWS ClientError finding NACL for subnet {subnet_id}: {e}")
        status = f'Error ({e.response["Error"]["Code"]})'
    except Exception as e:
        logger.error(f"Unexpected error finding NACL for subnet {subnet_id}: {e}")
        status = 'Error (Unexpected)'

    logger.info("--- Finished Finding Network ACL --- ")
    return status, nacl_id, nacl_details

def check_nacl_rules(nacl_details):
    """Checks the rules of the provided NACL details for required traffic."""
    logger = logging.getLogger('AwsCmlValidator')
    results = {
        'status': 'Not Checked',
        'details': {}
    }
    if not nacl_details:
        logger.error("NACL details not provided. Cannot check rules.")
        results['status'] = 'Skipped (No Details)'
        return results

    nacl_id = nacl_details.get('NetworkAclId', 'N/A')
    rules = nacl_details.get('Entries', [])
    logger.info(f"--- Checking Rules for NACL: {nacl_id} ({len(rules)} rules) ---")
    
    http_ok = _evaluate_nacl_rules(rules, protocol=6, port=80, cidr='0.0.0.0/0', is_egress=True)
    https_ok = _evaluate_nacl_rules(rules, protocol=6, port=443, cidr='0.0.0.0/0', is_egress=True)
    ephem_ok = _evaluate_nacl_rules(rules, protocol=6, port=49152, cidr='0.0.0.0/0', is_egress=False) # Simplified check

    results['status'] = 'Checked'
    results['details']['nacl_id'] = nacl_id
    results['details']['outbound_http'] = 'Allowed' if http_ok else 'Denied'
    results['details']['outbound_https'] = 'Allowed' if https_ok else 'Denied'
    results['details']['inbound_ephemeral'] = 'Allowed' if ephem_ok else 'Denied'

    logger.info(f"NACL Rule Check Results ({nacl_id}): HTTP Out={http_ok}, HTTPS Out={https_ok}, Ephem In={ephem_ok}")
    logger.info("--- Finished Checking Network ACL Rules ---")
    return results

def _evaluate_nacl_rules(rules, protocol, port, cidr, is_egress):
    """Evaluates ordered NACL rules for specific traffic. Returns True if allowed, False if denied."""
    logger = logging.getLogger('AwsCmlValidator')
    logger.debug(f"Evaluating NACL rules: Protocol={protocol}, Port={port}, CIDR={cidr}, Egress={is_egress}")
    # Ensure rules are sorted by rule number
    sorted_rules = sorted([r for r in rules if r.get('RuleNumber') != 32767], key=lambda x: x['RuleNumber'])
    
    for rule in sorted_rules:
        rule_num = rule.get('RuleNumber')
        rule_egress = rule.get('Egress', False)
        rule_protocol = rule.get('Protocol') # String like '6' for TCP, '17' for UDP, '-1' for all
        rule_action = rule.get('RuleAction') # 'allow' or 'deny'
        rule_cidr = rule.get('CidrBlock')
        rule_port_range = rule.get('PortRange') # Dict with 'From', 'To'

        # 1. Check direction
        if rule_egress != is_egress:
            continue

        # 2. Check protocol
        # Protocol codes: '6' = TCP, '17' = UDP, '1' = ICMP, '-1' = ALL
        protocol_str = str(protocol)
        protocol_match = (rule_protocol == protocol_str or rule_protocol == '-1')
        if not protocol_match:
            continue

        # 3. Check Port (only if protocol requires ports, e.g., TCP/UDP)
        port_match = False
        if rule_protocol in ['6', '17']: # TCP or UDP
            if rule_port_range: # If port range is defined in the rule
                from_port = rule_port_range.get('From')
                to_port = rule_port_range.get('To')
                if from_port is not None and to_port is not None and from_port <= port <= to_port:
                    port_match = True
            else: # If no port range is specified, rule applies to all ports for the protocol
                port_match = True
        else: # For protocols like ICMP or '-1', port isn't applicable/checked in this way
             port_match = True 

        if not port_match:
            continue

        # 4. Check CIDR Block
        # Note: This is a simplification. Real NACL evaluation involves longest prefix match.
        # We are checking for an exact CIDR match or if the rule CIDR is '0.0.0.0/0'.
        # This covers the common case for allowing internet access.
        cidr_match = (rule_cidr == cidr or rule_cidr == '0.0.0.0/0') 
        # A more robust check would involve IP address and subnet mask calculations. 
        
        if not cidr_match:
           continue

        # If all checks pass, this rule matches the traffic.
        # Return based on the rule's action.
        logger.debug(f"Matching NACL rule found (#{rule_num}): {rule}")
        if rule_action == 'allow':
            logger.debug(f"Rule {rule_num} allows the traffic.")
            return True
        elif rule_action == 'deny':
            logger.debug(f"Rule {rule_num} denies the traffic.")
            return False
        else:
            logger.warning(f"Unknown rule action '{rule_action}' for rule {rule_num}")
            # Treat unknown action as deny for safety? Or log and continue?
            # Let's treat as deny for now.
            return False

    # If no explicit rule matched, the implicit deny applies
    logger.debug("No explicit NACL rule matched. Traffic denied by implicit deny.")
    return False

