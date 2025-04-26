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

    try:
        response = ec2_client.describe_security_groups(GroupIds=security_group_ids)
        groups = response.get('SecurityGroups', [])
        sg_ssh_ok = sg_http_ok = sg_https_ok = False
        for sg in groups:
            for perm in sg.get('IpPermissions', []):
                from_port = perm.get('FromPort')
                to_port = perm.get('ToPort')
                ip_ranges = perm.get('IpRanges', [])
                # SSH (22)
                if from_port == 22 and to_port == 22:
                    sg_ssh_ok = any(r.get('CidrIp') == '0.0.0.0/0' for r in ip_ranges)
                # HTTP (80)
                if from_port == 80 and to_port == 80:
                    sg_http_ok = any(r.get('CidrIp') == '0.0.0.0/0' for r in ip_ranges)
                # HTTPS (443)
                if from_port == 443 and to_port == 443:
                    sg_https_ok = any(r.get('CidrIp') == '0.0.0.0/0' for r in ip_ranges)
        results['details'] = {
            'ssh_open': sg_ssh_ok,
            'http_open': sg_http_ok,
            'https_open': sg_https_ok,
            'message': 'Security group rule check results.'
        }
        if sg_http_ok and sg_https_ok and sg_ssh_ok:
            results['status'] = 'Passed'
        else:
            results['status'] = 'Failed'
    except ClientError as e:
        logger.error(f"Error describing security groups: {e}")
        results['status'] = 'Error'
        results['details']['error'] = str(e)
    except Exception as e:
        logger.error(f"Unexpected error during security group check: {e}")
        results['status'] = 'Error'
        results['details']['error'] = str(e)
    
    logger.info("--- Finished Security Group Checks ---")
    return results

# --- NACL Checks ---

def find_nacl_for_subnet(ec2_client, subnet_id):
    """Finds the NACL associated with a given subnet."""
    logger = logging.getLogger('AwsCmlValidator')
    logger.info(f"Finding NACL for subnet: {subnet_id}")
    try:
        nacls = ec2_client.describe_network_acls(Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}])
        nacl_list = nacls.get('NetworkAcls', [])
        if nacl_list:
            nacl_id = nacl_list[0]['NetworkAclId']
            logger.info(f"Found NACL: {nacl_id}")
            return nacl_id, nacl_list[0]
        else:
            logger.warning(f"No NACL found for subnet {subnet_id}")
            return None, None
    except ClientError as e:
        logger.error(f"Error finding NACL for subnet {subnet_id}: {e}")
        return None, None
    except Exception as e:
        logger.error(f"Unexpected error finding NACL: {e}")
        return None, None


def check_nacl_rules(nacl, port, protocol='tcp', cidr='0.0.0.0/0'):
    """Checks if the NACL allows traffic for the given port/protocol/cidr."""
    logger = logging.getLogger('AwsCmlValidator')
    logger.info(f"Checking NACL rules for port {port}/{protocol} and CIDR {cidr}")
    results = {'status': 'Not Checked', 'details': {}}
    if not nacl:
        logger.warning("No NACL provided for rule check.")
        results['status'] = 'Error (No NACL Provided)'
        results['details']['error'] = 'No NACL provided for rule check.'
        return results
    rules = nacl.get('Entries', [])
    for rule in sorted(rules, key=lambda r: r['RuleNumber']):
        rule_num = rule.get('RuleNumber')
        rule_action = rule.get('RuleAction')
        rule_protocol = rule.get('Protocol')
        rule_cidr = rule.get('CidrBlock')
        port_range = rule.get('PortRange', {})
        # Protocol match
        proto_match = (rule_protocol == '-1' or rule_protocol == protocol or protocol == 'tcp')
        # Port match
        if port_range:
            from_port = port_range.get('From')
            to_port = port_range.get('To')
            port_match = (from_port <= port <= to_port)
        else:
            port_match = True
        if not port_match or not proto_match:
            continue
        # CIDR Block
        cidr_match = (rule_cidr == cidr or rule_cidr == '0.0.0.0/0')
        if not cidr_match:
            continue
        # Rule Action
        if rule_action == 'allow':
            results['status'] = 'Passed'
            results['details'] = {'matched_rule': rule, 'message': 'Traffic allowed by NACL rule.'}
            return results
        elif rule_action == 'deny':
            results['status'] = 'Failed (Denied)'
            results['details'] = {'matched_rule': rule, 'message': 'Traffic denied by NACL rule.'}
            return results
    logger.debug("No explicit NACL rule matched. Traffic denied by implicit deny.")
    results['status'] = 'Failed (Implicit Deny)'
    results['details'] = {'message': 'No explicit NACL rule matched. Traffic denied by implicit deny.'}
    return results
