import logging
from botocore.exceptions import ClientError

def get_nat_gateways_for_subnet(ec2_client, subnet_id):
    """
    Returns a list of NAT Gateway IDs associated with the given subnet.
    """
    try:
        response = ec2_client.describe_nat_gateways(
            Filters=[{'Name': 'subnet-id', 'Values': [subnet_id]}]
        )
        nat_gateways = response.get('NatGateways', [])
        return [gw['NatGatewayId'] for gw in nat_gateways]
    except Exception as e:
        logging.error(f"Error fetching NAT gateways for subnet {subnet_id}: {e}")
        return []

def check_nat_gateway_health(ec2_client, nat_gateway_id):
    """
    Checks the health/status of a NAT Gateway.
    Returns a dict with state and public IP info.
    """
    try:
        response = ec2_client.describe_nat_gateways(
            NatGatewayIds=[nat_gateway_id]
        )
        if not response.get('NatGateways'):
            return {'state': 'NotFound'}
        gw = response['NatGateways'][0]
        state = gw.get('State', 'Unknown')
        public_ips = []
        for addr in gw.get('NatGatewayAddresses', []):
            if addr.get('PublicIp'):
                public_ips.append(addr['PublicIp'])
        return {
            'state': state,
            'public_ips': public_ips,
            'subnet_id': gw.get('SubnetId'),
            'vpc_id': gw.get('VpcId')
        }
    except Exception as e:
        logging.error(f"Error checking NAT Gateway {nat_gateway_id}: {e}")
        return {'state': 'Error', 'error': str(e)}
