#!/usr/bin/env python3

# Documentation for boto3 calls:
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.authorize_security_group_egress
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.authorize_security_group_ingress

import argparse
import boto3
import dns.resolver
import logging
import settings


logger = logging.getLogger(__name__)


def resolve_domain_to_addresses(
    domain: str,
) -> list:
    return [answer.address for answer in dns.resolver.query(domain, 'A')]


def update_security_group(
    sg: str,
    domain: str,
    port: int,
    inbound: bool,
    outbound: bool,
    tcp: bool,
    udp: bool,
    verbose: bool,
):

    logger.info(f"sgroup:{sg} domain:{domain} port:{port} inbound:{inbound} outbound:{outbound} tcp:{tcp} udp:{udp}")

    client = boto3.client('ec2')

    # Select either the ingress our egress method based on the 'inbound' boolean
    authorize_security_group = client.authorize_security_group_ingress if inbound else client.authorize_security_group_egress

    for address in resolve_domain_to_addresses(domain):

        logger.info(f"address: {address}")

        ret = authorize_security_group(
            GroupId=sg,
            IpPermissions=[{
                'IpProtocol': 'tcp' if tcp else 'udp',
                'IpRanges': [{
                    'CidrIp': address + "/32",
                    'Description': domain,
                }],
                'FromPort': port,  # TODO: Verify: Do we want this?
                'ToPort': port,
            }]
        )

        logger.info(f"authorize_security_group: {ret}")

        if verbose:
            print(f"authorize_security_group for address {address}: {ret}")


if __name__ == '__main__':
    """ Nothing more than careful arg parsing herein """

    parser = argparse.ArgumentParser(
        description="Update an AWS EC2 Security Group",
        epilog="Assumption: 'port' is singular and does not reference a range of ports.",
    )
    parser.add_argument(
        'sg',
        help="Security Group in the form 'sg-' followed by a long hexidecimal number, e.g., sg-0123456789abcdef",
        type=str,
    )
    parser.add_argument(
        'domain',
        help="Domain (or subdomain) to allow.",
        type=str,
    )
    parser.add_argument(
        'port',
        help="TCP or UDP Port to open.",
        type=int,
    )

    in_or_out = parser.add_mutually_exclusive_group(required=True)
    in_or_out.add_argument(
        '--inbound',
        help="Update inbound rules.",
        action='store_true',
    )
    in_or_out.add_argument(
        '--outbound',
        help="Update outbound rules.",
        action='store_true',
    )

    tcp_or_udp = parser.add_mutually_exclusive_group(required=True)
    tcp_or_udp.add_argument(
        '--tcp',
        help="Apply rule to TCP.",
        action='store_true',
    )
    tcp_or_udp.add_argument(
        '--udp',
        help="Apply rule to UDP.",
        action='store_true',
    )

    parser.add_argument(
        '--verbose',
        help="Verbose output.",
        action='store_true',
    )

    args = parser.parse_args()
    logger.debug(f"args: {args}")

    update_security_group(
        args.sg,
        args.domain,
        args.port,
        args.inbound,
        args.outbound,
        args.tcp,
        args.udp,
        args.verbose,
    )

    exit(0)
