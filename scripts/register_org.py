"""
Script for Uptycs-AWS Organization Registration for Security Monitoring

This script is designed to assist in registering an AWS organization with the Uptycs platform
for security monitoring purposes. The integration is performed through the provided arguments
which specify details like action type (register, delete, check), authentication configurations,
external ID, role name, and optional parameters related to the CloudTrail bucket.

The primary functions include:
- Registering the AWS organization for monitoring on Uptycs.
- Deleting the AWS organization from Uptycs.
- Checking the registration status of the AWS organization on Uptycs.

The script takes in mandatory arguments related to action type, authentication configurations,
external ID, and role name. Additionally, it also accepts optional arguments related to the
CloudTrail bucket. If any one of the optional CloudTrail parameters is specified, all of them
must be specified.

Usage:
    python <script_name>.py --action <action_type> --config <config_path> --externalid <external_id>
    --rolename <role_name> [--ctaccount <ct_account>] [--ctbucket <ct_bucket>]
    [--ctregion <ct_region>] [--ctprefix <ct_prefix>] [--masteraccount <master_account>]

Parameters:
    action: Action to perform (choices: Register, Delete, Check)
    config: Path to the authentication configuration file from Uptycs
    externalid: External ID applied to the trust relationship of the role (default: UptycsIntegrationRole)
    rolename: Name of the IAM role to be created (default: UptycsIntegrationRole)
    ctaccount: (Optional) Account ID of the CloudTrail bucket
    ctbucket: (Optional) Name of the CloudTrail bucket
    ctregion: (Optional) Region of the CloudTrail bucket
    ctprefix: (Optional) Prefix for the CloudTrail logs
    masteraccount: (Optional) Master AWS account ID (12 digits)

Requirements:
    - argparse
    - sys (for handling exit scenarios)

Note:
    Ensure the script has appropriate permissions to perform the specified action
    (register, delete, check) on both AWS and Uptycs platforms.
"""

import argparse
import base64
import datetime
import hashlib
import hmac
import json
import logging
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Tuple, Dict, Union, Optional, Any

import boto3
import urllib3

http = urllib3.PoolManager()

LOGLEVEL = os.environ.get('LOGLEVEL', logging.INFO)
logger = logging.getLogger()
logger.setLevel(LOGLEVEL)


def get_uptycs_internal_id(url: str, req_header: Dict[str, str]) -> Optional[str]:
    """
    Get the Uptycs internal ID corresponding to the given account ID from the provided URL.

    Args:
        url (str): The endpoint URL to make the request.
        req_header (Dict[str, str]): The request headers used for the HTTP request.

    Returns:
        Optional[str]: Uptycs internal ID if found; otherwise, None.
    """
    try:
        status, response = http_get(url, req_header)

        if status != 200:
            logger.info("Unexpected HTTP status: %s. Unable to get Uptycs internal ID.", status)
            return None

        items = response.get('items', [])

        for item in items:
            if item.get('orgId') == get_org_id():
                return item.get('id')

        logger.info('Failed to find Uptycs Org ID')

    except Exception as error:  # pylint: disable=W0718
        logger.info("Error getting uptycs internal id for org: %s", error)
    return None


def remove_illegal_characters(input_string: str) -> str:
    """
    Remove illegal characters from a string.

    Args:
        input_string (str): The input string.

    Returns:
        str: The input string with illegal characters replaced.
    """
    return input_string.replace('=', '').replace('+', '-').replace('/', '_')


def base64_object(input_object: Dict) -> str:
    """
    Convert a dictionary object to a base64-encoded string.

    Args:
        input_object (dict): The input dictionary.

    Returns:
        str: The base64-encoded string.
    """
    input_bytes = json.dumps(input_object).encode('utf-8')
    base64_bytes = base64.b64encode(input_bytes)
    base64_string = base64_bytes.decode('utf-8')
    output = remove_illegal_characters(base64_string)
    return output


def create_auth_token(key: str, secret: str) -> str:
    """
    Create an authentication token.

    Args:
        key (str): The API key.
        secret (str): The API secret.

    Returns:
        str: The authentication token.
    """
    date = int(datetime.datetime.now().timestamp())
    header = {'alg': 'HS256', 'typ': 'JWT'}
    payload = {'iss': key, 'iat': date, 'exp': date + 180}  # Token expires in 180 seconds
    unsigned_token = base64_object(header) + '.' + base64_object(payload)
    signature_hash = hmac.new(secret.encode('utf-8'), unsigned_token.encode('utf-8'),
                              hashlib.sha256)
    signature = base64.b64encode(signature_hash.digest()).decode('utf-8')
    return unsigned_token + '.' + remove_illegal_characters(signature)


def gen_api_headers(key: str, secret: str) -> Dict[str, str]:
    """
    Generate API request headers with authentication.

    Args:
        key (str): The API key.
        secret (str): The API secret.

    Returns:
        dict: Request headers including authorization.
    """
    token = create_auth_token(key, secret)
    req_header = {
        'Authorization': f"Bearer {token}",
        'date': datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
        'Content-type': "application/json"
    }
    return req_header


def http_post(url: str, headers: Dict[str, str], payload: Dict) -> Tuple[int, Optional[Dict]]:
    """
    Perform an HTTP POST request with JSON payload.

    Args:
        url (str): The URL to make the POST request.
        headers (Dict[str, str]): The request headers.
        payload (Dict): The JSON payload.

    Returns:
        Tuple[int, Optional[Dict]]: A tuple containing the HTTP status code and the JSON response
        (or None if an error occurs).
    """
    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers=headers)
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as error:
        logger.info("Got an exception with HTTP POST: %s", error)

        error_response = json.loads(error.read().decode('utf-8'))

        # Extract the error detail
        error_detail = error_response.get("error", {}).get("message", {}).get("detail",
                                                                              "No detail provided.")

        # Print the error detail
        print("Error Detail:", error_detail)
        return error.code, json.loads(error.read().decode('utf-8'))
    except Exception as error:  # pylint: disable=W0718
        logger.info("Got a general exception with HTTP request: %s", error)
        return 500, None  # Return a default status code and None for general exceptions


def http_delete(url: str, headers: Dict[str, str]) -> Tuple[int, Optional[str]]:
    """
    Perform an HTTP DELETE request.

    Args:
        url (str): The URL to make the DELETE request.
        headers (dict): The request headers.

    Returns: tuple: A tuple containing the HTTP status code and the response message (or None if
    an error occurs).
    """
    req = urllib.request.Request(url, headers=headers, method='DELETE')
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, response.msg
    except urllib.error.HTTPError as error:  # pylint: disable=W0718
        logger.info("Got an exception with HTTP POST: %s", error)

        error_response = json.loads(error.read().decode('utf-8'))

        # Extract the error detail
        error_detail = error_response.get("error", {}).get("message", {}).get("detail",
                                                                              "No detail provided.")

        # Print the error detail
        print("Error Detail:", error_detail)
        return error.code, error_detail


def http_get(
        url: str,
        headers: Dict[str, str],
        params: Optional[Dict] = None
) -> Tuple[int, Union[Dict, str]]:
    """
    Perform an HTTP GET request.

    Args:
        url (str): The URL to make the GET request.
        headers (dict): The request headers.
        params (dict, optional): Query parameters (default is None).

    Returns:
        tuple: A tuple containing the HTTP status code and the JSON response (or None if an
        error occurs).
    """
    if params:
        query_string = urllib.parse.urlencode(params)
        url = f"{url}?{query_string}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            content_type = response.getheader('Content-Type')
            status = response.status
            raw_data = response.read()

            if content_type == 'application/zip':
                logger.info('Ignoring zip content')
                # Now, you can further process the ZIP file or return a success status
                return status, content_type
            # Assume it's JSON and decode it as UTF-8
            data = json.loads(raw_data.decode('utf-8'))
            return status, data
    except urllib.error.HTTPError as error:
        logger.info("Got exception with http get %s", error)
        return error.code, json.loads(error.read().decode('utf-8'))


def deregister_account(
        url: str, header: Dict[str, str], account_id: str) -> Optional[Dict[str, Any]]:
    """
    Deregister the account using the provided URL and headers.

    Args:
        url (str): The base endpoint URL for deregistration.
        header (Dict[str, str]): The request headers used for the HTTP request.
        account_id (str): The account ID to deregister.

    Returns:
        Optional[Dict[str, Any]]: The response from the deregistration if successful, otherwise None
    """
    deregister_url = f"{url}/{account_id}"
    status, response = http_delete(deregister_url, header)
    if status == 200:
        return response
    return None


def get_org_id() -> str:
    """
    Fetch the organization ID using the boto3 organizations client.

    Returns:
        str: The organization ID.
    """
    org_client = boto3.client('organizations')
    resp = org_client.describe_organization()
    return resp['Organization']['Id']


def get_master_account() -> Optional[str]:
    """
    Fetch the master account ID using the boto3 organizations client.

    Returns:
        Optional[str]: The master account ID if found, otherwise None.
    """
    try:
        org_client = boto3.client('organizations')
        resp = org_client.describe_organization()
        return resp['Organization']['MasterAccountId']
    except Exception as error:  # pylint: disable=W0718
        logger.info('Error getting master account id %s', error)
        return None


def gen_cloudaccounts_api_url(domain: str, domain_suffix: str, customer_id: str) -> str:
    """
    Generate the Uptycs API URL for cloud accounts.

    Args:
        domain (str): The domain name.
        domain_suffix (str): The domain suffix.
        customer_id (str): The customer ID.

    Returns:
        str: The generated Uptycs API URL for cloud accounts.
    """
    uptycs_api_url = \
        f"https://{domain}{domain_suffix}/public/api/customers/{customer_id}" \
        f"/cloud/aws/organizations"
    return uptycs_api_url


def get_org_data(url: str, req_header: Dict[str, str]) -> Dict[str, Any]:
    """
    Fetch organization data from the provided URL using the given request headers.

    Args:
        url (str): The endpoint URL to make the request.
        req_header (Dict[str, str]): The request headers used for the HTTP request.

    Returns:
        Dict[str, Any]: The response from the HTTP request.
    """
    _, response = http_get(url, req_header)
    return response


@dataclass
class UptycsAPICreds:
    """
    Represents the Uptycs api credentials.

    Attributes:
        domain_suffix (str): Uptycs API domain_suffix.
        customer_id (str): Uptycs API customer_id.
        key (str): Uptycs API key.
        secret (str): Uptycs API secret
    """

    def __init__(self, api_keys_file: str):
        """
        Initializes the CloudTrailInfo with the provided information.

        Args:
            api_keys_file (str): Uptycs API parameter file
        """
        with open(api_keys_file, encoding='utf-8') as api_config_file:
            uptycs_api_params = json.load(api_config_file)
        self.domain = uptycs_api_params.get('domain')
        self.domain_suffix = uptycs_api_params.get('domainSuffix')
        self.customer_id = uptycs_api_params.get('customerId')
        self.key = uptycs_api_params.get('key')
        self.secret = uptycs_api_params.get('secret')


def org_registration_handler(cli_args: argparse.Namespace):
    """
    Initial lambda handler
    Args:
        cli_args: Uptycs API parameter file
    """

    api_credentials = UptycsAPICreds(cli_args.config)
    req_header = gen_api_headers(api_credentials.key, api_credentials.secret)
    cloudaccounts_api_url = gen_cloudaccounts_api_url(api_credentials.domain,
                                                      api_credentials.domain_suffix,
                                                      api_credentials.customer_id)

    try:
        if cli_args.action == "Register":
            req_payload = {
                "deploymentType": "uptycs",
                "accessConfig": {},
                "buckets": [],
                "organizationId": cli_args.masteraccount,
                "integrationName": cli_args.rolename,
                "awsExternalId": cli_args.externalid,
                "kinesisStream": {}
            }

            if cli_args.ctregion and cli_args.ctaccount and cli_args.ctbucket:
                req_payload["accessConfig"] = [{
                    "bucketAccount": cli_args.ctaccount,
                    "bucketPrefix": cli_args.ctprefix,
                    "bucketName": cli_args.ctbucket,
                    "bucketRegion": cli_args.ctregion
                }]

            status, response = http_post(cloudaccounts_api_url, req_header, req_payload)
            if 200 == status:
                print(f'Successfully integrated AWS org master account {cli_args.masteraccount}')
            else:
                print(
                    f"Error - {status} Message "
                    f"{response.get('error', {}).get('message', 'Unknown error')}")

        elif cli_args.action == "Delete":
            account_id = cli_args.masteraccount
            uptycs_account_id = get_uptycs_internal_id(cloudaccounts_api_url, req_header)
            if uptycs_account_id:
                resp = deregister_account(cloudaccounts_api_url, req_header, uptycs_account_id)
                if resp == 'OK':
                    print(f'Successfully deleted AWS account {account_id}')
                else:
                    print(f"Failed to delete AWS account {account_id}")
            else:
                print(f'No entry found for AWS account {account_id}')

        elif cli_args.action == "Check":
            account_id = cli_args.masteraccount
            uptycs_account_id = get_uptycs_internal_id(cloudaccounts_api_url, req_header)
            if uptycs_account_id:
                print(
                    f'Retrieved Uptycs internal account id '
                    f'{uptycs_account_id} for AWS {account_id}')
            else:
                print(f'No entry found for AWS account {account_id}')

            org_info = get_org_data(cloudaccounts_api_url, req_header)
            print(json.dumps(org_info, indent=2))

    except Exception as error:
        print(f"Exception handling {cli_args.action} event: {error}")


if __name__ == '__main__':
    """
    Main function 
    """
    parser = argparse.ArgumentParser(
        description='Creates a cloudformation template to Integrate Uptycs with this account'
    )

    required_args = parser.add_argument_group('required arguments')
    optional_args = parser.add_argument_group('optional arguments')


    required_args.add_argument('--action', choices=['Register', 'Delete', 'Check'], required=True,
                               help='The action to perform: Register, or Delete')
    required_args.add_argument('--config', required=True,
                               help='The path to your auth config file downloaded from Uptycs '
                                    'console')
    required_args.add_argument('--externalid', required=True,
                               help='The externalid applied to the trust relationship of the role',
                               default='UptycsIntegrationRole')
    required_args.add_argument('--rolename', required=True,
                               help='The name of the IAM role created.',
                               default='UptycsIntegrationRole')

    optional_args.add_argument('--ctaccount',
                               help='The AccountId of the CloudTrail bucket')
    optional_args.add_argument('--ctbucket',
                               help='The Name of the CloudTrail bucket')
    optional_args.add_argument('--ctregion',
                               help='The Name of the CloudTrail bucket region')
    optional_args.add_argument('--ctprefix',
                               help='The Name of the CloudTrail log prefix')
    optional_args.add_argument('--masteraccount',
                               help='The Master account ID (12 digits)')

    # Parse the arguments first
    args = parser.parse_args()

    # List containing optional arguments' values
    optional_params = [args.ctaccount, args.ctbucket, args.ctregion, args.ctprefix,
                       args.masteraccount]

    specified_params = [param for param in optional_params if param is not None]

    if 0 < len(specified_params) < len(optional_params):
        print("Error: If one optional CloudTrail parameter is specified, all must be specified.")
        sys.exit(1)

    action = args.action

    # Check if --arn argument is provided

    org_registration_handler(args)
