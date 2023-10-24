"""
Usage:
-----
python register_cloudtrail_bucket.py --config /path/to/config --account ACCOUNT_ID --ctbucket BUCKET_NAME --ctregion REGION [--ctprefix PREFIX]

Description:
------------
Creates a cloudformation template to Integrate Uptycs with an AWS account.

Arguments:
----------
--config:     REQUIRED. The path to your authentication configuration file
              downloaded from the Uptycs console. E.g., /path/to/config.json.

--account:    REQUIRED. The Master AWS account ID, which should be 12 digits.
              E.g., 123456789012.

--ctbucket:   REQUIRED. The name of the CloudTrail bucket where logs are stored.
              E.g., my-cloudtrail-bucket.

--ctregion:   REQUIRED. The AWS region where the CloudTrail bucket is located.
              E.g., us-west-1.

--ctprefix:   OPTIONAL. The prefix for the CloudTrail logs in the bucket. If not
              provided, the script assumes no prefix. E.g., o-123456.

Example:
--------
python register_cloudtrail_bucket.py --config ./uptycs_config.json --account 123456789012 --ctbucket my-cloudtrail-bucket --ctregion us-west-1 --ctprefix logs/

"""

from dataclasses import dataclass
import argparse
import base64
import datetime
import hashlib
import hmac
import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional, Dict, Tuple, Union

import urllib3

http = urllib3.PoolManager()

LOGLEVEL = os.environ.get('LOGLEVEL', logging.INFO)
logger = logging.getLogger()
logger.setLevel(LOGLEVEL)


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


def gen_cloudtrail_api_url(domain: str, domain_suffix: str, customer_id: str) -> str:
    """
    Generates Uptycs API cloudTrailBuckets URL.

    Args:
        domain (str): The Uptycs Domain.
        domain_suffix (str): The Uptycs DomainSuffix.
        customer_id (str): The Uptycs CustomerID.

    Returns:
        str: Uptycs cloudTrailBuckets API URL).
    """
    uptycs_api_url = f"https://{domain}{domain_suffix}/public/api/customers/" \
                     f"{customer_id}/cloudTrailBuckets"
    return uptycs_api_url


@dataclass
class CloudTrailInfo:
    """
    Represents the essential CloudTrail bucket information.

    Attributes:
        bucket_name (str): The name of the CloudTrail bucket.
        account (str): AWS account where the bucket exists.
        bucket_region (str): Region where the CloudTrail bucket is located.
        prefix (str): The prefix for the CloudTrail logs in the bucket.
    """

    def __init__(self, bucket_name: str, account: str, bucket_region: str, prefix: str):
        """
        Initializes the CloudTrailInfo with the provided information.

        Args:
            bucket_name (str): The name of the CloudTrail bucket.
            account (str): AWS account where the bucket exists.
            bucket_region (str): Region where the CloudTrail bucket is located.
            prefix (str): The prefix for the CloudTrail logs in the bucket.
        """
        self.bucket_name = bucket_name
        self.account = account
        self.bucket_region = bucket_region
        self.prefix = prefix


def ct_bucket_reg(req_header: dict[str, str], ct_api_url: str,
                  ct_info: CloudTrailInfo) -> bool:
    """

    Args:
        req_header ():
        ct_api_url (): cloudTrailBuckets registration url
        ct_info (): CloudTrail log prefix

    Returns: bool True if cloudtrail setup is success or False

    """
    try:
        logger.info('Registering cloudtrail')
        req_payload = {
            "tenantId": ct_info.account,
            "bucketName": ct_info.bucket_name,
            "bucketRegion": ct_info.bucket_region,
            "bucketPrefix": ct_info.prefix
        }
        status, response = http_post(ct_api_url, req_header, req_payload)
        logger.info(
            "Got status %s and response %s registering trail", status, response)
        if status == 200:
            return True
        logger.info("Failed to setup Cloudtrail. Complete setup in the Uptycs Console")
        return False
    except Exception as error:  # pylint: disable=W0718
        logger.info("Exception %s setting up Cloudtrail", error)
        return False

def delete_cloudtrail_handler(cliargs):
    """
    Handles the deregistration of a CloudTrail bucket based on the provided arguments.

    Args:
        cliargs (Namespace): Parsed command-line arguments containing the configuration
                          details and other necessary parameters.

    Returns:
        None

    Raises:
        FileNotFoundError: If the specified config file doesn't exist.
        JSONDecodeError: If there's an error decoding the config file.
        Exception: Any other exceptions raised by the underlying functions.

    Note:
        This function assumes the existence of other functions like gen_api_headers,
        gen_cloudtrail_api_url, and ct_bucket_reg. Make sure they're defined and imported
        appropriately.
    """
    with open(cliargs.config, encoding='utf-8') as api_config_file:
        uptycs_api_params = json.load(api_config_file)

    domain = uptycs_api_params.get('domain')
    domain_suffix = uptycs_api_params.get('domainSuffix')
    customer_id = uptycs_api_params.get('customerId')
    key = uptycs_api_params.get('key')
    secret = uptycs_api_params.get('secret')
    req_header = gen_api_headers(key, secret)
    ct_api_url = gen_cloudtrail_api_url(domain, domain_suffix, customer_id)
    try:
        del_url = f"{ct_api_url}/{cliargs.account}/{cliargs.ctbucket}"
    except Exception as error:
        print(error)
    status, msg = http_delete(del_url, req_header)
    if status == 200:
        print(f'Deleted cloudtrail bucket {cliargs.ctbucket}')
    else:
        print(f'Failed to delete cloudtrail bucket {cliargs.ctbucket}')



def cloudtrail_bucket_reg_handler(cliargs: argparse.Namespace) -> None:
    """
    Handles the registration of a CloudTrail bucket based on the provided arguments.

    Args:
        cliargs (Namespace): Parsed command-line arguments containing the configuration
                          details and other necessary parameters.

    Returns:
        None

    Raises:
        FileNotFoundError: If the specified config file doesn't exist.
        JSONDecodeError: If there's an error decoding the config file.
        Exception: Any other exceptions raised by the underlying functions.

    Note:
        This function assumes the existence of other functions like gen_api_headers,
        gen_cloudtrail_api_url, and ct_bucket_reg. Make sure they're defined and imported
        appropriately.
    """
    with open(cliargs.config, encoding='utf-8') as api_config_file:
        uptycs_api_params = json.load(api_config_file)

    domain = uptycs_api_params.get('domain')
    domain_suffix = uptycs_api_params.get('domainSuffix')
    customer_id = uptycs_api_params.get('customerId')
    key = uptycs_api_params.get('key')
    secret = uptycs_api_params.get('secret')
    req_header = gen_api_headers(key, secret)
    ct_api_url = gen_cloudtrail_api_url(domain, domain_suffix, customer_id)
    ct_info = CloudTrailInfo(cliargs.ctbucket, cliargs.account, cliargs.ctregion, cliargs.ctprefix)
    cloudtrail_registered = \
        ct_bucket_reg(req_header, ct_api_url,
                      ct_info)
    if cloudtrail_registered:
        print(f'Successfully registered cloudtrail bucket {cliargs.ctbucket}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Creates a cloudformation template to Integrate Uptycs with this account'
    )

    required_args = parser.add_argument_group('required arguments')
    optional_args = parser.add_argument_group('optional arguments')

    required_args.add_argument('--config', required=True,
                               help='The path to your auth config file downloaded from Uptycs console')
    required_args.add_argument('--account', required=True,
                               help='The Master account ID (12 digits)')
    required_args.add_argument('--ctbucket', required=True,
                               help='The Name of the CloudTrail bucket')
    required_args.add_argument('--ctregion', required=True,
                               help='The Name of the CloudTrail bucket region')

    optional_args.add_argument('--ctprefix',
                               help='The Name of the CloudTrail log prefix',
                               default=None)
    optional_args.add_argument('--action',
                               help='Set Delete if you wish to delete the trail',
                               default='Create')
    # Parse the arguments
    args = parser.parse_args()

    if args.action == 'Delete':
        delete_cloudtrail_handler(args)
    else:
        cloudtrail_bucket_reg_handler(args)
