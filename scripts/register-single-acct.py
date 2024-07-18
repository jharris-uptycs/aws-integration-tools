"""
This script integrates AWS accounts with Uptycs by creating CloudFormation templates,
registering AWS accounts, and setting up CloudTrail logging.

Usage:
    python script.py --action <Action> --config <ConfigPath> --rolename <RoleName>
                     --ctbucket <CloudTrailBucket> --ctregion <CloudTrailRegion>
                     --accountid <AccountId> --externalid <ExternalId> [--ctprefix <CloudTrailPrefix>]

Arguments:
    --action          REQUIRED: The action to perform: 'Check', 'Create', or 'Delete'.
    --config          REQUIRED: Path to the auth config file downloaded from the Uptycs console.
    --rolename        REQUIRED: Name of the IAM role to be created or checked (Not the arn).
    --ctbucket        REQUIRED (for Create action): Name of the CloudTrail bucket.
    --ctregion        REQUIRED (for Create action): Region of the CloudTrail bucket.
    --accountid       REQUIRED: AWS account ID (12 digits).
    --externalid      REQUIRED: External ID for the IAM role trust relationship.
    --ctprefix        OPTIONAL: Prefix applied to CloudTrail logs (default is an empty string).

Example:
    python script.py --action Create --config /path/to/config.json --rolename MyIAMRole
                     --ctbucket my-cloudtrail-bucket --ctregion us-west-2
                     --accountid 123456789012 --externalid my-external-id --ctprefix my-prefix

Actions:
    Check     - Check if the IAM role and CloudTrail configuration exist.
    Create    - Register the AWS account and set up CloudTrail logging.
    Delete    - Deregister the AWS account from Uptycs.

Notes:
    - Ensure that AWS CLI is configured and you have necessary permissions.
    - The 'config' file should contain API parameters in JSON format with keys:
      'domain', 'domainSuffix', 'customerId', 'key', and 'secret'.
"""

import argparse
import json
import sys
import boto3
import base64
import datetime
import hmac
import hashlib
import urllib.request
import urllib.error
import urllib.parse

def gen_api_headers(key, secret):
    """
    Generates the authorization headers for the API requests.

    Args:
        key (str): API key.
        secret (str): API secret.

    Returns:
        dict: Headers for the API request.
    """
    token = create_auth_token(key, secret)
    req_header = {
        'Authorization': f"Bearer {token}",
        'date': datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
        'Content-type': "application/json"
    }
    return req_header

def gen_url(domain, domain_suffix, customer_id):
    """
        Generates the URL for cloud account setup and externalID generation.

        Args:
            domain (str): API domain.
            domain_suffix (str): Domain suffix.
            customer_id (str): Customer ID.

        Returns:
            str: Full URL for the cloud accounts API.
        """
    return f"https://{domain}{domain_suffix}/public/api/customers/{customer_id}/unifiedCloudIntegration/aws/integrations"

def gen_cloudaccounts_api_url(domain, domain_suffix, customer_id):
    """
    Generates the URL for the cloud accounts API endpoint.

    Args:
        domain (str): API domain.
        domain_suffix (str): Domain suffix.
        customer_id (str): Customer ID.

    Returns:
        str: Full URL for the cloud accounts API.
    """
    return f"https://{domain}{domain_suffix}/public/api/customers/{customer_id}/cloudAccounts"

def gen_cloudtrail_api_url(domain, domain_suffix, customer_id):
    """
    Generates the URL for the CloudTrail API endpoint.

    Args:
        domain (str): API domain.
        domain_suffix (str): Domain suffix.
        customer_id (str): Customer ID.

    Returns:
        str: Full URL for the CloudTrail API.
    """
    return f"https://{domain}{domain_suffix}/public/api/customers/{customer_id}/cloudTrailBuckets"

def get_uptycs_internal_id(url, req_header, account_id):
    """
    Retrieves the internal Uptycs ID for a given account.

    Args:
        url (str): API URL.
        req_header (dict): Request headers.
        account_id (str): Account ID.

    Returns:
        str: Internal Uptycs ID.
    """
    params = {"hideServices": "true", "hideSideQuery": "false", "minimalInfo": "true"}
    status, response = http_get(url, req_header, params)
    for item in response['items']:
        if item['tenantId'] == account_id:
            return item['id']
    return None

def account_cloudtrail_handler(args):
    """
    Handles the creation of CloudTrail bucket in Uptycs.

    Args:
        args (argparse.Namespace): Command line arguments.
    """
    with open(args.config) as api_config_file:
        uptycs_api_params = json.load(api_config_file)
    domain = uptycs_api_params.get('domain')
    domain_suffix = uptycs_api_params.get('domainSuffix')
    customer_id = uptycs_api_params.get('customerId')
    key = uptycs_api_params.get('key')
    secret = uptycs_api_params.get('secret')
    req_header = gen_api_headers(key, secret)
    uptycs_api_url = gen_cloudtrail_api_url(domain, domain_suffix, customer_id)
    try:
        req_payload = {
            "tenantId": args.accountid,
            "bucketName": args.ctbucket,
            "bucketRegion": args.ctregion,
            "bucketPrefix": args.ctprefix
        }
        status, response = http_post(uptycs_api_url, req_header, req_payload)
        if status == 200:
            print(f"Successfully added CloudTrail for account {args.accountid}")
            return status, response
        print('Failed to add CloudTrail')
        return status, response['error']['message']['detail']
    except Exception as error:
        response = f"Error during create event {error}"
        return status, response

def account_registration_handler(args):
    """
    Handles the registration, deletion, and update of an AWS account in Uptycs.

    Args:
        args (argparse.Namespace): Command line arguments.
    """
    with open(args.config) as api_config_file:
        uptycs_api_params = json.load(api_config_file)
    account_id = args.accountid
    domain = uptycs_api_params.get('domain')
    domain_suffix = uptycs_api_params.get('domainSuffix')
    customer_id = uptycs_api_params.get('customerId')
    key = uptycs_api_params.get('key')
    secret = uptycs_api_params.get('secret')
    role_arn = f"arn:aws:iam::{account_id}:role/{args.rolename}"
    req_header = gen_api_headers(key, secret)
    uptycs_api_url = gen_cloudaccounts_api_url(domain, domain_suffix, customer_id)
    setup_url = gen_url(domain, domain_suffix, customer_id)

    if args.action == "Create":
    # Perform an initial setup which will return an optional ExternalId that can be used.
    # This script assumes that
        try:
            put_req_payload = {
                "tenantId": account_id,
                "tenantName": account_id,
                "isOrgIntegration": "false",
                "integrationType": "CLOUD_FORMATION"
            }
            status, response = http_put(setup_url, req_header, put_req_payload)

            post_req_payload = {
                "tenantId": account_id,
                "tenantName": account_id,
                "connectorType": "aws",
                "cloudformationTemplate": "https://uptycs-integration.s3.amazonaws.com/aws/cf-templates/uptycs_integration-130-020.json",
                "accessConfig": {
                    "role_arn": role_arn,
                    "external_id": args.externalid
                }
            }
            status, response = http_post(uptycs_api_url, req_header, post_req_payload)
            if status == 200:
                print(f"Successfully integrated AWS account {account_id}")
                return status, response
            elif status == 400:
                print(f"Failed with message {response['error']['message']['detail']}")
                sys.exit(1)
        except Exception as error:
            response = f"Error during create event {error}"
            return status, response

    elif args.action == "Delete":
        try:
            uptycs_account_id = get_uptycs_internal_id(uptycs_api_url, req_header, account_id)
            if uptycs_account_id:
                resp = deregister_account(uptycs_api_url, req_header, uptycs_account_id)
                if resp == 'OK':
                    print(f'Successfully deleted AWS account {account_id}')
                else:
                    print(f'Failed to delete AWS account {account_id}')
            else:
                print(f"Account {account_id} is not registered")
        except Exception as error:
            print(f'Exception {error} deleting AWS account')

def get_account_id():
    """
    Retrieves the AWS account ID of the caller.

    Returns:
        str: AWS account ID.
    """
    sts_client = boto3.client('sts')
    response = sts_client.get_caller_identity()
    return response['Account']

def check_for_cloudtrail():
    """
    Checks if there is a CloudTrail configuration in the AWS account.

    Returns:
        str: CloudTrail bucket name if exists, otherwise None.
    """
    session = boto3.Session()
    cloudtrail_client = session.client('cloudtrail')
    response = cloudtrail_client.describe_trails()

    if 'trailList' in response:
        trail = response['trailList'][0]
        return trail['S3BucketName']
    return None

def check_for_existing_role(role_name):
    """
    Checks if a specified IAM role exists.

    Args:
        role_name (str): Name of the IAM role.

    Returns:
        bool: True if role exists, False otherwise.
    """
    iam_client = boto3.client('iam')
    try:
        iam_client.get_role(RoleName=role_name)
        return True
    except iam_client.exceptions.NoSuchEntityException:
        return False

def get_external_id_from_trust_relationship(role_name):
    """
    Retrieves the external ID from the trust relationship of a specified IAM role.

    Args:
        role_name (str): Name of the IAM role.

    Returns:
        str: External ID if found, otherwise None.
    """
    iam_client = boto3.client('iam')
    try:
        response = iam_client.get_role(RoleName=role_name)
        role = response['Role']
        assume_role_policy = role['AssumeRolePolicyDocument']
        if 'Statement' in assume_role_policy:
            for statement in assume_role_policy['Statement']:
                if 'Condition' in statement and 'StringEquals' in statement['Condition']:
                    conditions = statement['Condition']['StringEquals']
                    if 'sts:ExternalId' in conditions:
                        return conditions['sts:ExternalId']
    except iam_client.exceptions.NoSuchEntityException:
        pass
    return None

def remove_illegal_characters(input_string):
    """
    Removes illegal characters from a string for URL encoding.

    Args:
        input_string (str): Input string.

    Returns:
        str: Cleaned string.
    """
    return input_string.replace('=', '').replace('+', '-').replace('/', '_')

def base64_object(input_object):
    """
    Encodes a JSON object to a base64 string.

    Args:
        input_object (dict): Input JSON object.

    Returns:
        str: Base64 encoded string.
    """
    input_bytes = json.dumps(input_object).encode('utf-8')
    base64_bytes = base64.b64encode(input_bytes)
    base64_string = base64_bytes.decode('utf-8')
    return remove_illegal_characters(base64_string)

def create_auth_token(key, secret):
    """
    Creates an authentication token.

    Args:
        key (str): API key.
        secret (str): API secret.

    Returns:
        str: Authentication token.
    """
    date = int(datetime.datetime.now().timestamp())
    header = {'alg': 'HS256', 'typ': 'JWT'}
    payload = {'iss': key, 'iat': date, 'exp': date + 60}
    unsigned_token = base64_object(header) + '.' + base64_object(payload)
    signature_hash = hmac.new(secret.encode('utf-8'), unsigned_token.encode('utf-8'), hashlib.sha256)
    signature = base64.b64encode(signature_hash.digest()).decode('utf-8')
    return unsigned_token + '.' + remove_illegal_characters(signature)

def http_put(url, headers, payload):
    """
    Sends an HTTP PUT request to the specified URL with the given headers and payload.

    Args:
        url (str): The URL to which the PUT request is sent.
        headers (dict): The headers to include in the PUT request.
        payload (dict): The payload to send in the PUT request.

    Returns:
        tuple: A tuple containing the response status code and the JSON-decoded response data.
               If an HTTPError occurs, the error code and error message are returned.
    """
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers=headers, method='PUT')
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8'))


def http_post(url, headers, payload):
    """
    Sends an HTTP POST request.

    Args:
        url (str): URL for the request.
        headers (dict): Headers for the request.
        payload (dict): Payload for the request.

    Returns:
        tuple: Status code and response JSON.
    """
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8'))

def http_delete(url, headers):
    """
    Sends an HTTP DELETE request.

    Args:
        url (str): URL for the request.
        headers (dict): Headers for the request.

    Returns:
        tuple: Status code and response message.
    """
    req = urllib.request.Request(url, headers=headers, method='DELETE')
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, response.msg
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8'))

def http_get(url, headers, params=None):
    """
    Sends an HTTP GET request.

    Args:
        url (str): URL for the request.
        headers (dict): Headers for the request.
        params (dict, optional): Query parameters for the request.

    Returns:
        tuple: Status code and response JSON.
    """
    if params:
        query_string = urllib.parse.urlencode(params)
        url = f"{url}?{query_string}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8'))

def deregister_account(url, header, account_id):
    """
    Deregisters an account from Uptycs.

    Args:
        url (str): URL for the request.
        header (dict): Headers for the request.
        account_id (str): Account ID.

    Returns:
        str: Response message.
    """
    deregister_url = f"{url}/{account_id}"
    status, response = http_delete(deregister_url, header)
    if status == 200:
        return response
    return None

def main():
    """
    Main function to parse arguments and call Uptycs Web API to update External ID and IAM Role ARN in AWS CSPM integration.
    """
    parser = argparse.ArgumentParser(
        description='Creates a cloudformation template to Integrate Uptycs with this account'
    )
    parser.add_argument('--action', choices=['Check', 'Create', 'Delete'], required=True,
                        help='The action to perform: Check, Create, or Delete')
    parser.add_argument('--config', required=True,
                        help='REQUIRED: The path to your auth config file downloaded from Uptycs console')
    parser.add_argument('--rolename', required=True,
                        help='The Name of the IAM role that you will create')
    parser.add_argument('--ctbucket', required=True,
                        help='OPTIONAL: The Name of the CloudTrail bucket')
    parser.add_argument('--ctregion', required=True,
                        help='OPTIONAL: The Name of the CloudTrail bucket region')
    parser.add_argument('--accountid', required=True,
                        help='OPTIONAL: The Master account ID (12 digits)')
    parser.add_argument('--externalid', required=True,
                        help='OPTIONAL: The Master account ID (12 digits)')
    parser.add_argument('--ctprefix',
                        help='OPTIONAL: The prefix applied to the cloudtrail logs (if any)',
                        default='')

    args = parser.parse_args()

    if args.action == 'Check':
        print(f"Checking if role {args.rolename} already exists")
        role_exists = check_for_existing_role(args.rolename)
        if role_exists:
            external_id = get_external_id_from_trust_relationship(args.rolename)
            print(f"Found an existing role with name {args.rolename} and externalId {external_id}")
        else:
            print(f"Role {args.rolename} does not currently exist")

        print(f"Checking if a suitable CloudTrail configuration exists.")
        bucket = check_for_cloudtrail()
        if bucket:
            print(f"Found a valid CloudTrail logging to a bucket {bucket}")
        else:
            print(f"No valid CloudTrail exists")
        print(f"Checking for API credentials file {args.config}")
        try:
            with open(args.config) as api_config_file:
                data = json.load(api_config_file)
        except FileNotFoundError:
            print("File not found. Check the location of the apikey file: ", args.config)
            sys.exit(0)

    elif args.action in ('Create', 'Delete'):
        account_registration_handler(args)
        if args.action == 'Create':
            account_cloudtrail_handler(args)

if __name__ == '__main__':
    main()
