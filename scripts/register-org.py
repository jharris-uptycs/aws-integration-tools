#
# Uptycs AWS Organization Registration script
# The script will Register or delete an AWS organization if the required roles and cloudtrail have
# been created manually
#
# Usage: register-org.py --action xx --config xxx --rolename xxx --externalid xx --ctbucket xx
# --ctaccount xx --ctregion xx --masteraccount xxx
#
# Specify master account ID if not running inside Cloudshell in master or not using master account
# cli profile
#
import json
import boto3
import logging
import os
import argparse
import urllib3
import base64
import hashlib
import hmac
import datetime
import urllib.request
import urllib.error
import urllib.parse
import sys

http = urllib3.PoolManager()

LOGLEVEL = os.environ.get('LOGLEVEL', logging.INFO)
logger = logging.getLogger()
logger.setLevel(LOGLEVEL)



def get_uptycs_internal_id(url, req_header, account_id):
    # params = {"hideServices": "true", "hideSideQuery": "false", "minimalInfo": "true"}

    try:
        status, response = http_get(url, req_header)
        if status == 200:
            for item in response['items']:
                if item['orgId'] == get_org_id():
                    uptycs_org_id = response['items'][0]['id']
                    return uptycs_org_id
                else:
                    logger.info('Failed to find Uptycs Org ID')
                    return
        else:
            return
    except Exception as error:
        logger.info("Error getting uptycs internal id for org")
        return


def remove_illegal_characters(input_string):
    return input_string.replace('=', '').replace('+', '-').replace('/', '_')


def base64_object(input_object):
    input_bytes = json.dumps(input_object).encode('utf-8')
    base64_bytes = base64.b64encode(input_bytes)
    base64_string = base64_bytes.decode('utf-8')
    output = remove_illegal_characters(base64_string)
    return output

def create_auth_token(key, secret):
    date = int(datetime.datetime.now().timestamp())
    header = {'alg': 'HS256', 'typ': 'JWT'}
    payload = {'iss': key, 'iat': date, 'exp': date + 60}  # Token expires in 60 seconds
    unsigned_token = base64_object(header) + '.' + base64_object(payload)
    signature_hash = hmac.new(secret.encode('utf-8'), unsigned_token.encode('utf-8'),
                              hashlib.sha256)
    signature = base64.b64encode(signature_hash.digest()).decode('utf-8')
    return unsigned_token + '.' + remove_illegal_characters(signature)

def http_post(url, headers, payload):
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8'))

def http_delete(url, headers):
    req = urllib.request.Request(url, headers=headers, method='DELETE')
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, response.msg
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8'))

def http_get(url, headers, params=None):
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
    deregister_url = f"{url}/{account_id}"
    status, response = http_delete(deregister_url, header)
    if status == 200:
        return (response)

def get_org_id():
    org_client = boto3.client('organizations')
    resp = org_client.describe_organization()
    return resp['Organization']['Id']


def get_master_account():
    try:
        org_client = boto3.client('organizations')
        resp = org_client.describe_organization()
        return resp['Organization']['MasterAccountId']
    except Exception as error:
        logger.info('Error getting master account id {}'.format(error))

def check_stack_exists(stack_name):
    cf_client = boto3.client('cloudformation')
    try:
        cf_client.describe_stacks(StackName=stack_name)
        return True
    except cf_client.exceptions.ClientError as error:
        if 'does not exist' in str(error):
            return False
        else:
            raise error

def gen_api_headers(key, secret):
    token = create_auth_token(key, secret)
    req_header = {
        'Authorization': f"Bearer {token}",
        'date': datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
        'Content-type': "application/json"
    }
    return req_header

def gen_cloudaccounts_api_url(domain, domainSuffix, customer_id):
    uptycs_api_url = f"https://{domain}{domainSuffix}/public/api/customers/{customer_id}/cloud/aws/organizations"
    return uptycs_api_url


def gen_cloudtrail_api_url(domain, domainSuffix, customer_id):
    uptycs_api_url = f"https://{domain}{domainSuffix}/public/api/customers/{customer_id}/cloudTrailBuckets"
    return uptycs_api_url


def get_uptycs_internal_id(url, req_header, account_id):
    params = {"hideServices": "true", "hideSideQuery": "false", "minimalInfo": "true"}
    status, response = http_get(url, req_header, params)
    for item in response['items']:
        for acct in item['accounts']:
            if acct['tenantId'] == account_id:
                return acct['organizationId']


def account_registration_handler(args):
    with open(args.config) as api_config_file:
        uptycs_api_params = json.load(api_config_file)
    account_id = get_master_account() if args.masteraccount is None else args.masteraccount
    domain = uptycs_api_params.get('domain')
    domainSuffix = uptycs_api_params.get('domainSuffix')
    customer_id = uptycs_api_params.get('customerId')
    key = uptycs_api_params.get('key')
    secret = uptycs_api_params.get('secret')
    req_header = gen_api_headers(key, secret)
    uptycs_api_url = gen_cloudaccounts_api_url(domain, domainSuffix, customer_id)

    response_data = {}

    if args.action == "Register":
        try:
            req_payload = {
                    "deploymentType": "uptycs",
                    "accessConfig": {},
                    "organizationId": account_id,
                    "integrationName": args.rolename,
                    "awsExternalId": args.externalid,
                    "buckets": [
                        {
                            "bucketAccount": args.ctaccount,
                            "bucketPrefix": args.ctprefix,
                            "bucketName": args.ctbucket,
                            "bucketRegion": args.ctregion
                        }
                    ],
                    "kinesisStream": {}
                }

            status, response = http_post(uptycs_api_url, req_header, req_payload)
            if 200 == status:
                print(f'Successfully integrated AWS org master account {account_id}')
            else:
                print(f"Error - {status} Message {response['error']['message']}")
        except Exception as error:
            print(f"Error during create event {error}")
            # Handle delete event
    elif args.action == "Delete":
        try:
            account_id = get_master_account() if not args.masteraccount else args.masteraccount
            uptycs_account_id = get_uptycs_internal_id(uptycs_api_url, req_header,
                                                       account_id)
            if uptycs_account_id:
                resp = deregister_account(uptycs_api_url, req_header, uptycs_account_id)
                if resp == 'OK':
                    print(f'Successfully deleted AWS account {account_id}')
            else:
                print(f'No entry found for AWS account {account_id}')
        except Exception as error:
            print(f'Exception handling delete event {error}')



if __name__ == '__main__':
    """
    Main function to parse arguments and call Uptycs Web API to update External ID and IAM Role ARN 
    in AWS CSPM integration
    """
    parser = argparse.ArgumentParser(
        description='Creates a cloudformation template to Integrate Uptycs with this account'
    )
    parser.add_argument('--action', choices=['Register', 'Delete'], required=True,
                        help='REQUIRED: The action to perform: Register, or Delete')
    parser.add_argument('--config', required=True,
                        help='REQUIRED: The path to your auth config file downloaded from Uptycs console')
    parser.add_argument('--externalid', required=True,
                        help='The externalid applied to the trust relationship of the role',
                        default='UptycsIntegrationRole')
    parser.add_argument('--rolename', required=True,
                        help='REQUIRED: The name of the IAM role created.',
                        default='UptycsIntegrationRole')
    parser.add_argument('--ctaccount', required=True,
                        help='REQUIRED: The AccountId of the CloudTrail bucket')
    parser.add_argument('--ctbucket', required=True,
                        help='REQUIRED: The Name of the CloudTrail bucket')
    parser.add_argument('--ctregion', required=True,
                        help='REQUIRED: The Name of the CloudTrail bucket region')
    parser.add_argument('--ctprefix',
                        help='OPTIONAL: The Name of the CloudTrail log prefix')
    parser.add_argument('--masteraccount',
                        help='OPTIONAL: The Master account ID (12 digits)')

    # Parse the arguments
    args = parser.parse_args()

    action = args.action


    # Check if --arn argument is provided

    if action == 'Check':
        print(f"Checking for api credentials file {args.config}")
        try:
            with open(args.config) as api_config_file:
                data = json.load(api_config_file)
                # write_dict_to_ssm(ssmparam, data)
        except FileNotFoundError:
            print("File not found check the location of the apikey file: ", args.config)
            sys.exit(0)

    else:
        account_registration_handler(args)





