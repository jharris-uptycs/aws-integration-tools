#
# Creates a CloudTrail to a new bucket in an account
# If no bucket exists the bucket will be created.
# If the bucket exists a suitable bucket policy is attached.
#
# usage: create-org-trail --action xxxx --ctbucket xxxx --trailname xxxx
#

import boto3
from botocore.exceptions import ClientError
import json
import logging
import os
import argparse

LOGLEVEL = os.environ.get('LOGLEVEL', logging.INFO)
logger = logging.getLogger()
logger.setLevel(LOGLEVEL)

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

def get_region():
    try:
        session = boto3.Session()
        return(session.region_name)
    except Exception as error:
        print(f'Error getting region {error}')

def create_trail(trail_name, bucket_name, is_organization = False):
    try:
        # Create a CloudTrail client
        cloudtrail_client = boto3.client('cloudtrail')

        # Create the trail
        response = cloudtrail_client.create_trail(
            Name=trail_name,
            S3BucketName=bucket_name,
            IsOrganizationTrail=is_organization,  # Enable organization-wide trail
            EnableLogFileValidation=True  # Enable log file validation
        )

        print(f"Trail '{trail_name}' created successfully!")

        return response['TrailARN']

    except ClientError as e:
        if e.response['Error']['Code'] == 'TrailAlreadyExistsException':
            print(f"Trail '{trail_name}' already exists.")
        elif e.response['Error']['Code'] == 'S3BucketDoesNotExistException':
            print(f"S3 bucket '{bucket_name}' does not exist.")
        else:
            print("An error occurred:", e)

        return None


def delete_trail(trail_name):
    try:
        # Create a CloudTrail client
        cloudtrail_client = boto3.client('cloudtrail')

        # Delete the trail
        cloudtrail_client.delete_trail(Name=trail_name)

        print(f"Trail '{trail_name}' deleted successfully!")

    except ClientError as e:
        if e.response['Error']['Code'] == 'TrailNotFoundException':
            print(f"Trail '{trail_name}' not found.")
        else:
            print("An error occurred:", e)

def create_s3_bucket_with_policy(bucket_name, bucket_policy, region):
    try:
        # Create an S3 client
        s3_client = boto3.client('s3', region_name=region)

        # Check if the bucket already exists
        bucket_exists = False
        response = s3_client.list_buckets()
        for bucket in response['Buckets']:
            if bucket['Name'] == bucket_name:
                bucket_exists = True
                break

        if not bucket_exists:
            # Bucket does not exist, create it with the specified region as location constraint
            if region == 'us-east-1':
                s3_client.create_bucket(Bucket=bucket_name)
            else:
                s3_client.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={'LocationConstraint': region}
                )
            print(f"S3 bucket '{bucket_name}' created in region '{region}'.")

        # Set the bucket policy if the bucket was created or already exists
        bucket_policy = bucket_policy
        s3_client.put_bucket_policy(Bucket=bucket_name, Policy=bucket_policy)
        print(f"S3 bucket '{bucket_name}' policy updated:")

    except Exception as error:
        print(f"An error occurred while creating/updating the bucket: {str(error)}")


def empty_and_delete_bucket(bucket_name):
    try:
        # Create a Boto3 S3 client
        s3_client = boto3.client('s3')

        # List all objects in the bucket
        response = s3_client.list_objects_v2(Bucket=bucket_name)

        # Check if the bucket has any objects
        if 'Contents' in response:
            objects_to_delete = [{'Key': obj['Key']} for obj in response['Contents']]

            # Delete all objects from the bucket
            s3_client.delete_objects(Bucket=bucket_name, Delete={'Objects': objects_to_delete})

        # Delete the empty bucket
        s3_client.delete_bucket(Bucket=bucket_name)
        print(f"Bucket '{bucket_name}' has been emptied and deleted successfully.")
    except Exception as error:
        print(f"An error occurred: {str(error)}")


def load_bucket_policy(bucket_name, region):

    master_accountId = get_master_account()
    org_id = get_org_id()
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck20150319",
                "Effect": "Allow",
                "Principal": {
                    "Service": [
                        "cloudtrail.amazonaws.com"
                    ]
                },
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket_name}",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceArn": f"arn:aws:cloudtrail:{region}:{master_accountId}:trail/{trail_name}"
                    }
                }
            },
            {
                "Sid": "AWSCloudTrailWrite20150319",
                "Effect": "Allow",
                "Principal": {
                    "Service": [
                        "cloudtrail.amazonaws.com"
                    ]
                },
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{master_accountId}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceArn": f"arn:aws:cloudtrail:{region}:{master_accountId}:trail/{trail_name}"
                    }
                }
            },
            {
                "Sid": "AWSCloudTrailOrganizationWrite20150319",
                "Effect": "Allow",
                "Principal": {
                    "Service": [
                        "cloudtrail.amazonaws.com"
                    ]
                },
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{org_id}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceArn": f"arn:aws:cloudtrail:{region}:{master_accountId}:trail/{trail_name}"
                    }
                }
            }
        ]
    }

    return(json.dumps(bucket_policy, indent=2))



if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description='Creates a valid org wide trail with required bucket policy and uptycs IAM Role'
    )
    parser.add_argument('--action', choices=['Create', 'Delete'], required=True,
                        help='The action to perform: Create, or Delete')
    parser.add_argument('--ctbucket', required=True,
                        help='The Name of the CloudTrail bucket')
    parser.add_argument('--trailname',
                        help='The Name of the CloudTrail that you will create '
                             '(default:UptycsIntegrationTrail)',
                        default='UptycsIntegrationTrail')


    # Parse the arguments
    args = parser.parse_args()

    action = args.action
    bucket_name = args.ctbucket
    trail_name = args.trailname

    # Convert the dictionary to a JSON string

    region = get_region()

    if action == 'Create':
        policy = load_bucket_policy(bucket_name, region)
        create_s3_bucket_with_policy(bucket_name, policy, region)
        create_trail(trail_name, bucket_name, is_organization = False)
    elif action == 'Delete':
        delete_trail(trail_name)
        empty_and_delete_bucket(bucket_name)
