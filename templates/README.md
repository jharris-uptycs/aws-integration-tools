Description of Templates

## org-setup.yaml

Description:
This template is designed to set up necessary roles and permissions for Uptycs
security management across an AWS Organization. It performs two primary functions:

1. Creates an IAM role named 'UptycsIAMRole' within the master account. This role
   is tailored for the Uptycs service, allowing it to perform actions and access
   resources as defined by the attached policies.

2. Establishes a service-managed StackSet that contains the defined Uptycs IAM role.
   This StackSet is configured to deploy automatically to all existing and future
   member accounts within the organization, ensuring that Uptycs has the necessary
   permissions across the entire AWS environment.

## org-log-acct-iam-role.json

Example of the the IAM role that should be applied to the account containing your cloudtrail bucket

## org-member-acct-iam-role.json

Example of the the IAM role that should be applied to each org member account