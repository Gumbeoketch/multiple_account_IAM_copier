import boto3
import json

# Define the master account's IAM client
# Here we call the AWS IAM service
master_account_session = boto3.Session(profile_name='default') # profile can be obtained by running "aws configure list-profiles" 
iam_master = master_account_session.client('iam')

# Define the target accounts and the role to assume
target_accounts = ['982081066392']  # Add all target accounts
role_name = 'OrganizationAccountAccessRole'  # Role name that allows access to target account(s)

# List of custom policies to copy
custom_policies = ['security_custom_policy']

def assume_role(account_id, role_name):
    sts_client = boto3.client('sts')
    response = sts_client.assume_role(
        RoleArn=f'arn:aws:iam::{account_id}:role/{role_name}',
        RoleSessionName='CopyCustomPoliciesSession'
    )
    credentials = response['Credentials']
    
    return boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

def get_policy_arn(policy_name):
    try:
        policy = iam_master.get_policy(PolicyArn=f'arn:aws:iam::510556361670:policy/{policy_name}')
        return policy['Policy']['Arn']
    except iam_master.exceptions.NoSuchEntityException:
        print(f'Policy {policy_name} does not exist in the master account.')
        return None

def get_policy_document(policy_arn):
    policy_version = iam_master.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=iam_master.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
    )
    return policy_version['PolicyVersion']['Document']

def create_policy_in_target_account(session, policy_name, policy_document):
    iam_target = session.client('iam')
    try:
        response = iam_target.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document)
        )
        print(f"Successfully created {policy_name} in target account.")
    except iam_target.exceptions.EntityAlreadyExistsException:
        print(f"Policy {policy_name} already exists in the target account.")
    except Exception as e:
        print(f"Failed to create policy {policy_name} in target account: {e}")

def copy_policies_to_accounts():
    for account_id in target_accounts:
        print(f"Copying policies to account {account_id}...")

        # Assume role into the target account
        target_session = assume_role(account_id, role_name)

        # Loop through each custom policy
        for policy_name in custom_policies:
            print(f"Processing policy {policy_name}...")

            # Get policy ARN and document from master account
            policy_arn = get_policy_arn(policy_name)
            if policy_arn:
                policy_document = get_policy_document(policy_arn)
                
                # Create the policy in the target account
                create_policy_in_target_account(target_session, policy_name, policy_document)

if __name__ == "__main__":
    copy_policies_to_accounts()

