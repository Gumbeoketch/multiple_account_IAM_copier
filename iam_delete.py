import boto3

# Define the master account's IAM client
master_account_session = boto3.Session(profile_name='default') # profile can be obtained by running "aws configure list-profiles"  
iam_master = master_account_session.client('iam')

# Define the target accounts and the role to assume
target_accounts = ['982081066392']  # Add all target accounts
role_name = 'OrganizationAccountAccessRole'  # Role name that allows access to target accounts

# List of custom policies to delete
custom_policies = ['security_custom_policy']

def assume_role(account_id, role_name):
    """Assumes the specified role in the target account and returns a session."""
    sts_client = boto3.client('sts')
    response = sts_client.assume_role(
        RoleArn=f'arn:aws:iam::{account_id}:role/{role_name}',
        RoleSessionName='DeleteCustomPoliciesSession'
    )
    credentials = response['Credentials']
    
    return boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

def get_policy_arn(policy_name, account_id):
    """Generates the policy ARN using the account ID and policy name."""
    return f'arn:aws:iam::{account_id}:policy/{policy_name}'

def delete_policy_in_target_account(session, policy_name, policy_arn):
    """Deletes a policy in the target account."""
    iam_target = session.client('iam')
    try:
        # First, you need to delete the policy versions except the default one
        policy_versions = iam_target.list_policy_versions(PolicyArn=policy_arn)
        for version in policy_versions['Versions']:
            if not version['IsDefaultVersion']:
                iam_target.delete_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=version['VersionId']
                )
        # Now delete the policy itself
        iam_target.delete_policy(PolicyArn=policy_arn)
        print(f"Successfully deleted {policy_name} from target account.")
    except iam_target.exceptions.NoSuchEntityException:
        print(f"Policy {policy_name} does not exist in the target account.")
    except Exception as e:
        print(f"Failed to delete policy {policy_name} in target account: {e}")

def delete_policies_from_accounts():
    """Main function to loop through target accounts and delete policies."""
    for account_id in target_accounts:
        print(f"Deleting policies from account {account_id}...")

        # Assume role into the target account
        target_session = assume_role(account_id, role_name)

        # Loop through each custom policy
        for policy_name in custom_policies:
            print(f"Processing policy {policy_name}...")
            policy_arn = get_policy_arn(policy_name, account_id)

            # Delete the policy in the target account
            delete_policy_in_target_account(target_session, policy_name, policy_arn)

if __name__ == "__main__":
    delete_policies_from_accounts()

