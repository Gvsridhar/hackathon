import boto3
import json

def get_user_policies(userid):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('hackathon-user-table')
    try:
        response = table.get_item(
            Key={'userid': userid}
        )
        return response['Item'].get('policies', [])
    except Exception as e:
        print(f"Error querying DynamoDB: {e}")
        return []

def create_iam_role_if_not_exists(role_name, trust_policy):
    iam_client = boto3.client('iam')
    try:
        iam_client.get_role(RoleName=role_name)
        print(f"Role {role_name} already exists")
    except iam_client.exceptions.NoSuchEntityException:
        try:
            response = iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy)
            )
            return response['Role']
        except Exception as e:
            print(f"Error creating IAM role: {e}")
            return None
    except Exception as e:
        print(f"Error checking IAM role: {e}")
        return None

def attach_iam_policies(role_name, policies):
    iam_client = boto3.client('iam')
    for policy_arn in policies:
        try:
            iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_arn
            )
        except Exception as e:
            print(f"Error attaching IAM policy {policy_arn}: {e}")

def generate_sts_token(role_arn, session_name):
    sts_client = boto3.client('sts')
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name
        )
        return response['Credentials']
    except Exception as e:
        print(f"Error generating STS token: {e}")
        return None

def lambda_handler(event, context):
    # 1. Get userid from lambda event
    userid = event.get('userid')
    if not userid:
        return {
            'statusCode': 400,
            'body': json.dumps('userid is required in the event')
        }

    # 2. Query dynamodb table for list of iam policies userid has
    policies = get_user_policies(userid)
    if not policies:
        return {
            'statusCode': 404,
            'body': json.dumps('No policies found for the given userid')
        }

    # 3. Check and create iam role if not existing already
    role_name = f'hackathon-{userid}-iam-role'
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }
    role = create_iam_role_if_not_exists(role_name, trust_policy)
    if role is None:
        return {
            'statusCode': 500,
            'body': json.dumps('Error creating or checking IAM role')
        }

    # 4. Attach policies returned from dynamodb query to the iam role
    attach_iam_policies(role_name, policies)

    # 5. Generate aws sts creds against the iam role
    credentials = generate_sts_token(role['Arn'], f'{userid}-session')
    if credentials is None:
        return {
            'statusCode': 500,
            'body': json.dumps('Error generating STS credentials')
        }

    # 6. Return aws credentials as response from lambda function
    return {
        'statusCode': 200,
        'body': json.dumps({
            'AccessKeyId': credentials['AccessKeyId'],
            'SecretAccessKey': credentials['SecretAccessKey'],
            'SessionToken': credentials['SessionToken'],
            'Expiration': credentials['Expiration']
        })
    }