# ABR blast radius report: `acme-support-bot`

**Blast radius score:** 100/100 (Severe)  
**Findings:** 4 critical, 3 high, 4 medium, 3 low  
**Risky AWS actions reachable:** 18 (14 not used by any tool)

| Severity | ID | Finding |
| --- | --- | --- |
| CRITICAL | ABR-001 | Lethal trifecta: a prompt injection can steal private data |
| CRITICAL | ABR-108 | Privilege escalation path: Lambda with a privileged role |
| CRITICAL | ABR-109 | Privilege escalation path: Backdoor existing Lambda |
| CRITICAL | ABR-201 | Unused permissions: can escalate privileges |
| HIGH | ABR-203 | Unused permissions: can delete or break resources |
| HIGH | ABR-204 | Unused permissions: can send data or access outside the account |
| HIGH | ABR-205 | Unused permissions: reads sensitive data |
| MEDIUM | ABR-301 | Wildcard permission in statement 'AppData' |
| MEDIUM | ABR-301 | Wildcard permission in statement 'DebugAddedDuringLaunch' |
| MEDIUM | ABR-302 | Tool 'lookup_order' only needs specific resources but the role allows all of them |
| MEDIUM | ABR-302 | Tool 'get_help_article' only needs specific resources but the role allows all of them |
| LOW | ABR-303 | Statement 'AppConfig' is not used by any tool |
| LOW | ABR-303 | Statement 'DebugAddedDuringLaunch' is not used by any tool |
| LOW | ABR-303 | Statement 'EmailCustomers' is not used by any tool |

## CRITICAL: Lethal trifecta: a prompt injection can steal private data

The agent reads attacker-controlled content, can reach private data, and has a way to send data out. A hidden instruction in a web page or email could make it read secrets and send them to the attacker.
  - Untrusted input: browse_web, read_support_inbox
  - Private data: read_support_inbox, lookup_order, dynamodb:GetItem, dynamodb:Query, dynamodb:Scan, lambda:GetFunction, s3:GetObject, s3:ListBucket, ...
  - Way out: browse_web, lambda:AddPermission, lambda:CreateFunctionUrlConfig, ses:SendEmail, sqs:SendMessage

**Fix:** Break one leg: run the untrusted-input tool in a separate agent with no data access, remove the outbound tool, or require human approval before anything is sent out.

## CRITICAL: Privilege escalation path: Lambda with a privileged role

Can create a Lambda that runs as a more powerful role, then invoke it. The agent reads untrusted input, so an attacker can steer it here.

**Fix:** Remove iam:PassRole, lambda:CreateFunction, lambda:InvokeFunction from the agent's role.

## CRITICAL: Privilege escalation path: Backdoor existing Lambda

Can replace the code of a Lambda that already runs with a powerful role. The agent reads untrusted input, so an attacker can steer it here.

**Fix:** Remove lambda:UpdateFunctionCode from the agent's role.

## CRITICAL: Unused permissions: can escalate privileges

4 risky action(s) in this category are allowed but no tool uses them. They only add to what a hijacked agent could do.

Actions: `iam:PassRole`, `lambda:CreateFunction`, `lambda:InvokeFunction`, `lambda:UpdateFunctionCode`

**Fix:** Remove these actions from the role, or replace the policy with the generated least-privilege policy.

## HIGH: Unused permissions: can delete or break resources

3 risky action(s) in this category are allowed but no tool uses them. They only add to what a hijacked agent could do.

Actions: `dynamodb:DeleteItem`, `dynamodb:DeleteTable`, `lambda:DeleteFunction`

**Fix:** Remove these actions from the role, or replace the policy with the generated least-privilege policy.

## HIGH: Unused permissions: can send data or access outside the account

3 risky action(s) in this category are allowed but no tool uses them. They only add to what a hijacked agent could do.

Actions: `lambda:AddPermission`, `lambda:CreateFunctionUrlConfig`, `ses:SendEmail`

**Fix:** Remove these actions from the role, or replace the policy with the generated least-privilege policy.

## HIGH: Unused permissions: reads sensitive data

4 risky action(s) in this category are allowed but no tool uses them. They only add to what a hijacked agent could do.

Actions: `dynamodb:Scan`, `lambda:GetFunction`, `s3:ListBucket`, `secretsmanager:GetSecretValue`

**Fix:** Remove these actions from the role, or replace the policy with the generated least-privilege policy.

## MEDIUM: Wildcard permission in statement 'AppData'

Allows dynamodb:*. New AWS actions get added to wildcards automatically.

**Fix:** List the exact actions the tools call instead of a wildcard.

## MEDIUM: Wildcard permission in statement 'DebugAddedDuringLaunch'

Allows lambda:*. New AWS actions get added to wildcards automatically.

**Fix:** List the exact actions the tools call instead of a wildcard.

## MEDIUM: Tool 'lookup_order' only needs specific resources but the role allows all of them

dynamodb:GetItem, dynamodb:Query are allowed on every resource, but the tool only uses arn:aws:dynamodb:us-east-1:111122223333:table/orders.

**Fix:** Scope the Resource element to the ARNs listed for this tool.

## MEDIUM: Tool 'get_help_article' only needs specific resources but the role allows all of them

s3:GetObject is allowed on every resource, but the tool only uses arn:aws:s3:::acme-help-center/*.

**Fix:** Scope the Resource element to the ARNs listed for this tool.

## LOW: Statement 'AppConfig' is not used by any tool

It allows secretsmanager:GetSecretValue, but no tool in the manifest calls these.

**Fix:** Delete the statement.

## LOW: Statement 'DebugAddedDuringLaunch' is not used by any tool

It allows lambda:*, iam:PassRole, but no tool in the manifest calls these.

**Fix:** Delete the statement.

## LOW: Statement 'EmailCustomers' is not used by any tool

It allows ses:SendEmail, but no tool in the manifest calls these.

**Fix:** Delete the statement.

## Suggested least-privilege policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LookupOrder",
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:Query"
      ],
      "Resource": [
        "arn:aws:dynamodb:us-east-1:111122223333:table/orders"
      ]
    },
    {
      "Sid": "GetHelpArticle",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": [
        "arn:aws:s3:::acme-help-center/*"
      ]
    },
    {
      "Sid": "RequestRefund",
      "Effect": "Allow",
      "Action": [
        "sqs:SendMessage"
      ],
      "Resource": [
        "arn:aws:sqs:us-east-1:111122223333:refund-requests"
      ]
    }
  ]
}
```

_ABR checks identity policies only. SCPs, permission boundaries and session policies can only take permissions away; resource policies (S3 bucket, KMS key) can also grant access and are not checked._
