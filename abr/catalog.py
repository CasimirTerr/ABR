"""Catalog of AWS actions that matter when an AI agent is hijacked.

Each action is tagged with one or more categories:

- data_access: reads private or sensitive data
- exfiltration: can move data or access outside the account
- privilege_escalation: can grant the agent (or an attacker) more power
- destructive: deletes or breaks resources
- defense_evasion: turns off logging or detection
"""

DATA_ACCESS = "data_access"
EXFILTRATION = "exfiltration"
PRIVILEGE_ESCALATION = "privilege_escalation"
DESTRUCTIVE = "destructive"
DEFENSE_EVASION = "defense_evasion"

CATEGORY_LABELS = {
    DATA_ACCESS: "Reads sensitive data",
    EXFILTRATION: "Can send data or access outside the account",
    PRIVILEGE_ESCALATION: "Can escalate privileges",
    DESTRUCTIVE: "Can delete or break resources",
    DEFENSE_EVASION: "Can turn off logging or detection",
}

RISKY_ACTIONS = {
    # Data access
    "s3:GetObject": [DATA_ACCESS],
    "s3:ListBucket": [DATA_ACCESS],
    "secretsmanager:GetSecretValue": [DATA_ACCESS],
    "ssm:GetParameter": [DATA_ACCESS],
    "ssm:GetParameters": [DATA_ACCESS],
    "ssm:GetParametersByPath": [DATA_ACCESS],
    "kms:Decrypt": [DATA_ACCESS],
    "dynamodb:GetItem": [DATA_ACCESS],
    "dynamodb:Query": [DATA_ACCESS],
    "dynamodb:Scan": [DATA_ACCESS],
    "rds-data:ExecuteStatement": [DATA_ACCESS],
    "logs:GetLogEvents": [DATA_ACCESS],
    "logs:FilterLogEvents": [DATA_ACCESS],
    "lambda:GetFunction": [DATA_ACCESS],
    "codecommit:GetFile": [DATA_ACCESS],
    # Exfiltration / external communication
    "s3:PutBucketPolicy": [EXFILTRATION],
    "s3:PutBucketAcl": [EXFILTRATION],
    "s3:PutObjectAcl": [EXFILTRATION],
    "s3:DeletePublicAccessBlock": [EXFILTRATION, DEFENSE_EVASION],
    "s3:PutObject": [EXFILTRATION],
    "ses:SendEmail": [EXFILTRATION],
    "ses:SendRawEmail": [EXFILTRATION],
    "sns:Publish": [EXFILTRATION],
    "sqs:SendMessage": [EXFILTRATION],
    "lambda:CreateFunctionUrlConfig": [EXFILTRATION],
    "lambda:AddPermission": [EXFILTRATION],
    "ec2:ModifySnapshotAttribute": [EXFILTRATION],
    "ec2:ModifyImageAttribute": [EXFILTRATION],
    "rds:ModifyDBSnapshotAttribute": [EXFILTRATION],
    "ec2:AuthorizeSecurityGroupIngress": [EXFILTRATION],
    # Privilege escalation (based on well-known AWS IAM escalation methods)
    "iam:CreatePolicyVersion": [PRIVILEGE_ESCALATION],
    "iam:SetDefaultPolicyVersion": [PRIVILEGE_ESCALATION],
    "iam:AttachUserPolicy": [PRIVILEGE_ESCALATION],
    "iam:AttachRolePolicy": [PRIVILEGE_ESCALATION],
    "iam:AttachGroupPolicy": [PRIVILEGE_ESCALATION],
    "iam:PutUserPolicy": [PRIVILEGE_ESCALATION],
    "iam:PutRolePolicy": [PRIVILEGE_ESCALATION],
    "iam:PutGroupPolicy": [PRIVILEGE_ESCALATION],
    "iam:AddUserToGroup": [PRIVILEGE_ESCALATION],
    "iam:CreateAccessKey": [PRIVILEGE_ESCALATION, EXFILTRATION],
    "iam:CreateLoginProfile": [PRIVILEGE_ESCALATION],
    "iam:UpdateLoginProfile": [PRIVILEGE_ESCALATION],
    "iam:UpdateAssumeRolePolicy": [PRIVILEGE_ESCALATION],
    "iam:CreateUser": [PRIVILEGE_ESCALATION],
    "iam:PassRole": [PRIVILEGE_ESCALATION],
    "sts:AssumeRole": [PRIVILEGE_ESCALATION],
    "lambda:UpdateFunctionCode": [PRIVILEGE_ESCALATION],
    "lambda:CreateFunction": [PRIVILEGE_ESCALATION],
    "lambda:InvokeFunction": [PRIVILEGE_ESCALATION],
    "ec2:RunInstances": [PRIVILEGE_ESCALATION],
    "cloudformation:CreateStack": [PRIVILEGE_ESCALATION],
    "glue:CreateDevEndpoint": [PRIVILEGE_ESCALATION],
    "ssm:SendCommand": [PRIVILEGE_ESCALATION],
    # Destructive
    "s3:DeleteObject": [DESTRUCTIVE],
    "s3:DeleteBucket": [DESTRUCTIVE],
    "dynamodb:DeleteTable": [DESTRUCTIVE],
    "dynamodb:DeleteItem": [DESTRUCTIVE],
    "ec2:TerminateInstances": [DESTRUCTIVE],
    "ec2:DeleteVolume": [DESTRUCTIVE],
    "ec2:DeleteSnapshot": [DESTRUCTIVE],
    "rds:DeleteDBInstance": [DESTRUCTIVE],
    "rds:DeleteDBCluster": [DESTRUCTIVE],
    "kms:ScheduleKeyDeletion": [DESTRUCTIVE],
    "kms:DisableKey": [DESTRUCTIVE],
    "lambda:DeleteFunction": [DESTRUCTIVE],
    "iam:DeleteRole": [DESTRUCTIVE],
    "backup:DeleteRecoveryPoint": [DESTRUCTIVE],
    # Defense evasion
    "cloudtrail:StopLogging": [DEFENSE_EVASION],
    "cloudtrail:DeleteTrail": [DEFENSE_EVASION],
    "cloudtrail:UpdateTrail": [DEFENSE_EVASION],
    "cloudtrail:PutEventSelectors": [DEFENSE_EVASION],
    "guardduty:DeleteDetector": [DEFENSE_EVASION],
    "guardduty:UpdateDetector": [DEFENSE_EVASION],
    "securityhub:DisableSecurityHub": [DEFENSE_EVASION],
    "config:StopConfigurationRecorder": [DEFENSE_EVASION],
    "config:DeleteConfigurationRecorder": [DEFENSE_EVASION],
    "logs:DeleteLogGroup": [DEFENSE_EVASION, DESTRUCTIVE],
}

# Combinations of actions that together give a known privilege escalation path.
# Each entry: (name, list of required actions, explanation)
ESCALATION_PATHS = [
    ("Rewrite own policy", ["iam:CreatePolicyVersion"],
     "Can publish a new version of a managed policy with full admin rights."),
    ("Switch policy version", ["iam:SetDefaultPolicyVersion"],
     "Can roll a policy back to an older, more permissive version."),
    ("Attach admin policy", ["iam:AttachRolePolicy"],
     "Can attach AdministratorAccess to a role, including its own."),
    ("Attach admin policy to a user", ["iam:AttachUserPolicy"],
     "Can attach AdministratorAccess to a user."),
    ("Write inline admin policy", ["iam:PutRolePolicy"],
     "Can add an inline policy granting any permission to a role."),
    ("Mint access keys", ["iam:CreateAccessKey"],
     "Can create long-lived access keys for another user and hand them out."),
    ("Set a console password", ["iam:CreateLoginProfile"],
     "Can give another user a console password and log in as them."),
    ("Lambda with a privileged role", ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
     "Can create a Lambda that runs as a more powerful role, then invoke it."),
    ("Backdoor existing Lambda", ["lambda:UpdateFunctionCode"],
     "Can replace the code of a Lambda that already runs with a powerful role."),
    ("EC2 with a privileged role", ["iam:PassRole", "ec2:RunInstances"],
     "Can launch an instance with a powerful instance profile and use its credentials."),
    ("CloudFormation with a privileged role", ["iam:PassRole", "cloudformation:CreateStack"],
     "Can deploy a stack that runs as a more powerful role."),
    ("Glue dev endpoint", ["iam:PassRole", "glue:CreateDevEndpoint"],
     "Can create a Glue endpoint with a powerful role and SSH into it."),
    ("Run commands on instances", ["ssm:SendCommand"],
     "Can run shell commands on managed EC2 instances and use their roles."),
    ("Edit a role's trust policy", ["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
     "Can let itself assume any role and then assume it."),
]
