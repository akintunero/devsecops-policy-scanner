package dsp_scanner.terraform.aws

# Check for public S3 buckets
deny[msg] {
    resource := input.resource.aws_s3_bucket[_]
    not resource.acl
    msg = {
        "title": "S3 Bucket Missing ACL",
        "description": "S3 bucket does not have an ACL defined",
        "severity": "HIGH",
        "platform": "terraform",
        "recommendation": "Define an ACL for the S3 bucket",
        "code_snippet": sprintf("resource \"aws_s3_bucket\" \"%v\" {\n  # Missing ACL configuration\n}", [resource.bucket])
    }
}

# Check for unencrypted S3 buckets
deny[msg] {
    resource := input.resource.aws_s3_bucket[_]
    not resource.server_side_encryption_configuration
    msg = {
        "title": "Unencrypted S3 Bucket",
        "description": "S3 bucket is not configured with server-side encryption",
        "severity": "HIGH",
        "platform": "terraform",
        "recommendation": "Enable server-side encryption for S3 buckets",
        "code_snippet": sprintf("resource \"aws_s3_bucket\" \"%v\" {\n  # Missing server_side_encryption_configuration\n}", [resource.bucket])
    }
}

# Check for open security groups
deny[msg] {
    resource := input.resource.aws_security_group[_]
    ingress := resource.ingress[_]
    contains(ingress.cidr_blocks[_], "0.0.0.0/0")
    msg = {
        "title": "Open Security Group Rule",
        "description": "Security group allows inbound access from any source",
        "severity": "HIGH",
        "platform": "terraform",
        "recommendation": "Restrict inbound access to specific IP ranges",
        "code_snippet": sprintf("resource \"aws_security_group\" \"%v\" {\n  ingress {\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}", [resource.name])
    }
}

# Check for unencrypted EBS volumes
deny[msg] {
    resource := input.resource.aws_ebs_volume[_]
    not resource.encrypted
    msg = {
        "title": "Unencrypted EBS Volume",
        "description": "EBS volume is not encrypted",
        "severity": "HIGH",
        "platform": "terraform",
        "recommendation": "Enable encryption for EBS volumes",
        "code_snippet": sprintf("resource \"aws_ebs_volume\" \"%v\" {\n  encrypted = false  # or missing\n}", [resource.name])
    }
}

# Check for public RDS instances
deny[msg] {
    resource := input.resource.aws_db_instance[_]
    resource.publicly_accessible == true
    msg = {
        "title": "Publicly Accessible RDS Instance",
        "description": "RDS instance is publicly accessible",
        "severity": "HIGH",
        "platform": "terraform",
        "recommendation": "Disable public access for RDS instances",
        "code_snippet": sprintf("resource \"aws_db_instance\" \"%v\" {\n  publicly_accessible = true\n}", [resource.identifier])
    }
}

# Check for unencrypted RDS instances
deny[msg] {
    resource := input.resource.aws_db_instance[_]
    not resource.storage_encrypted
    msg = {
        "title": "Unencrypted RDS Storage",
        "description": "RDS instance storage is not encrypted",
        "severity": "HIGH",
        "platform": "terraform",
        "recommendation": "Enable storage encryption for RDS instances",
        "code_snippet": sprintf("resource \"aws_db_instance\" \"%v\" {\n  # Missing storage_encrypted = true\n}", [resource.identifier])
    }
}

# Check for unencrypted SNS topics
deny[msg] {
    resource := input.resource.aws_sns_topic[_]
    not resource.kms_master_key_id
    msg = {
        "title": "Unencrypted SNS Topic",
        "description": "SNS topic is not encrypted with KMS",
        "severity": "MEDIUM",
        "platform": "terraform",
        "recommendation": "Enable KMS encryption for SNS topics",
        "code_snippet": sprintf("resource \"aws_sns_topic\" \"%v\" {\n  # Missing kms_master_key_id\n}", [resource.name])
    }
}

# Check for unencrypted SQS queues
deny[msg] {
    resource := input.resource.aws_sqs_queue[_]
    not resource.kms_master_key_id
    msg = {
        "title": "Unencrypted SQS Queue",
        "description": "SQS queue is not encrypted with KMS",
        "severity": "MEDIUM",
        "platform": "terraform",
        "recommendation": "Enable KMS encryption for SQS queues",
        "code_snippet": sprintf("resource \"aws_sqs_queue\" \"%v\" {\n  # Missing kms_master_key_id\n}", [resource.name])
    }
}

# Check for public ECR repositories
deny[msg] {
    resource := input.resource.aws_ecr_repository[_]
    policy := json.unmarshal(resource.policy)
    statement := policy.Statement[_]
    statement.Principal == "*"
    msg = {
        "title": "Public ECR Repository",
        "description": "ECR repository has a public access policy",
        "severity": "HIGH",
        "platform": "terraform",
        "recommendation": "Restrict ECR repository access to specific principals",
        "code_snippet": sprintf("resource \"aws_ecr_repository\" \"%v\" {\n  # Review repository policy\n}", [resource.name])
    }
}

# Check for unencrypted CloudWatch log groups
deny[msg] {
    resource := input.resource.aws_cloudwatch_log_group[_]
    not resource.kms_key_id
    msg = {
        "title": "Unencrypted CloudWatch Log Group",
        "description": "CloudWatch log group is not encrypted with KMS",
        "severity": "MEDIUM",
        "platform": "terraform",
        "recommendation": "Enable KMS encryption for CloudWatch log groups",
        "code_snippet": sprintf("resource \"aws_cloudwatch_log_group\" \"%v\" {\n  # Missing kms_key_id\n}", [resource.name])
    }
}

# Check for IAM users with console access
deny[msg] {
    resource := input.resource.aws_iam_user[_]
    password := input.resource.aws_iam_user_login_profile[_]
    msg = {
        "title": "IAM User with Console Access",
        "description": "IAM user is configured with console access",
        "severity": "MEDIUM",
        "platform": "terraform",
        "recommendation": "Use IAM roles and federation instead of IAM users with console access",
        "code_snippet": sprintf("resource \"aws_iam_user_login_profile\" \"%v\" {\n  # Consider using IAM roles instead\n}", [password.user])
    }
}

# Check for overly permissive IAM policies
deny[msg] {
    resource := input.resource.aws_iam_policy[_]
    policy := json.unmarshal(resource.policy)
    statement := policy.Statement[_]
    statement.Effect == "Allow"
    statement.Action[_] == "*"
    msg = {
        "title": "Overly Permissive IAM Policy",
        "description": "IAM policy grants full access (*) permissions",
        "severity": "HIGH",
        "platform": "terraform",
        "recommendation": "Follow principle of least privilege and grant specific permissions only",
        "code_snippet": sprintf("resource \"aws_iam_policy\" \"%v\" {\n  # Review policy permissions\n}", [resource.name])
    }
}
