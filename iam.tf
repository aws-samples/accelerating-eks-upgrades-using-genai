data "aws_iam_policy_document" "glue_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["glue.amazonaws.com", "quicksight.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "kms_policy" {
  # checkov:skip=CKV_AWS_109: This key policy is required for the management of the key.
  # checkov:skip=CKV_AWS_111: This key policy is required for the management of the key.
  # checkov:skip=CKV_AWS_356: This key policy is required for the management of the key.
  statement {
    sid       = "AllowRootKeyManagement"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"] //creates cyclic dependency if we specify the KMS arn
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_iam_role" "lambda_role" {
  name               = "${var.customer_name}-eks-insights-lambda"
  assume_role_policy = <<EOF
{
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
EOF
}

resource "aws_iam_role_policy_attachment" "lambda_role_policy_attachment" {
  policy_arn = aws_iam_policy.lambda_role_policy.arn
  role       = aws_iam_role.lambda_role.name
}

resource "aws_iam_policy" "lambda_role_policy" {
  name   = "${var.customer_name}-eks-insights-lambda-permissions"
  policy = data.aws_iam_policy_document.lambda_role_policy_document.json
}

resource "aws_iam_role_policy_attachment" "lambda_role_assume_policy_attachment" {
  policy_arn = aws_iam_policy.cross_account_assume_role_policy.arn
  role       = aws_iam_role.lambda_role.name
}

resource "aws_iam_policy" "cross_account_assume_role_policy" {
  name   = "${var.customer_name}-eks-insights-cross-account-permissions"
  policy = data.aws_iam_policy_document.cross_account_role_assume.json
}

data "aws_iam_policy_document" "cross_account_role_assume" {
  statement {
    sid       = "AllowCrossAccountAssume"
    effect    = "Allow"
    resources = ["arn:aws:iam::*:role/${var.cross_accounts_role}"]

    actions = [
      "sts:AssumeRole",
    ]
  }
}

data "aws_iam_policy_document" "lambda_role_policy_document" {
  statement {
    sid       = "AllowSQSPermissions"
    effect    = "Allow"
    resources = ["${aws_sqs_queue.eks_cluster_queue.arn}", "${aws_sqs_queue.eks_cluster_queue_deadletter.arn}"]

    actions = [
      "sqs:ChangeMessageVisibility",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:ReceiveMessage",
      "sqs:SendMessage",
    ]
  }

  statement {
    sid       = "AllowEKSClustersAccess"
    effect    = "Allow"
    resources = ["arn:aws:eks:*:*:*"]
    actions = [
      "eks:ListClusters",
      "eks:DescribeCluster",
      "eks:ListAccessEntries",
      "eks:ListAccessPolicies",
      "eks:ListAssociatedAccessPolicies"
    ]
  }

  statement {
    sid       = "AllowOrgAccess"
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "organizations:ListAccountsForParent",
      "organizations:ListAccounts",
      "organizations:ListRoots",
      "organizations:DescribeOrganization",
      "organizations:ListOrganizationalUnitsForParent",
      "organizations:ListAWSServiceAccessForOrganization",
    ]
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = ["${data.aws_organizations_organization.current.id}"]
    }
  }

  statement {
    sid       = "AllowSNSPublishAccess"
    effect    = "Allow"
    resources = ["${aws_sns_topic.eks_insights_topic.arn}"]
    actions = [
      "sns:Publish"
    ]
  }

  statement {
    sid       = "AllowKMSAccess"
    effect    = "Allow"
    resources = ["${aws_kms_key.eks_insights_kms.arn}"]
    actions = [
      "kms:GenerateDataKey*",
      "kms:Decrypt",
      "kms:CreateGrant",
    ]
  }

  statement {
    sid       = "AllowInvokingGlue"
    effect    = "Allow"
    resources = ["${aws_glue_job.eks_org_data_glue_job.arn}"]
    actions = [
      "glue:StartJobRun",
      "glue:GetJobRun",
      "glue:GetJobRunState",
    ]
  }

  statement {
    sid       = "AllowCreatingLogGroups"
    effect    = "Allow"
    resources = ["arn:aws:logs:*:*:*"]
    actions   = ["logs:CreateLogGroup"]
  }
  statement {
    sid       = "AllowWritingLogs"
    effect    = "Allow"
    resources = ["arn:aws:logs:*:*:log-group:/aws/lambda/*:*"]

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
  }
}


resource "aws_iam_role" "eks_insights_glue_role" {
  name               = "${var.customer_name}-eks-insights-solution"
  assume_role_policy = data.aws_iam_policy_document.glue_assume.json
}

resource "aws_iam_role_policy_attachment" "glue_role_assume_policy_attachment" {
  policy_arn = aws_iam_policy.cross_account_assume_role_policy.arn
  role       = aws_iam_role.eks_insights_glue_role.name
}


resource "aws_iam_role_policy_attachment" "eks_insights_s3_access_policy_attachment" {
  policy_arn = aws_iam_policy.eks_insights_role_access_policy.arn
  role       = aws_iam_role.eks_insights_glue_role.name
}

resource "aws_iam_policy" "eks_insights_role_access_policy" {
  name   = "${var.customer_name}-eks-insights-solution-permissions"
  policy = data.aws_iam_policy_document.eks_insights_role_policy_document.json
}

data "aws_iam_policy_document" "eks_insights_role_policy_document" {
  statement {
    sid       = "AllowS3Access"
    effect    = "Allow"
    resources = ["arn:aws:s3:::${aws_s3_bucket.org_data_bucket.id}", "arn:aws:s3:::${aws_s3_bucket.org_data_bucket.id}/*"]

    actions = [
      "s3:ListBucket",
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:PutObject",
    ]
  }

  statement {
    sid       = "AllowEKSClustersAccess"
    effect    = "Allow"
    resources = ["arn:aws:eks:*:*:*"]
    actions = [
      "eks:ListClusters",
      "eks:ListInsights",
      "eks:ListAddons",
      "eks:DescribeCluster",
      "eks:DescribeAddonConfiguration",
      "eks:DescribeAddonVersions",
      "eks:DescribeAddon",
      "eks:DescribeInsight",
      "eks:ListAccessEntries",
      "eks:ListAccessPolicies",
      "eks:ListAssociatedAccessPolicies"
    ]
  }

  statement {
    sid       = "AllowSNSPublishAccess"
    effect    = "Allow"
    resources = ["${aws_sns_topic.eks_insights_topic.arn}"]
    actions = [
      "sns:Publish"
    ]
  }

  statement {
    sid       = "AllowOrgAccess"
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "organizations:ListAccountsForParent",
      "organizations:ListAccounts",
      "organizations:ListRoots",
      "organizations:DescribeOrganization",
      "organizations:ListOrganizationalUnitsForParent",
      "organizations:ListAWSServiceAccessForOrganization",
    ]
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = ["${data.aws_organizations_organization.current.id}"]
    }
  }

  statement {
    sid       = "AllowBedrockAccess"
    effect    = "Allow"
    resources = ["arn:aws:bedrock:${var.bedrock_region}::foundation-model/${var.bedrock_model}"]
    actions = [
      "bedrock:InvokeModel",
      "bedrock:InvokeModelWithResponseStream"
    ]
  }

  statement {
    sid       = "AllowKMSAccess"
    effect    = "Allow"
    resources = ["${aws_kms_key.eks_insights_kms.arn}"]
    actions = [
      "kms:GenerateDataKey*",
      "kms:Decrypt",
      "kms:CreateGrant",
    ]
  }

  statement {
    sid       = "AllowCreatingLogGroups"
    effect    = "Allow"
    resources = ["arn:aws:logs:*:*:*"]
    actions   = ["logs:CreateLogGroup"]
  }

  statement {
    sid       = "AllowWritingLogs"
    effect    = "Allow"
    resources = ["arn:aws:logs:*:*:log-group:/aws-glue/*/*:*"]
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
  }
}