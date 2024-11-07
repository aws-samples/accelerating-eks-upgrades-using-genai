resource "aws_s3_object" "eks_insights_script" {
  bucket = aws_s3_bucket.org_data_bucket.id
  key    = "glue-scripts/eks_generate_insights.py"
  acl    = "private"
  source = "${path.module}/scripts/eks_generate_insights.py"
  etag   = filemd5("${path.module}/scripts/eks_generate_insights.py")
}

resource "aws_glue_job" "eks_org_data_glue_job" {
  # checkov:skip=CKV_AWS_195: The Glue job does not use any data stores
  name         = "${var.customer_name}-eks-generate-insights"
  role_arn     = aws_iam_role.eks_insights_glue_role.arn
  glue_version = var.eks_org_data_glue_version

  #   security_configuration = aws_glue_security_configuration.eks_insights_glue_sec_config.name
  execution_property {
    max_concurrent_runs = 250
  }

  command {
    name            = "pythonshell"
    script_location = "s3://${aws_s3_bucket.org_data_bucket.id}/glue-scripts/eks_generate_insights.py"
    python_version  = var.eks_org_data_glue_python_version
  }

  default_arguments = {
    "--enable-job-insights"              = "false"
    "--additional-python-modules"        = "boto3>=1.34.121,semver>=3.0.2,dictdiffer>=0.9.0,PyGithub>=2.3.0"
    "--enable-glue-datacatalog"          = "true"
    "--enable-continuous-cloudwatch-log" = "true"
    "--job-language"                     = "python"
    "--TempDir"                          = "s3://${aws_s3_bucket.org_data_bucket.id}/glue-scripts/temp_dir_for_glue_jobs/"
    "--CLUSTER_REGION"                   = ""
    "--CLUSTER_NAME"                     = ""
    "--ACCOUNT_ID"                       = ""
    "--SNS_TOPIC_ARN"                    = aws_sns_topic.eks_insights_topic.arn
    "--BEDROCK_MODEL"                    = var.bedrock_model
    "--OUTPUT_S3_BUCKET"                 = aws_s3_bucket.org_data_bucket.id
    "--BEDROCK_REGION"                   = var.bedrock_region
  }
  depends_on = [aws_iam_role.eks_insights_glue_role]
}