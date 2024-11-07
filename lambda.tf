# Create Lambda function archive
data "archive_file" "eks_clusters_scanner_lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/scripts/eks_clusters_scanner.py"
  output_path = "${path.module}/scripts/eks_clusters_scanner_lambda_function.zip"
}

# Create Lambda function
resource "aws_lambda_function" "eks_cluster_scanner" {
  # checkov:skip=CKV_AWS_272: No signing profiles required 
  # checkov:skip=CKV_AWS_117: Doesn't require VPC Connectivity
  filename                       = data.archive_file.eks_clusters_scanner_lambda_zip.output_path
  function_name                  = "${var.customer_name}-eks-clusters-scanner"
  role                           = aws_iam_role.lambda_role.arn
  handler                        = "eks_clusters_scanner.lambda_handler"
  runtime                        = "python3.9"
  timeout                        = 900
  memory_size                    = 512
  source_code_hash               = data.archive_file.eks_clusters_scanner_lambda_zip.output_base64sha256
  reserved_concurrent_executions = 3
  kms_key_arn                    = aws_kms_key.eks_insights_kms.arn

  tracing_config {
    mode = "Active"
  }
  dead_letter_config {
    target_arn = aws_sns_topic.eks_insights_topic.arn
  }
  environment {
    variables = {
      SQS_QUEUE_URL                  = aws_sqs_queue.eks_cluster_queue.id
      REGION                        = var.aws_default_region
      TAGS_CHECK_ENABLED             = var.eks_scan_tag_enabled
      TAGS_TO_CHECK                  = var.eks_scan_tag_key_value
      SNS_TOPIC_ARN                  = aws_sns_topic.eks_insights_topic.arn
      EKS_INSIGHTS_GLUE_JOB_ROLE_ARN = aws_iam_role.eks_insights_glue_role.arn
    }
  }
  depends_on = [aws_sqs_queue.eks_cluster_queue]
}

data "archive_file" "trigger_glue_job_lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/scripts/trigger_glue_job.py"
  output_path = "${path.module}/scripts/trigger_glue_job_lambda_function.zip"
}

# Create a Lambda function
resource "aws_lambda_function" "glue_job_trigger_lambda" {
  # checkov:skip=CKV_AWS_272: No signing profiles required
  # checkov:skip=CKV_AWS_117: Doesn't require VPC Connectivity
  filename                       = data.archive_file.trigger_glue_job_lambda_zip.output_path
  function_name                  = "${var.customer_name}-trigger-eks-insights-glue"
  role                           = aws_iam_role.lambda_role.arn
  handler                        = "trigger_glue_job.lambda_handler"
  runtime                        = "python3.9"
  source_code_hash               = data.archive_file.trigger_glue_job_lambda_zip.output_base64sha256
  reserved_concurrent_executions = 3
  kms_key_arn                    = aws_kms_key.eks_insights_kms.arn

  tracing_config {
    mode = "Active"
  }
  dead_letter_config {
    target_arn = aws_sns_topic.eks_insights_topic.arn
  }
  environment {
    variables = {
      EKS_INSIGHTS_GLUE_JOB = aws_glue_job.eks_org_data_glue_job.name
    }
  }
}

# Create an event source mapping between the SQS queue and the Lambda function
resource "aws_lambda_event_source_mapping" "sqs_glue_mapping" {
  event_source_arn = aws_sqs_queue.eks_cluster_queue.arn
  function_name    = aws_lambda_function.glue_job_trigger_lambda.arn
  batch_size       = 1 # Process one message at a time
  enabled          = true
}


# Define the EventBridge rule to trigger the Lambda function
resource "aws_cloudwatch_event_rule" "daily_lambda_trigger" {
  name                = "${var.customer_name}-eks-insights-lambda-trigger"
  description         = "Trigger Lambda function every day at 21:00 UTC"
  schedule_expression = "cron(0 21 * * ? *)"
}

# Define the EventBridge target to invoke the Lambda function
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.daily_lambda_trigger.name
  arn       = aws_lambda_function.eks_cluster_scanner.arn
  target_id = "${var.customer_name}-eks-insights-lambda-target"
}

# Grant the EventBridge service permission to invoke the Lambda function
resource "aws_lambda_permission" "allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.eks_cluster_scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_lambda_trigger.arn
}