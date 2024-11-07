resource "aws_sqs_queue" "eks_cluster_queue" {
  name                              = "${var.customer_name}-eks-insights"
  kms_master_key_id                 = aws_kms_key.eks_insights_kms.key_id
  kms_data_key_reuse_period_seconds = 300

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.eks_cluster_queue_deadletter.arn
    maxReceiveCount     = 5
  })
}

# Create a dead-letter queue for the main queue
resource "aws_sqs_queue" "eks_cluster_queue_deadletter" {
  name                              = "${var.customer_name}-eks-insights-dlq"
  kms_master_key_id                 = aws_kms_key.eks_insights_kms.key_id
  kms_data_key_reuse_period_seconds = 300
}