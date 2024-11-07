# SNS topic
resource "aws_sns_topic" "eks_insights_topic" {
  name              = "${var.customer_name}-eks-insights"
  kms_master_key_id = aws_kms_key.eks_insights_kms.key_id
}

resource "aws_sns_topic_subscription" "this" {
  count     = length(var.sns_email)
  topic_arn = aws_sns_topic.eks_insights_topic.arn
  protocol  = "email"
  endpoint  = var.sns_email[count.index]
}