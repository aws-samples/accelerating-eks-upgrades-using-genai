# accelerating-eks-upgrades-using-genai

Upgrading EKS clusters faces several challenges, including identifying deprecated resources, high costs associated with the process, lack of expertise within teams, and potential security vulnerabilities due to delays in upgrades. This solution showcases a Generative AI approach developed using Amazon Bedrock to accelerate EKS upgrades. It analyzes deprecations using EKS Upgrade Insights, converts manifests to the target Kubernetes version, provides alternative suggestions for end-of-life resources, and generates pull requests with changelists segregating by team/component owners, grouping files based on API/Resource deprecation, and displaying source and target YAMLs with differences.

An Amazon QuickSight dashboard is also deployed that shows the EKS Clusters list at the Organization level, EKS clusters per region on every account, the cluster versions on every account, and also the current support status based on the official release calendar. You will also see metadata information about the cluster, including the Addon versions and a summary of Upgrade Insights for every cluster that includes deprecated APIs info, replacements, and corresponding client statistics that would show the user agent, last accessed date, and usage times in the last 30 days. The dashboard can also be integrated with Amazon Q to perform natural language queries on visuals and backend datasets.

Overall, the solution helps streamlining the upgrade process by addressing the identified challenges and providing a tool that can be integrated with customer environment for current and also future upgrades.

## Prerequisites

You should have the following:

* The Hub and Spoke accounts model with AWS Identity and Access Management (IAM) permissions allows the creation of Lambda functions, SQS queues, Glue jobs, SNS topics, Amazon Simple Storage Service (Amazon S3) buckets, EventBridge rules, and necessary cross-account IAM roles. These roles provide permissions on the Spoke accounts' components to scan the Amazon Elastic Kubernetes Service (Amazon EKS) clusters and assume their context to download Kubernetes manifests.
* The deployment role should have cross-account assume permissions on the Spoke accounts, and the assumed role should have access to the EKS clusters, including the ability to retrieve manifests and assume the required context. 
* Access to Amazon Bedrock models. For more information, refer to [Model access](https://docs.aws.amazon.com/bedrock/latest/userguide/model-access.html). We are using the Bedrock Anthropic Claude-3 (Sonnet) model by default as the preferred and recommended option. However, it is customizable if you prefer choosing different models within Bedrock.


<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | ~> 1.3 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 5.50.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_archive"></a> [archive](#provider\_archive) | n/a |
| <a name="provider_aws"></a> [aws](#provider\_aws) | ~> 5.50.0 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_eks_quicksight_dashboard"></a> [eks\_quicksight\_dashboard](#module\_eks\_quicksight\_dashboard) | ./modules/eks-quicksight-dashboard | n/a |

## Sample cross-account role creation

```
resource "aws_iam_role" "cross_account_role" {
  name               = "terraform-deployment-role"
  assume_role_policy = data.aws_iam_policy_document.cross_account_role_trust_policy.json
}

# Define the trust policy for the role
data "aws_iam_policy_document" "cross_account_role_trust_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::<ACCOUNT_ID>:root"] # Replace <ACCOUNT_ID> with the account ID you want to grant access to
    }
  }
}

# Attach the AdministratorAccess policy to the role
resource "aws_iam_role_policy_attachment" "cross_account_role_policy_attachment" {
  role       = aws_iam_role.cross_account_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
```

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_event_rule.daily_lambda_trigger](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_target.lambda_target](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_glue_job.eks_org_data_glue_job](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/glue_job) | resource |
| [aws_iam_policy.cross_account_assume_role_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.eks_insights_role_access_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.lambda_role_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_role.eks_insights_glue_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.lambda_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy_attachment.eks_insights_s3_access_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.glue_role_assume_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.lambda_role_assume_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.lambda_role_policy_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_kms_alias.eks_insights_kms_alias](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_alias) | resource |
| [aws_kms_key.eks_insights_kms](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [aws_lambda_event_source_mapping.sqs_glue_mapping](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_event_source_mapping) | resource |
| [aws_lambda_function.eks_cluster_scanner](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.glue_job_trigger_lambda](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_permission.allow_cloudwatch](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_s3_bucket.org_data_bucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket_public_access_block.org_data_bucket_public_access_block](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block) | resource |
| [aws_s3_bucket_server_side_encryption_configuration.org_data_bucket_sse](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration) | resource |
| [aws_s3_object.eks_insights_script](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_object) | resource |
| [aws_sns_topic.eks_insights_topic](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic) | resource |
| [aws_sns_topic_subscription.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_subscription) | resource |
| [aws_sqs_queue.eks_cluster_queue](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue) | resource |
| [aws_sqs_queue.eks_cluster_queue_deadletter](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue) | resource |
| [archive_file.eks_clusters_scanner_lambda_zip](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.trigger_glue_job_lambda_zip](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.cross_account_role_assume](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.eks_insights_role_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.glue_assume](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.kms_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.lambda_role_policy_document](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_organizations_organization.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/organizations_organization) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_aws_default_region"></a> [aws\_default\_region](#input\_aws\_default\_region) | The region where the components are to be deployed | `string` | n/a | yes |
| <a name="input_bedrock_model"></a> [bedrock\_model](#input\_bedrock\_model) | Amazon Bedrock model used for insights generation | `string` | n/a | yes |
| <a name="input_bedrock_region"></a> [bedrock\_region](#input\_bedrock\_region) | Region for the Bedrock model | `string` | n/a | yes |
| <a name="input_cross_accounts_role"></a> [cross\_accounts\_role](#input\_cross\_accounts\_role) | Role that has to be assumed on Spoke accounts with access to EKS clusters- role should also be able to assume EKS context | `string` | n/a | yes |
| <a name="input_customer_name"></a> [customer\_name](#input\_customer\_name) | The name of customer or team | `string` | n/a | yes |
| <a name="input_deploy_quicksight_dashboard"></a> [deploy\_quicksight\_dashboard](#input\_deploy\_quicksight\_dashboard) | Boolean flag indicating whether the EKS Organization QuickSight should be deployed or not | `bool` | n/a | yes |
| <a name="input_eks_dashboard_qs_region"></a> [eks\_dashboard\_qs\_region](#input\_eks\_dashboard\_qs\_region) | Region where the EKS Organization dashboard should be deployed | `string` | n/a | yes |
| <a name="input_eks_insights_glue_sec_config"></a> [eks\_insights\_glue\_sec\_config](#input\_eks\_insights\_glue\_sec\_config) | Security configuration for Glue job | `string` | n/a | yes |
| <a name="input_eks_org_data_glue_python_version"></a> [eks\_org\_data\_glue\_python\_version](#input\_eks\_org\_data\_glue\_python\_version) | Glue Python version to use for the EKS Organization data jobs | `string` | n/a | yes |
| <a name="input_eks_org_data_glue_version"></a> [eks\_org\_data\_glue\_version](#input\_eks\_org\_data\_glue\_version) | Glue version to use for the EKS Organization data jobs | `string` | n/a | yes |
| <a name="input_eks_scan_tag_enabled"></a> [eks\_scan\_tag\_enabled](#input\_eks\_scan\_tag\_enabled) | Boolean flag indicating whether EKS clusters should be scanned based on tag | `bool` | n/a | yes |
| <a name="input_eks_scan_tag_key_value"></a> [eks\_scan\_tag\_key\_value](#input\_eks\_scan\_tag\_key\_value) | Tag key:value to check if `eks_scan_tag_enabled` variable is set to true | `string` | n/a | yes |
| <a name="input_quicksight_access_group_membership"></a> [quicksight\_access\_group\_membership](#input\_quicksight\_access\_group\_membership) | Membership access level for the QuickSight access group | `list(any)` | n/a | yes |
| <a name="input_quicksight_access_group_name"></a> [quicksight\_access\_group\_name](#input\_quicksight\_access\_group\_name) | Access group name for QuickSight dashboard | `string` | n/a | yes |
| <a name="input_quicksight_dashboard_access_actions"></a> [quicksight\_dashboard\_access\_actions](#input\_quicksight\_dashboard\_access\_actions) | Dashboard access actions for the QuickSight group | `string` | n/a | yes |
| <a name="input_quicksight_datasets"></a> [quicksight\_datasets](#input\_quicksight\_datasets) | Datasets definition for EKS Organization QuickSight dashboard | <pre>map(object({<br>    import_mode = string<br>    input_columns = list(object({<br>      name = string<br>      type = string<br>    }))<br>    upload_settings_format = string<br>    logical_table_map = object({<br>      cast_columns = list(object({<br>        column_name     = string<br>        new_column_type = string<br>      }))<br>      rename_columns = list(object({<br>        column_name     = string<br>        new_column_name = string<br>      }))<br>      geo_columns = list(object({<br>        column_name     = string<br>        geographic_role = string<br>      }))<br>    })<br>  }))</pre> | n/a | yes |
| <a name="input_sns_email"></a> [sns\_email](#input\_sns\_email) | Email list for SNS notifications | `list(any)` | n/a | yes |
| <a name="input_solution_regions"></a> [solution\_regions](#input\_solution\_regions) | The region where the solution should scan for EKS clusters | `list(string)` | n/a | yes |

<!-- END_TF_DOCS -->