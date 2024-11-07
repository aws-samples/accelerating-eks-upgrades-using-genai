variable "aws_default_region" {
  type        = string
  description = "The region where the components are to be deployed"
}

variable "customer_name" {
  type        = string
  description = "The name of customer or team"
}

variable "solution_regions" {
  type        = list(string)
  description = "The region where the solution should scan for EKS clusters"
}

variable "deploy_quicksight_dashboard" {
  type        = bool
  description = "Boolean flag indicating whether the EKS Organization QuickSight should be deployed or not"
}

variable "bedrock_model" {
  type        = string
  description = "Amazon Bedrock model used for insights generation"
}

variable "bedrock_region" {
  type        = string
  description = "Region for the Bedrock model"
}

variable "eks_scan_tag_enabled" {
  type        = bool
  description = "Boolean flag indicating whether EKS clusters should be scanned based on tag"
}

variable "eks_scan_tag_key_value" {
  type        = string
  description = "Tag key:value to check if `eks_scan_tag_enabled` variable is set to true"
}

variable "eks_dashboard_qs_region" {
  type        = string
  description = "Region where the EKS Organization dashboard should be deployed"
}

variable "eks_org_data_glue_version" {
  type        = string
  description = "Glue version to use for the EKS Organization data jobs"
}

variable "eks_org_data_glue_python_version" {
  type        = string
  description = "Glue Python version to use for the EKS Organization data jobs"
}

variable "quicksight_access_group_name" {
  type        = string
  description = "Access group name for QuickSight dashboard"
}
variable "quicksight_access_group_membership" {
  type        = list(any)
  description = "Membership access level for the QuickSight access group"
}

variable "quicksight_dashboard_access_actions" {
  type        = string
  description = "Dashboard access actions for the QuickSight group"
}

variable "quicksight_datasets" {
  description = "Datasets definition for EKS Organization QuickSight dashboard"
  type = map(object({
    import_mode = string
    input_columns = list(object({
      name = string
      type = string
    }))
    upload_settings_format = string
    logical_table_map = object({
      cast_columns = list(object({
        column_name     = string
        new_column_type = string
      }))
      rename_columns = list(object({
        column_name     = string
        new_column_name = string
      }))
      geo_columns = list(object({
        column_name     = string
        geographic_role = string
      }))
    })
  }))
}

variable "sns_email" {
  type        = list(any)
  description = "Email list for SNS notifications"
}

variable "cross_accounts_role" {
  type        = string
  description = "Role that has to be assumed on Spoke accounts with access to EKS clusters- role should also be able to assume EKS context"
}