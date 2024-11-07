customer_name                       = "aws-eks-upgrades-accelerator"
aws_default_region                  = "us-west-2"
solution_regions                    = ["us-east-1", "us-west-2", "eu-west-2"]
cross_accounts_role                 = "terraform-deployment-role"
deploy_quicksight_dashboard         = true
bedrock_model                       = "anthropic.claude-3-5-sonnet-20240620-v1:0"
bedrock_region                      = "us-west-2"
eks_scan_tag_enabled                = true
eks_scan_tag_key_value              = "UpgradeCheckEnabled:True"
eks_dashboard_qs_region             = "us-west-2"
eks_org_data_glue_python_version    = "3.9"
eks_org_data_glue_version           = "3.0"
quicksight_access_group_name        = "eks_dashboard_admins"
quicksight_access_group_membership  = ["user@domain.com"]
quicksight_dashboard_access_actions = "quicksight:DescribeDashboard,quicksight:ListDashboardVersions,quicksight:UpdateDashboardPermissions,quicksight:QueryDashboard,quicksight:UpdateDashboard,quicksight:DeleteDashboard,quicksight:UpdateDashboardPublishedVersion,quicksight:DescribeDashboardPermissions"
sns_email                           = ["user@domain.com"]

#Please do not modify quicksight_datasets unless you're making changes to default layout
quicksight_datasets = {
  eks-dashboard-clusters-data = {
    import_mode = "SPICE"
    input_columns = [
      {
        name = "Account Id"
        type = "STRING"
      },
      {
        name = "Region"
        type = "STRING"
      },
      {
        name = "Cluster Name"
        type = "STRING"
      },
      {
        name = "Cluster Version"
        type = "STRING"
      },
      {
        name = "Latest Version"
        type = "STRING"
      },
      {
        name = "Versions Back"
        type = "STRING"
      }
    ]
    upload_settings_format = "JSON"
    logical_table_map = {
      cast_columns = [
        {
          column_name     = "Cluster Version"
          new_column_type = "DECIMAL"
        },
        {
          column_name     = "Latest Version"
          new_column_type = "DECIMAL"
        },
        {
          column_name     = "Versions Back"
          new_column_type = "INTEGER"
        }
      ]
      geo_columns = [{
        geographic_role = "STATE"
        column_name     = "Region"
      }]
      rename_columns = []
    }
  },
  eks-dashboard-clusters-details = {
    import_mode = "SPICE"
    input_columns = [
      {
        name = "Account Id"
        type = "STRING"
      },
      { name = "Region"
        type = "STRING"
      },
      {
        name = "Cluster Name"
        type = "STRING"
      },
      {
        name = "Cluster Version"
        type = "STRING"
      },
      {
        name = "aws-ebs-csi-driver"
        type = "STRING"
      },
      {
        name = "aws-efs-csi-driver"
        type = "STRING"
      },
      {
        name = "coredns"
        type = "STRING"
      },
      {
        name = "kube-proxy"
        type = "STRING"
      },
      {
        name = "vpc-cni"
        type = "STRING"
      }
    ]
    upload_settings_format = "JSON"
    logical_table_map = {
      cast_columns = [
        {
          column_name     = "Cluster Version"
          new_column_type = "DECIMAL"
        }
      ]
      geo_columns = [
        {
          geographic_role = "STATE"
          column_name     = "Region"
        }
      ]
      rename_columns = [
        {
          column_name     = "aws-ebs-csi-driver"
          new_column_name = "EBS CSI Driver"
        },
        {
          column_name     = "aws-efs-csi-driver"
          new_column_name = "EFS CSI Driver"
        },
        {
          column_name     = "coredns"
          new_column_name = "Core DNS"
        },
        {
          column_name     = "kube-proxy"
          new_column_name = "Kube Proxy"
        },
        {
          column_name     = "vpc-cni"
          new_column_name = "VPC CNI"
        }
      ]
    }
  },
  eks-dashboard-clusters-summary-data = {
    import_mode = "SPICE"
    input_columns = [
      {
        name = "Account Id"
        type = "STRING"
      },
      {
        name = "Region"
        type = "STRING"
      },
      {
        name = "Number of Clusters"
        type = "STRING"
      }
    ]
    upload_settings_format = "JSON"
    logical_table_map = {
      cast_columns = [
        {
          column_name     = "Number of Clusters"
          new_column_type = "INTEGER"
        }
      ]
      geo_columns = [{
        geographic_role = "STATE"
        column_name     = "Region"
      }]
      rename_columns = []
    }
  },
  eks-dashboard-support-data = {
    import_mode = "SPICE"
    input_columns = [
      {
        name = "Account Id"
        type = "STRING"
      },
      {
        name = "Region"
        type = "STRING"
      },
      {
        name = "Cluster Name"
        type = "STRING"
      },
      {
        name = "Cluster Version"
        type = "STRING"
      },
      {
        name = "EndOfSupportDate"
        type = "STRING"
      },
      {
        name = "EndOfExtendedSupportDate"
        type = "STRING"
      },
      {
        name = "Status"
        type = "STRING"
      },
      {
        name = "UpgradesReport"
        type = "STRING"
      }
    ]
    upload_settings_format = "JSON"
    logical_table_map = {
      cast_columns = [
        {
          column_name     = "Cluster Version"
          new_column_type = "DECIMAL"
        }
      ]
      geo_columns = [{
        geographic_role = "STATE"
        column_name     = "Region"
      }]
      rename_columns = [
        {
          column_name     = "EndOfSupportDate"
          new_column_name = "End Of Standard Support Date"
        },
        {
          column_name     = "EndOfExtendedSupportDate"
          new_column_name = "End Of Extended Support Date"
        },
        {
          column_name     = "Status"
          new_column_name = "Support Status"
        },
        {
          column_name     = "UpgradesReport"
          new_column_name = "Upgrades S3 Report"
        }
      ]
    }
  },
  eks-dashboard-kubernetes-release-calendar = {
    import_mode = "SPICE"
    input_columns = [
      {
        name = "Kubernetes version"
        type = "STRING"
      },
      {
        name = "Upstream release"
        type = "STRING"
      },
      {
        name = "Amazon EKS release"
        type = "STRING"
      },
      {
        name = "End of standard support"
        type = "STRING"
      },
      {
        name = "End of extended support"
        type = "STRING"
      },
      {
        name = "EndOfExtendedSupportDate"
        type = "STRING"
      }
    ]
    upload_settings_format = "JSON"
    logical_table_map = {
      cast_columns = [
        {
          column_name     = "Kubernetes version"
          new_column_type = "STRING"
        }
      ]
      geo_columns = []
      rename_columns = [{
        column_name     = "Kubernetes version"
        new_column_name = "Kubernetes Version"
      }]
    }
  },
  eks-dashboard-clusters-upgrade-insights = {
    import_mode = "SPICE"
    input_columns = [
      {
        name = "Account Id"
        type = "STRING"
      },
      {
        name = "Region"
        type = "STRING"
      },
      {
        name = "Cluster Name"
        type = "STRING"
      },
      {
        name = "Cluster Version"
        type = "STRING"
      },
      {
        name = "InsightId"
        type = "STRING"
      },
      {
        name = "Current API Usage"
        type = "STRING"
      },
      {
        name = "API Deprecated Version"
        type = "STRING"
      },
      {
        name = "API Replacement"
        type = "STRING"
      },
      {
        name = "User Agent"
        type = "STRING"
      },
      {
        name = "Number of Requests In Last 30Days"
        type = "STRING"
      },
      {
        name = "Last Request Time"
        type = "STRING"
      }
    ]
    upload_settings_format = "JSON"
    logical_table_map = {
      cast_columns = [
        {
          column_name     = "Cluster Version"
          new_column_type = "DECIMAL"
        },
        {
          column_name     = "API Deprecated Version"
          new_column_type = "DECIMAL"
        },
        {
          column_name     = "Number of Requests In Last 30Days"
          new_column_type = "INTEGER"
        }
      ]
      geo_columns = [{
        geographic_role = "STATE"
        column_name     = "Region"
      }]
      rename_columns = []
    }
  }
}