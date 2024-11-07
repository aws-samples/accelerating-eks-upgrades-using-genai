import os
import boto3
import json
import logging
from botocore.exceptions import ClientError

# Constants
SQS_QUEUE_URL = os.environ['SQS_QUEUE_URL']  
REGION = os.environ.get('REGION')
TAGS_CHECK_ENABLED = os.environ.get('TAGS_CHECK_ENABLED', 'True').lower() == 'true'
TAGS_TO_CHECK = os.environ['TAGS_TO_CHECK']
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']
GLUE_JOB_ROLE_ARN = os.environ['EKS_INSIGHTS_GLUE_JOB_ROLE_ARN']
CROSS_ACCOUNT_ROLE_NAME = os.environ['CROSS_ACCOUNT_ROLE_NAME']

# Clients 
sqs_client = boto3.client('sqs')
eks_client = boto3.client('eks')
sns_client = boto3.client('sns')

# Logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def check_eks_tags(eks_client, cluster_name, tag_key, tag_value):
    """Checks if cluster has required tags"""
    try:
        response = eks_client.describe_cluster(name=cluster_name)
        tags = response['cluster']['tags'] 
        return tags.get(tag_key) == tag_value
    except ClientError:
        logger.exception(f"Error checking tags for cluster {cluster_name}")
        return False

def send_sqs_message(cluster, account_id, region):
    """Sends cluster details to SQS queue"""
    message_body = json.dumps({
        "account_id": account_id, 
        "cluster_name": cluster,
        "region": region
    })

    sqs_client.send_message(
        QueueUrl=SQS_QUEUE_URL, 
        MessageBody=message_body
    )
    logger.info(f"Sent SQS message: {message_body}")

def send_notification(clusters_with_access_and_tags, clusters_missing_access_or_tags):
    """Sends notification SNS message"""
    if not clusters_with_access_and_tags:
        clusters_with_access_and_tags.append('None')

    if not clusters_missing_access_or_tags:
        clusters_missing_access_or_tags.append('None')

    message = f"**Clusters with access and tags- Upgrade Insights generation kicked off for the below:** {', '.join(clusters_with_access_and_tags)} \n\n" 
    message += f"**Clusters missing access or tags:** {', '.join(clusters_missing_access_or_tags)}"
    
    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN, 
            Message=message,
            Subject='EKS Upgrades Insights- Cluster Access and Tag Report'
        )
        logger.info(f"Sent SNS notification: {message}")
    except Exception as e:
        logger.exception("Error publishing SNS message: %s", e)

def lambda_handler(event, context):
    master_session = boto3.session.Session()
    sts_client = master_session.client('sts')  
    account_id = sts_client.get_caller_identity()['Account']
    region = master_session.region_name

    clusters_with_access_and_tags = []
    clusters_missing_access_or_tags = []
    
    eks_client = boto3.client('eks', region_name=region)  
    clusters = eks_client.list_clusters()['clusters']

    for cluster in clusters:
        has_access = False
        has_tags = False
        
        if TAGS_CHECK_ENABLED:
            tag_key, tag_value = TAGS_TO_CHECK.split(':')  
            has_tags = check_eks_tags(eks_client, cluster, tag_key, tag_value)
        
        try:
            access_entries = eks_client.list_access_entries(clusterName=cluster)['accessEntries']
            # has_access = GLUE_JOB_ROLE_ARN in access_entries
            has_access = f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE_NAME}" in access_entries
        except ClientError as e:
            logger.warning(f"Unable to list access entries for {cluster}: {e}")
        
        if has_access and has_tags:
            clusters_with_access_and_tags.append(f'\n Account: {account_id}- Region: {region}- Cluster: {cluster}')
            send_sqs_message(cluster, account_id, region) 
        else:
            clusters_missing_access_or_tags.append(f'\n Account: {account_id}- Region: {region}- Cluster: {cluster}')

    send_notification(clusters_with_access_and_tags, clusters_missing_access_or_tags)
    
    return {
        'statusCode': 200,
        'body': 'EKS cluster scanning completed successfully'
    }
