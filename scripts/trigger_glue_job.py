import os
import json
import boto3
from botocore.exceptions import ClientError
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

GLUE_JOB_NAME = os.getenv('EKS_INSIGHTS_GLUE_JOB')
glue_client = boto3.client('glue')

def trigger_glue_job(account_id, cluster_name, cluster_region):
    try:
        glue_client.start_job_run(
            JobName=GLUE_JOB_NAME,
            Arguments={
                '--ACCOUNT_ID': account_id, 
                '--CLUSTER_NAME': cluster_name,
                '--CLUSTER_REGION': cluster_region
            }
        )
        logger.info(f"Triggered Glue job: {GLUE_JOB_NAME}")
    except ClientError as e:
        logger.error(f"Error triggering Glue job: {e}")
        
def process_record(record):
    message_body = record['body']
    message_data = json.loads(message_body)
    logger.info(f"Received message: {message_body}")

    account_id = message_data['account_id']
    cluster_name = message_data['cluster_name'] 
    cluster_region = message_data['region']
    
    trigger_glue_job(account_id, cluster_name, cluster_region)

def lambda_handler(event, context):
    records = event['Records']

    for record in records:
        process_record(record)

    return {
        'statusCode': 200,
        'body': json.dumps('SQS messages processed successfully')
    }
