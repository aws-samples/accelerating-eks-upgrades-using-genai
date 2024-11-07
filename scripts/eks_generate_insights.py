import os
import json
import logging
import subprocess  # nosec
import shlex
import shutil
import semver
import sys
import yaml
import boto3
import time
import pip
from collections import defaultdict
from dictdiffer import diff
from github import Github
from datetime import datetime
from botocore.exceptions import ClientError
from collections import defaultdict
from awsglue.utils import getResolvedOptions

logger = logging.getLogger("get_eks_manifests_insights")
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()

logger.addHandler(console_handler)

args = getResolvedOptions(
    sys.argv,
    [
        "CLUSTER_REGION",
        "CLUSTER_NAME",
        "ACCOUNT_ID",
        "BEDROCK_REGION",
        "BEDROCK_MODEL",
        "OUTPUT_S3_BUCKET",
        "CROSS_ACCOUNT_ROLE_NAME",
        "SNS_TOPIC_ARN",
    ],
)

CLUSTER_REGION = args["CLUSTER_REGION"]
CLUSTER_NAME = args["CLUSTER_NAME"]
ACCOUNT_ID = args["ACCOUNT_ID"]
BEDROCK_REGION = args["BEDROCK_REGION"]
BEDROCK_MODEL = args["BEDROCK_MODEL"]
OUTPUT_S3_BUCKET = args["OUTPUT_S3_BUCKET"]
CROSS_ACCOUNT_ROLE_NAME = args["CROSS_ACCOUNT_ROLE_NAME"]
SNS_TOPIC_ARN = args["SNS_TOPIC_ARN"]


def parse_list_param(param) -> list:
    if not param:
        return []
    if "," not in param:
        return [param]
    return param.split(",")


def parse_string_to_list(input_string, delimiter) -> list:
    if not delimiter:
        return [input_string]
    return [item.strip() for item in input_string.split(delimiter) if item]


def get_current_eks_version(
    eks_client, cluster_region, eks_cluster_name, current_account_id
) -> str:
    
    response = eks_client.describe_cluster(name=eks_cluster_name)
    eks_client.close()
    return response.get("cluster").get("version")


def get_latest_eks_version(eks_client) -> str:
    response = eks_client.describe_addon_versions()
    cluster_versions = set()
    for addon in response.get("addons"):
        for version_info in addon["addonVersions"]:
            for compatibility in version_info["compatibilities"]:
                cluster_versions.add(compatibility["clusterVersion"])
    return sorted(cluster_versions)[-1]


def check_dict_for_key(dict, key):
    if key in dict:
        return dict[key]
    else:
        return False


def get_upgrade_insights(
    eks_client, eks_cluster_name, target_version
) -> list:
    upgrade_insights = []
    max_results = 10
    response = eks_client.list_insights(
        clusterName=eks_cluster_name,
        filter={
            "categories": ["UPGRADE_READINESS"],
            "kubernetesVersions": [str(target_version)],
            "statuses": ['WARNING', 'ERROR', 'UNKNOWN'],
        },
        maxResults=max_results,
    )
    next_token = response.get("nextToken")
    upgrade_insights.extend(response.get("insights"))
    while next_token:
        response = eks_client.list_insights(
            maxResults=max_results, nextToken=next_token
        )
        upgrade_insights.extend(response.get("insights"))
        next_token = response.get("nextToken")

    return upgrade_insights


def set_kubeconfig(cluster, region) -> None:
    try:
        subprocess.check_call(
            [
                "aws",
                "eks",
                "update-kubeconfig",
                "--name",
                cluster,
                "--region",
                region,
                "--kubeconfig",
                "/tmp/kube-config/config",
            ],
            stdout=subprocess.DEVNULL,
        )  # nosec
        kubeconfig_path = os.path.expanduser("/tmp/kube-config/config")
        os.environ["KUBECONFIG"] = kubeconfig_path
    except subprocess.CalledProcessError as e:
        logger.error(f"Error setting KUBECONFIG: {e}")


def get_namespaced_api_resources(cluster, region) -> list:
    set_kubeconfig(cluster, region)
    # The command is defined as a list of strings (`command_parts`), which is safer than constructing a command string dynamically.
    command_parts = ["/tmp/kubectl/kubectl", "--kubeconfig", "/tmp/kube-config/config", "api-resources", "--namespaced=true", "-o", "name"]
    # Each part of the command is quoted using `shlex.quote` to escape any special characters that could be used for code injection attacks.
    # The quoted command parts are passed directly to `subprocess.run` as a list, avoiding the need for `shlex.split`.
    # nosemgrep: dangerous-subprocess-use-audit
    namespaced_resources = subprocess.run(
        [shlex.quote(part) for part in command_parts],
        stderr=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        text=True,
        check=False,
    )
    if namespaced_resources.returncode == 0:
        api_resources = [
            api.split(".")[0] for api in namespaced_resources.stdout.strip().split("\n")
        ]
        return api_resources
    return []


def get_non_namespaced_api_resources(cluster, region) -> list:
    set_kubeconfig(cluster, region)
    # The command is defined as a list of strings (`command_parts`), which is safer than constructing a command string dynamically.
    command_parts = ["/tmp/kubectl/kubectl", "--kubeconfig", "/tmp/kube-config/config", "api-resources", "--namespaced=false", "-o", "name"]
    # Each part of the command is quoted using `shlex.quote` to escape any special characters that could be used for code injection attacks.
    # The quoted command parts are passed directly to `subprocess.run` as a list, avoiding the need for `shlex.split`.
    # nosemgrep: dangerous-subprocess-use-audit
    non_namespaced_resources = subprocess.run(
        [shlex.quote(part) for part in command_parts],
        stderr=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        text=True,
        check=False,
    )
    if non_namespaced_resources.returncode == 0:
        api_resources = [
            api.split(".")[0]
            for api in non_namespaced_resources.stdout.strip().split("\n")
        ]
        return api_resources
    return []


def get_resources(cluster, region, resource_kind, namespaced=None) -> dict:
    resources: dict = {}
    set_kubeconfig(cluster, region)
    # The command is defined as a list of strings (`command_parts`), which is safer than constructing a command string dynamically.
    if namespaced:
        command_parts = ["/tmp/kubectl/kubectl", "--kubeconfig", "/tmp/kube-config/config", "get", f"{resource_kind}", "--all-namespaces", "-o", "json"]
    else:
        command_parts = ["/tmp/kubectl/kubectl", "--kubeconfig", "/tmp/kube-config/config", "get", f"{resource_kind}", "-o", "json"]
    # Each part of the command is quoted using `shlex.quote` to escape any special characters that could be used for code injection attacks.
    # The quoted command parts are passed directly to `subprocess.run` as a list, avoiding the need for `shlex.split`.
    # nosemgrep: dangerous-subprocess-use-audit
    response = subprocess.run(
        [shlex.quote(part) for part in command_parts],
        stderr=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        text=True,
        check=False,
    )
    if response.returncode == 0:
        resources_raw = json.loads(response.stdout)
        for item in resources_raw.get("items"):
            if "namespace" not in item["metadata"].keys():
                namespace = "non-namespaced"
            else:
                namespace = item.get("metadata").get("namespace")
            if namespace not in resources:
                resources[namespace] = []
            resources[namespace].append(item.get("metadata").get("name"))
        return resources
    return {}


def get_manifest(cluster, region, kind, api_version, res_name, namespace=None) -> dict:
    set_kubeconfig(cluster, region)
    # The command is defined as a list of strings (`command_parts`), which is safer than constructing a command string dynamically.
    if namespace:
        command_parts = ["/tmp/kubectl/kubectl", "--kubeconfig", "/tmp/kube-config/config", "get", f"{kind}.{api_version}", "-n", f"{namespace}", f"{res_name}", "-o", "json"]
    else:
        command_parts = ["/tmp/kubectl/kubectl", "--kubeconfig", "/tmp/kube-config/config", "get", f"{kind}.{api_version}", f"{res_name}", "-o", "json"]
    # Each part of the command is quoted using `shlex.quote` to escape any special characters that could be used for code injection attacks.
    # The quoted command parts are passed directly to `subprocess.run` as a list, avoiding the need for `shlex.split`.
    # nosemgrep: dangerous-subprocess-use-audit
    manifest = subprocess.run(
        [shlex.quote(part) for part in command_parts],
        stderr=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        text=True,
        check=False,
    )
    if manifest.returncode == 0:
        return json.loads(manifest.stdout)
    return {}


def copy_file_to_s3(source_path, bucket_name):
    s3_client = boto3.client("s3")

    if source_path.startswith("./"):
        destination_key = source_path[2:]

    try:
        s3_client.upload_file(source_path, bucket_name, destination_key)
        logger.info(
            f"File '{source_path}' uploaded to '{bucket_name}/{destination_key}'"
        )
    except ClientError as e:
        logger.error(f"Error uploading file: {e}")


def export_manifest(output_s3_bucket, path, manifest: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(manifest, f)
    f.close()
    logger.info(f"Manifest exported to {path}")

    copy_file_to_s3(path, output_s3_bucket)


def kubectl_convert(manifest_path, target_api_version) -> dict:
    # The command is defined as a list of strings (`command_parts`), which is safer than constructing a command string dynamically.
    command_parts = ["/tmp/kubectl-convert/kubectl-convert", "-f", f"{manifest_path}", "-o", "json", "--output-version", f"{target_api_version}"] 
    try:
        # Each part of the command is quoted using `shlex.quote` to escape any special characters that could be used for code injection attacks.
        # The quoted command parts are passed directly to `subprocess.run` as a list, avoiding the need for `shlex.split`.
        # nosemgrep: dangerous-subprocess-use-audit
        new_manifest = subprocess.run(
            [shlex.quote(part) for part in command_parts],
            stderr=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
            check=False,
        )
        logger.info(f"Success executing kubectl convert: {new_manifest}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing kubectl convert: {e.output}")

    if new_manifest.returncode == 0:
        return json.loads(new_manifest.stdout)
    return {}


def invoke_bedrock_model(prompt, br_region, br_model):
    max_retries = 3
    retry_count = 0
    response = None
    bedrock_client = boto3.client("bedrock-runtime", region_name=br_region)
    body = {
        "messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}],
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 4000,
    }
    accept = "application/json"
    contentType = "application/json"

    while retry_count < max_retries:
        try:
            # Invoke the Bedrock model
            response = bedrock_client.invoke_model(
                body=json.dumps(body), modelId=br_model, accept=accept, contentType=contentType
            )
            break  # Exit the loop if the model is invoked successfully
        except bedrock_client.exceptions.InternalServiceException as e:
            if 'Timeout' in str(e):
                logger.error(f"Timeout occurred. Retrying... (Attempt {retry_count + 1})")
                retry_count += 1
                # Intentional delay of 15 seconds to retry invoking Bedrock model after a brief pause
                # nosemgrep: arbitrary-sleep
                time.sleep(15)
            else:
                raise e  # Raise the exception if it's not a timeout error
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            break  # Exit the loop if an unhandled exception occurs

    if response:
        response_body = json.loads(response.get("body").read())
        return response_body.get("content")[0]["text"]
    else:
        logger.error("Failed to invoke the Bedrock model after maximum retries.")
        raise Exception("Failed to invoke the Bedrock model after maximum retries.")


def get_bedrock_suggestions(
    br_region, br_model, manifest, target_version, api_status, new_api_version=None
) -> str:
    api_version = manifest.get("apiVersion")
    resource_kind = manifest.get("kind")

    if api_status == "removed":
        input_prompt = (
            f"\n\nHuman: Can you try creating {resource_kind} using API group {api_version} on Kubernetes "
            f"{target_version}. If it fails, find alternate solutions and generate YAML for {resource_kind} that works on Kubernetes {target_version} "
            f"\n\nAssistant:"
        )
        return invoke_bedrock_model(input_prompt, br_region, br_model)
    if api_status == "deprecated":
        input_prompt = (
            f"\n\nHuman: Can you try creating {resource_kind} using {new_api_version} on Kubernetes "
            f"{target_version} leveraging the manifest {manifest}. \n\nAssistant:"
        )
        return invoke_bedrock_model(input_prompt, br_region, br_model)
    return ""


def generate_markdown(
    eks_client,
    source_dir,
    target_dir,
    output_file,
    cluster,
    eks_region,
    current_version,
    target_version,
):
    source_files = get_yaml_files(source_dir)
    target_files = get_yaml_files(target_dir)

    with open(output_file, "a", encoding="utf-8") as f:
        f.write(
            f"# EKS Cluster Name: {cluster} \n ## Cluster Region: {eks_region} \n ## Current Version: {current_version} \n ## Target Version: {target_version}\n\n"
        )

        # Get the list of installed add-on
        addon_list = eks_client.list_addons(clusterName=cluster)["addons"]
        f.write("## Installed Add-ons in the cluster:\n\n")
        for addon_name in addon_list:
            # Get the details of installed add-on
            addon_details = eks_client.describe_addon(
                clusterName=cluster, addonName=addon_name
            )["addon"]
            f.write(f"  {addon_name}: {addon_details['addonVersion']}\n\n")

        f.write("## Compatible Add-on versions to be used for target version:\n\n")
        for addon_name in addon_list:
            get_addon_versions = eks_client.describe_addon_versions(
                kubernetesVersion=target_version, addonName=addon_name
            )
            # Get the list of add-on versions
            addon_versions = get_addon_versions["addons"]
            latest_version = None
            default_version = None

            # Find the latest and default version
            for addon in addon_versions:
                addon_version = addon["addonVersions"]
                if not latest_version:
                    latest_version = addon_version[0]

                for version in addon_version:
                    for compatibility in version["compatibilities"]:
                        if compatibility["defaultVersion"]:
                            default_version = version
                            break

            f.write(
                f"  {addon_name}: {latest_version['addonVersion']} (Latest) - {default_version['addonVersion']} (Default) \n\n"
            )

        diff_groups = group_api_differences(source_dir, target_dir)

        for diff_key, file_pairs in diff_groups.items():
            source_apiVersion, source_kind, target_apiVersion, target_kind = diff_key
            f.write("## API Version/Resource deprecation:\n\n")
            f.write("<details>\n")
            f.write(
                f"<summary><b> Current usage: {source_apiVersion}/{source_kind} -> Replaced with: {target_apiVersion}/{target_kind}</b></summary>\n\n"
            )
            for source_path, target_path in file_pairs:
                f.write("___\n\n<b>Source:</b> ")
                f.write(f"s3://{OUTPUT_S3_BUCKET}/ekscelerator-insights{source_path[1:]}\n")
                f.write("\n<b>Target:</b> ")
                f.write(f"s3://{OUTPUT_S3_BUCKET}/ekscelerator-insights{target_path[1:]}\n")

            f.write("</details>\n\n")

        f.write("## Component YAML Files Comparison\n\n")
        f.write(f"## Source Directory: s3://{OUTPUT_S3_BUCKET}/ekscelerator-insights{source_dir[1:]}\n")
        f.write(f"## Target Directory: s3://{OUTPUT_S3_BUCKET}/ekscelerator-insights{target_dir[1:]}\n\n")

        f.write("## Files List\n\n")
        f.write("### Source Files:\n")
        for file in source_files:
            f.write(f"- s3://{OUTPUT_S3_BUCKET}/ekscelerator-insights{file[1:]}\n")
        f.write("\n### Target Files:\n")
        team_owner_results = defaultdict(list)
        no_team_owner_results = defaultdict(list)
        for file in target_files:
            with open(file, "r") as tgtFile:
                try:
                    data = yaml.safe_load(tgtFile)
                    metadata = data.get("metadata", {})
                    annotations = metadata.get("annotations", {})
                    labels = metadata.get("labels", {})
                    component_owner = (
                        annotations.get("component_owner")
                        if annotations.get("component_owner")
                        else labels.get("component_owner")
                    )
                    if component_owner:
                        team_owner_results[component_owner].append(file)
                    else:
                        no_team_owner_results["NoOwner"].append(file)
                except yaml.YAMLError as e:
                    logger.error(f"Error reading YAML file: {file}")
                    logger.error(e)
        if team_owner_results:
            for component_owner, files in team_owner_results.items():
                f.write(f"\n<b>Team/Owner: {component_owner}</b>\n")
                for file_path in files:
                    f.write(f"\ns3://{OUTPUT_S3_BUCKET}/ekscelerator-insights{file_path[1:]}\n")
        if no_team_owner_results:
            for component_owner, files in no_team_owner_results.items():
                f.write("\n<b>No Team/Owner found for the below components:</b>\n")
                for file_path in files:
                    f.write(f"\ns3://{OUTPUT_S3_BUCKET}/ekscelerator-insights{file_path[1:]}\n")

        f.write("\n## Differences\n\n")
        for source_file in source_files:
            helm_chart_name = check_yaml_for_helm_annotations(source_file)
            team_name = check_yaml_for_team_labels(source_file)
            target_file = os.path.join(
                target_dir, os.path.relpath(source_file, source_dir)
            )
            if target_file in target_files:
                diff = compare_yaml_files(source_file, target_file)
                if diff:
                    with open(source_file, "r", encoding="utf-8") as f1, open(
                        target_file, "r", encoding="utf-8"
                    ) as f2:
                        srcYAML = yaml.safe_load(f1)
                        tgtYAML = yaml.safe_load(f2)
                        f.write(f"### {os.path.relpath(source_file, source_dir)}\n\n")
                        if helm_chart_name:
                            f.write(
                                "This was deployed using the Helm chart {helm_chart_name}\n\n"
                            )
                        else:
                            f.write(
                                "This was probably deployed using a manifest source- no Helm chart source found\n\n"
                            )
                        if team_name:
                            f.write(
                                "The team or infra owner for this is {team_name}\n\n"
                            )
                        else:
                            f.write("No team or infra owner could be found\n\n")
                        f.write("<details>\n")
                        f.write("<summary>Click to view Source YAML</summary>\n\n")
                        f.write("```yaml\n")
                        f.write(yaml.dump(srcYAML, sort_keys=False))
                        f.write("\n```\n\n")
                        f.write("</details>\n\n")
                        f.write("<details>\n")
                        f.write("<summary>Click to view Target YAML</summary>\n\n")
                        f.write("```yaml\n")
                        f.write(yaml.dump(tgtYAML, sort_keys=False))
                        f.write("\n```\n\n")
                        f.write("</details>\n\n")
                        f.write("```diff\n")
                        f.write(diff)
                        f.write("\n```\n\n")

            else:
                f.write(f"### {os.path.relpath(source_file, source_dir)}\n\n")
                f.write(
                    "File not found in target directory. It is possibly a deprecated component, lookout for the suggestions file.\n\n"
                )


def get_yaml_files(directory):
    yaml_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".yaml") or file.endswith(".yml"):
                yaml_files.append(os.path.join(root, file))
    return yaml_files


def compare_yaml_files(source_file, target_file):
    with open(source_file, "r") as srcFile:
        data1 = srcFile.read()

    with open(target_file, "r") as tgtFile:
        data2 = tgtFile.read()

    data1_dict = yaml.load(data1, Loader=yaml.FullLoader)
    data2_dict = yaml.load(data2, Loader=yaml.FullLoader)

    if not data1_dict == data2_dict:
        return "\n".join(str(x) for x in list(diff(data1_dict, data2_dict)))


def check_yaml_for_helm_annotations(yaml_file):
    with open(yaml_file, "r") as file:
        try:
            yaml_data = yaml.safe_load(file)
        except yaml.YAMLError as exc:
            logger.error(f"Error loading YAML file: {exc}")
            return

    # Check for annotations
    annotations = yaml_data.get("metadata", {}).get("annotations", {})
    helm_release_name = annotations.get("meta.helm.sh/release-name")
    helm_chart_name = annotations.get("helm.sh/chart")

    # Check for labels
    labels = yaml_data.get("metadata", {}).get("labels", {})
    helm_release_name_label = labels.get("meta.helm.sh/release-name")
    helm_chart_name_label = labels.get("helm.sh/chart")

    if (
        helm_release_name
        or helm_chart_name
        or helm_release_name_label
        or helm_chart_name_label
    ):
        chart_name = (
            helm_chart_name
            or helm_chart_name_label
            or helm_release_name
            or helm_release_name_label
        )
        return chart_name
    else:
        return ""


def check_yaml_for_team_labels(yaml_file):
    with open(yaml_file, "r") as file:
        try:
            yaml_data = yaml.safe_load(file)
        except yaml.YAMLError as exc:
            logger.error(f"Error loading YAML file: {exc}")
            return

    # Check for annotations
    annotations = yaml_data.get("metadata", {}).get("annotations", {})
    component_owner_annotation = annotations.get("component_owner")
    infra_owner_annotation = annotations.get("infra_owner")

    # Check for labels
    labels = yaml_data.get("metadata", {}).get("labels", {})
    component_owner_label = labels.get("component_owner")
    infra_owner_label = labels.get("infra_owner")

    if (
        component_owner_annotation
        or infra_owner_annotation
        or component_owner_label
        or infra_owner_label
    ):
        owner_name = (
            infra_owner_annotation
            or component_owner_annotation
            or component_owner_label
            or infra_owner_label
        )
        return owner_name
    else:
        return ""


def group_api_differences(source_dir, target_dir):
    diff_groups = defaultdict(list)

    for root, dirs, files in os.walk(source_dir):
        for file in files:
            if file.endswith(".yaml"):
                source_path = os.path.join(root, file)
                relative_path = os.path.relpath(source_path, source_dir)
                target_path = os.path.join(target_dir, relative_path)

                if os.path.exists(target_path):
                    source_data = load_yaml(source_path)
                    target_data = load_yaml(target_path)

                    if source_data and target_data:
                        source_apiVersion = source_data.get("apiVersion", "")
                        source_kind = source_data.get("kind", "")
                        target_apiVersion = target_data.get("apiVersion", "")
                        target_kind = target_data.get("kind", "")

                        if (
                            source_apiVersion != target_apiVersion
                            or source_kind != target_kind
                        ):
                            diff_key = (
                                source_apiVersion,
                                source_kind,
                                target_apiVersion,
                                target_kind,
                            )
                            diff_groups[diff_key].append((source_path, target_path))

    return diff_groups


def load_yaml(file_path):
    try:
        with open(file_path, "r") as file:
            data = yaml.safe_load(file)
        return data
    except Exception as e:
        logger.error(f"Error loading YAML file {file_path}: {e}")
        return None


def get_assumed_credentials(account_id):
    """Assumes account role and returns temp credentials"""
    role_arn = f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE_NAME}"
    sts_client = boto3.client("sts")
    assumed_role = sts_client.assume_role(
        RoleArn=role_arn, RoleSessionName="cross_acct_assume"
    )
    return assumed_role["Credentials"]


def send_sns_notification(subject, message):
    """
    Sends an SNS notification with the provided error message.
    """
    sns_client = boto3.client("sns")
    try:
        response = sns_client.publish(
            TopicArn=SNS_TOPIC_ARN, Message=message, Subject=subject
        )
        logger.info(
            f'SNS notification sent successfully. MessageId: {response["MessageId"]}'
        )
    except Exception as e:
        logger.error(f"Failed to send SNS notification: {e}")


def main(
    cluster_region,
    cluster_name,
    bedrock_region,
    bedrock_model,
    output_s3_bucket
):
    try:
        install_kubectl()
        install_kubectl_convert()

        if os.path.exists("./ekscelerator-insights"):
            logger.warning(
                "Working directory ./ekscelerator-insights already exists, deleting it in order to get "
                "new insights."
            )
            shutil.rmtree("./ekscelerator-insights")
        else:
            logger.info("Creating working directory: .")
            os.makedirs("./ekscelerator-insights", exist_ok=True)

        master_session = boto3.session.Session()
        sts_client = master_session.client("sts")

        s3_client = master_session.client("s3")

        current_account_id = sts_client.get_caller_identity()["Account"]
   
        credentials = get_assumed_credentials(ACCOUNT_ID)
        eks_client = boto3.client(
            "eks",
            region_name=cluster_region,
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )
        # Export the temporary credentials as environment variables
        os.environ["AWS_ACCESS_KEY_ID"] = credentials["AccessKeyId"]
        os.environ["AWS_SECRET_ACCESS_KEY"] = credentials["SecretAccessKey"]
        os.environ["AWS_SESSION_TOKEN"] = credentials["SessionToken"]

        current_version = get_current_eks_version(
            eks_client, cluster_region, cluster_name, current_account_id
        )
        latest_version = get_latest_eks_version(eks_client)
        if current_version == latest_version:
            logger.info(f"Cluster {cluster_name} is on the latest version {latest_version}. Well done!")
        else:
            logger.info(f"Cluster {cluster_name} is not on the latest version {latest_version}. Checking for upgrade insights...")
            next_minor_version = semver.Version.parse(
                current_version, optional_minor_and_patch=True
            ).bump_minor()
            eks_latest_version = semver.Version.parse(
                latest_version, optional_minor_and_patch=True
            )
            while next_minor_version <= eks_latest_version:
                version_to_review = (
                    f"{next_minor_version.major}.{next_minor_version.minor}"
                )
                logger.info(f"Checking for upgrade insights for target version {version_to_review}...")
                upgrade_insights = get_upgrade_insights(
                    eks_client, cluster_name, version_to_review
                )
                next_minor_version = next_minor_version.bump_minor()
                if not upgrade_insights:
                    logger.info(f"Upgrade insights not found for cluster {cluster_name} in region {cluster_region} for target version {version_to_review}")
                    continue

                process_dir = (
                    f"./ekscelerator-insights/"
                    f"{ACCOUNT_ID}/"
                    f"{cluster_region}/"
                    f"{cluster_name}/"
                    f"current-{current_version}/"
                    f"{version_to_review}-deprecations"
                )
                target_dir = (
                    f"./ekscelerator-insights/"
                    f"{ACCOUNT_ID}/"
                    f"{cluster_region}/"
                    f"{cluster_name}/"
                    f"target-{version_to_review}"
                )
                namespaced_apis = get_namespaced_api_resources(
                    cluster_name, cluster_region
                )
                non_namespaced_apis = get_non_namespaced_api_resources(
                    cluster_name, cluster_region
                )
                for insight in upgrade_insights:
                    insight_id = insight["id"]
                    insight_response = eks_client.describe_insight(
                        clusterName=cluster_name, id=insight_id
                    )
                    for details in (
                        insight_response.get("insight")
                        .get("categorySpecificSummary")
                        .get("deprecationDetails")
                    ):
                        if len(details.get("clientStats")):
                            current_comp = parse_string_to_list(
                                details.get("usage"), "/"
                            )
                            replacement_comp = details.get("replacedWith")
                            comp_kind = current_comp[-1]
                   
                            if comp_kind in namespaced_apis:
                                namespaced = True
                            elif comp_kind in non_namespaced_apis:
                                namespaced = False
                            else:
                                logger.info(f"{current_version} not found in any of the Kubernetes api-resources. Skipping this...")
                                continue

                            resources = get_resources(
                                cluster_name, cluster_region, comp_kind, namespaced
                            )
                            if resources:
                                for namespace, resources in resources.items():
                                    for res in resources:
                                        comp_dir = (
                                            f"{process_dir}/{namespace}/{comp_kind}"
                                        )
                                        os.makedirs(comp_dir, exist_ok=True)
                                        manifest_dict = get_manifest(
                                            cluster_name,
                                            cluster_region,
                                            comp_kind,
                                            f"{current_comp[2]}.{current_comp[1]}",
                                            res,
                                            namespace,
                                        )

                                        if manifest_dict:
                                            export_manifest(
                                                output_s3_bucket,
                                                f"{comp_dir}/{res}.yaml",
                                                manifest_dict,
                                            )
                                            new_manifest_dir = (
                                                f"{target_dir}/"
                                                f"{namespace}/"
                                                f"{comp_kind}"
                                            )
                                            os.makedirs(new_manifest_dir, exist_ok=True)
                                            bedrock_suggestion = ""
                                            if replacement_comp:
                                                new_api_group = [
                                                    item
                                                    for item in replacement_comp.split(
                                                        "/"
                                                    )
                                                    if item
                                                ]
                                                new_api_version = f"{new_api_group[1]}/{new_api_group[2]}"
                                                new_manifest_dict = kubectl_convert(
                                                    f"{comp_dir}/{res}.yaml",
                                                    new_api_version,
                                                )
                                                if new_manifest_dict:
                                                    export_manifest(
                                                        output_s3_bucket,
                                                        f"{new_manifest_dir}/{res}.yaml",
                                                        new_manifest_dict,
                                                    )
                                                else:
                                                    logger.info(f"Kubectl convert failed to migrate manifest for the component {comp_kind}.")
                                                    logger.info("Invoking Bedrock model for suggestions...")
                                                    bedrock_suggestion = (
                                                        get_bedrock_suggestions(
                                                            bedrock_region,
                                                            bedrock_model,
                                                            manifest_dict,
                                                            version_to_review,
                                                            "deprecated",
                                                            new_api_version,
                                                        )
                                                    )
                                            else:
                                                logger.info(f"Current version: {current_version} - Target version: {version_to_review} - No replacement API group found for {comp_kind}, this resource is probably removed...")
                                                logger.info(
                                                    "Invoking Bedrock model for suggestions..."
                                                )
                                                bedrock_suggestion = (
                                                    get_bedrock_suggestions(
                                                        bedrock_region,
                                                        bedrock_model,
                                                        manifest_dict,
                                                        version_to_review,
                                                        "removed",
                                                    )
                                                )
                                            if bedrock_suggestion:
                                                with open(
                                                    f"{new_manifest_dir}/{res}.suggestion",
                                                    "w",
                                                    encoding="utf-8",
                                                ) as f:
                                                    f.write(bedrock_suggestion)

                                                logger.info(
                                                    "Got suggestions from Bedrock, you will see the results in the suggestion file.")
                                                logger.info(f"Suggestions exported to {f.name}")
                                                copy_file_to_s3(f.name, output_s3_bucket)
                            else:
                                logger.info(
                                    f"No resource {comp_kind} found in the cluster {cluster_name}."
                                )

                # Compare source and target YAMLs to populate markdown file
                generate_markdown(
                    eks_client,
                    process_dir,
                    target_dir,
                    f"{ACCOUNT_ID}_{cluster_region}_{cluster_name}_upgrade_instructions.md",
                    cluster_name,
                    cluster_region,
                    current_version,
                    version_to_review,
                )
                s3_client.upload_file(
                    f"{ACCOUNT_ID}_{cluster_region}_{cluster_name}_upgrade_instructions.md",
                    output_s3_bucket,
                    f"ekscelerator-insights/upgrade-reports/{ACCOUNT_ID}/{cluster_region}/{cluster_name}_upgrade_instructions.md",
                )
                logger.info(
                    f"Upgrade report for {cluster_name} residing on account {ACCOUNT_ID} and region {cluster_region} uploaded to s3://{output_s3_bucket}/ekscelerator-insights/upgrade-reports/{ACCOUNT_ID}/{cluster_region}/{cluster_name}_upgrade_instructions.md"
                )

        subject = (
            f"EKS Upgrade Insights generation succeeded for cluster {cluster_name}"
        )
        error_msg = f"EKS Upgrade insights successfully generated for cluster {cluster_name} on account {ACCOUNT_ID} and region {cluster_region}. It's available to access here: s3://{output_s3_bucket}/ekscelerator-insights/upgrade-reports/{ACCOUNT_ID}/{cluster_region}/{cluster_name}_upgrade_instructions.md"
        send_sns_notification(subject, error_msg)
    except Exception as e:
        subject = f"EKS Upgrade Insights failed for cluster {cluster_name}"
        error_msg = f"There was an error while trying to generate EKS Upgrade insights for cluster {cluster_name} on account {ACCOUNT_ID} and region {cluster_region}. Error: {e}. Please check the Glue job logs for more information"
        send_sns_notification(subject, error_msg)
        raise Exception(f"{cluster_name}:Exception raised: {e}")



def install_kubectl():
    try:
        os.makedirs("/tmp/kubectl", exist_ok=True)
        os.makedirs("/tmp/kube-config", mode=0o777, exist_ok=True)
        kubectl_url = "https://amazon-eks.s3.us-west-2.amazonaws.com/1.29.0/2024-01-04/bin/linux/amd64/kubectl"
        subprocess.check_call(["curl", "-o", "/tmp/kubectl/kubectl", kubectl_url])
        os.chmod("/tmp/kubectl/kubectl", 0o755)
        logger.info("kubectl has been installed successfully.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install kubectl: {e}")


def install_kubectl_convert():
    try:
        stable_version_url = "https://dl.k8s.io/release/stable.txt"
        stable_version = (
            subprocess.check_output(["curl", "-L", "-s", stable_version_url])
            .decode()
            .strip()
        )
        kubectl_convert_download_url = f"https://dl.k8s.io/release/{stable_version}/bin/linux/amd64/kubectl-convert"
        os.makedirs("/tmp/kubectl-convert", exist_ok=True)
        subprocess.check_call(
            ["curl", "-Lo", "kubectl-convert", kubectl_convert_download_url]
        )

        install_command = ["install", "-m", "0755", "kubectl-convert", "/tmp/kubectl-convert/kubectl-convert"]
        # The quoted command parts are passed directly to `subprocess.run` as a list, avoiding the need for `shlex.split` and `shell=Treu`.
        # nosemgrep: dangerous-subprocess-use-audit
        subprocess.run(install_command, check=True)
        logger.info("kubectl-convert has been installed successfully.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install kubectl-convert: {e}")


if __name__ == "__main__":
    # Install AWS CLI
    subprocess.run(["python", "-m", "pip", "install", "awscli==1.30.0"])

    # Uninstall existing botocore and boto3
    subprocess.run(["python", "-m", "pip", "uninstall", "-y", "botocore", "boto3"])

    # Install botocore and boto3
    subprocess.run(["python", "-m", "pip", "install", "botocore", "boto3"])

    main(
        CLUSTER_REGION,
        CLUSTER_NAME,
        BEDROCK_REGION,
        BEDROCK_MODEL,
        OUTPUT_S3_BUCKET
    )
