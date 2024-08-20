import json
import boto3
import base64
import inspect
import subprocess

from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.daemonset.Daemonset import Daemonset


from pathlib import Path
from botocore.exceptions import ClientError


class AWSDaemonset(Daemonset):
  def __init__(self, falcon_client_id, falcon_client_secret, logger, image_registry=None, proxy_server=None,
               proxy_port=None, sensor_tags=None, cluster_name=None, cluster_type=None, sensor_mode=None,
               sensor_image_tag=None, ecr_iam_policy=None, sensor_iam_role=None, kac_iam_role=None, iar_iam_role=None):
    super().__init__(falcon_client_id, falcon_client_secret, logger, image_registry, proxy_server,
                     proxy_port, sensor_tags, cluster_name, cluster_type, sensor_mode, sensor_image_tag)

    self.sensor_mode = sensor_mode
    self.sensor_image_tag = sensor_image_tag
    self.cluster_name = cluster_name
    self.cluster_type = cluster_type
    self.ecr_iam_policy = ecr_iam_policy
    self.sensor_iam_role = sensor_iam_role
    self.kac_iam_role = kac_iam_role
    self.iar_iam_role = iar_iam_role

  def login_to_ecr_repo(self, ecr_region, ecr_repo):
    command = (f'aws ecr get-login-password --region {ecr_region} | sudo skopeo login --username AWS --password-stdin'
               f' {ecr_repo}')

    return True if self.run_command(command=command) else False

  def check_ecr_exists(self, ecr_registry_uri) -> bool:
    try:
      repository_name = ecr_registry_uri.split('amazonaws.com/')[-1]
      registry_id = ecr_registry_uri.split('.')[0]
      region = ecr_registry_uri.split('.')[3]

      # Create an ECR client
      client = boto3.client('ecr', region_name=region)

      # Check if the repository exists
      client.describe_repositories(registryId=registry_id, repositoryNames=[repository_name])
      self.logger.info(f'Repository {ecr_registry_uri} does exist.')

      return True
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return False

  def check_ecr_image_exists(self, ecr_registry_uri, ecr_image_tag) -> bool:
    # Check if the image tag exists in the repository
    repository_name = ecr_registry_uri.split('amazonaws.com/')[-1]
    region = ecr_registry_uri.split('.')[3]

    # Create an ECR client
    client = boto3.client('ecr', region_name=region)

    try:
      response = client.describe_images(
        repositoryName=repository_name,
        imageIds=[
          {
            'imageTag': ecr_image_tag
          }
        ]
      )

      if response['imageDetails']:
        self.logger.info(f"Image with tag '{ecr_image_tag}' exists in repository '{repository_name}'.")
        return True
      else:
        self.logger.error(f"Image with tag '{ecr_image_tag}' does not exist in repository '{repository_name}'.")
        return False
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return False

  def copy_image_to_ecr(self, source_image_repo, source_image_tag, target_image_repo, target_image_tag) -> bool:
    command = (f'skopeo copy --multi-arch all docker://{source_image_repo}:{source_image_tag} docker:/'
               f'/{target_image_repo}:{target_image_tag}')

    if self.run_command(command=command):
      return True
    else:
      return False

  def get_ecr_partial_pull_token(self, ecr_registry: str) -> str:
    try:
      ecr_region: str = ecr_registry.split('.')[3]

      partial_pull_token_command: str = f"aws ecr get-login-password --region {ecr_region}"

      stdout, stderr = self.run_command(command=partial_pull_token_command, output=True)

      if stdout is not None:
        output = f'AWS:{stdout}'
        partial_pull_token = (base64.b64encode(output.encode()).decode())
        return partial_pull_token
      else:
        return 'None'
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return 'None'

  def get_ecr_image_pull_token(self, ecr_registry_uri: str) -> str:
    partial_pull_token: str = self.get_ecr_partial_pull_token(ecr_registry=ecr_registry_uri)

    if self.add_crowdstrike_helm_repo() is True:
      try:
        ecr_registry_uri: str = self.image_registry.split('/')[0]

        if partial_pull_token != 'None':
          falcon_image_pull_data = {
            "auths": {
              f"{ecr_registry_uri}": {
                "auth": partial_pull_token
              }
            }
          }

          falcon_image_pull_token = base64.b64encode(json.dumps(falcon_image_pull_data).encode()).decode()

          return falcon_image_pull_token
        else:
          return 'None'
      except Exception as e:
        self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
        self.logger.error(f'{e}')
        return 'None'
    else:
      return 'None'

  def copy_crwd_image_to_ecr(self, sensor_type: str, ecr_image_repo: str, image_tag: str = 'latest') -> bool:
    try:
      ecr_region: str = ecr_image_repo.split('.')[3]
      ecr_repo: str = ecr_image_repo.split('/')[0]

      crowdstrike_image_repo: str = self.get_crwd_repo_url(sensor_type=sensor_type)

      if image_tag == 'None':
        return False

      if not self.login_to_crowdstrike_repo():
        return False

      if not self.login_to_ecr_repo(ecr_region=ecr_region, ecr_repo=ecr_repo):
        return False

      if not self.copy_image_to_ecr(source_image_repo=crowdstrike_image_repo, source_image_tag=image_tag,
                                    target_image_repo=ecr_image_repo, target_image_tag=image_tag):
        return False

      self.logger.info(f"{image_tag} copied to {ecr_image_repo} successfully.")
      return True
    except subprocess.CalledProcessError as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f"An error occurred while running: {e.cmd}")
      self.logger.error(f"Exit code: {e.returncode}")
      self.logger.error(f"Output: {e.output}")
      self.logger.error(f"{e.stderr}")
      return False

  def get_ecr_repo_tag_token(self, sensor_type, ecr_registry_uri, image_tag) -> tuple:
    image_tag = self.get_crwd_image_tag(sensor_type=sensor_type, image_tag=image_tag)

    if self.check_ecr_exists(ecr_registry_uri=ecr_registry_uri):
      if not self.check_ecr_image_exists(ecr_registry_uri=ecr_registry_uri, ecr_image_tag=image_tag):
        self.copy_crwd_image_to_ecr(sensor_type=sensor_type, ecr_image_repo=ecr_registry_uri, image_tag=image_tag)

      image_pull_token = self.get_ecr_image_pull_token(ecr_registry_uri=ecr_registry_uri)

      return ecr_registry_uri, image_tag, image_pull_token
    else:
      self.logger.error('Invalid ECR URI or ECR does not exist')
      return 'None', 'None', 'None'

  def get_repo_tag_token(self, sensor_type, image_tag) -> tuple:
    registry_type, registry_uri = self.get_image_repo(sensor_type=sensor_type)

    if registry_type == 'crwd_registry':
      falcon_image_repo, falcon_image_tag, falcon_image_pull_token = self.get_crwd_repo_tag_token(
        sensor_type=sensor_type, image_tag=image_tag)

      return registry_type, falcon_image_repo, falcon_image_tag, falcon_image_pull_token
    elif registry_type == 'ecr_registry':
      falcon_image_repo, falcon_image_tag, falcon_image_pull_token = self.get_ecr_repo_tag_token(
        sensor_type=sensor_type, ecr_registry_uri=registry_uri, image_tag=image_tag)

      return registry_type, falcon_image_repo, falcon_image_tag, falcon_image_pull_token
    else:
      return 'None', 'None', 'None', 'None'

  def get_aws_account_id(self) -> str | None:
    output, error = self.run_command(command='aws sts get-caller-identity --query "Account" --output text',
                                     output=True)

    if output is not None:
      return output.strip()
    else:
      return None

  def get_cluster_oidc_issuer(self, region) -> str | None:
    cluster_name = self.cluster_name

    command = (f'aws eks describe-cluster --name {cluster_name} --region {region} --query '
               '"cluster.identity.oidc.issuer" --output text')

    output, error = self.run_command(command=command, output=True)

    if output is not None:
      return output.split('/')[-1].rstrip()
    else:
      return None

  def check_aws_iam_policy(self, policy_name) -> str | None:
    iam = boto3.client('iam')

    try:
      # List policies with the given name
      response = iam.list_policies(Scope='Local')

      # Check if the policy exists in the list of policies
      for policy in response['Policies']:
        if policy['PolicyName'] == policy_name:
          self.logger.info(f"IAM policy '{policy_name}' exists with ARN: {policy['Arn']}")
          return policy['Arn']

      self.logger.info(f"IAM policy '{policy_name}' does not exist.")
      return None
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return None

  def create_and_get_eks_fargate_permissions_policy(self, ecr_region, permission_policy_name) -> str | None:
    policy_arn: str = self.check_aws_iam_policy(policy_name=permission_policy_name)
    permissions_policy_file_path: str = './abstrakt/conf/aws/eks/policies/eks-fargate-permission-policy.json'

    if policy_arn is not None:
      return policy_arn
    else:
      permission_policy_file = Path(permissions_policy_file_path)

      create_policy_command = (
        f'aws iam create-policy --region "{ecr_region}" --policy-name {permission_policy_name} '
        f'--policy-document file://{permission_policy_file} --description "Policy to enable '
        f'Falcon Sensors to pull container image from ECR"')

      output, error = self.run_command(command=create_policy_command, output=True)

      if output is not None:
        output = json.loads(output)

        return output['Policy']['Arn']
      else:
        return None

  def create_eks_fargate_trust_policy_json_file(self, account_id, region, oidc_issuer, namespace,
                                                service_account) -> str | None:
    trust_policy = f"""{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Effect": "Allow",
      "Principal": {{
        "Federated": "arn:aws:iam::{account_id}:oidc-provider/oidc.eks.{region}.amazonaws.com/id/{oidc_issuer}"
      }},
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {{
        "StringEquals": {{
          "oidc.eks.{region}.amazonaws.com/id/{oidc_issuer}:aud": "sts.amazonaws.com",
          "oidc.eks.{region}.amazonaws.com/id/{oidc_issuer}:sub": "system:serviceaccount:{namespace}:{service_account}"
        }}
      }}
    }}
  ]
}}
"""

    if service_account == 'crowdstrike-falcon-sa':
      file_name = './abstrakt/conf/aws/eks/policies/sensor-eks-fargate-trust-policy.json'
    elif service_account == 'falcon-kac-sa':
      file_name = './abstrakt/conf/aws/eks/policies/kac-eks-fargate-trust-policy.json'
    elif service_account == 'image-analyzer-falcon-image-analyzer':
      file_name = './abstrakt/conf/aws/eks/policies/iar-eks-fargate-trust-policy.json'
    else:
      return None

    try:
      with open(file_name, 'w') as file:
        file.write(trust_policy)
      return file_name
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return None

  def check_aws_iam_role(self, role_name) -> str | None:
    iam = boto3.client('iam')

    try:
      # Get the role
      response = iam.get_role(RoleName=role_name)

      # If the role exists, return the ARN
      role_arn = response['Role']['Arn']
      self.logger.info(f"IAM role '{role_name}' exists with ARN: {role_arn}")
      return role_arn
    except ClientError as e:
      # Check if the error is because the role does not exist
      if e.response['Error']['Code'] == 'NoSuchEntity':
        self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
        self.logger.info(f"IAM role '{role_name}' does not exist.")
        self.logger.error(f'{e}')
        return None
      else:
        self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
        self.logger.error(f'{e}')
        return None
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return None

  def create_and_get_eks_fargate_role(self, account_id, region, oidc_issuer, role_name,
                                      namespace, service_account) -> str | None:
    file_name = self.create_eks_fargate_trust_policy_json_file(account_id=account_id,
                                                               region=region,
                                                               oidc_issuer=oidc_issuer,
                                                               namespace=namespace,
                                                               service_account=service_account)

    if file_name is None:
      return None

    iam_role_arn = self.check_aws_iam_role(role_name)

    if iam_role_arn is None:
      command = f'aws iam create-role --role-name {role_name} --assume-role-policy-document file://{file_name}'

      output, error = self.run_command(command=command, output=True)

      if output is not None:
        output = json.loads(output)
        return output['Role']['Arn']

      return None
    else:
      return iam_role_arn

  def attach_policy_to_iam_role(self, policy_arn, iam_role_arn):
    role_name = iam_role_arn.split('role/')[-1]
    command = f'aws iam attach-role-policy --role-name {role_name} --policy-arn {policy_arn} --output json'

    try:
      result = subprocess.run(command, shell=True, check=True, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)

      if result.returncode == 0:
        return True
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return False

  def set_and_attach_policy_to_iam_role(self, ecr_region, namespace, service_account) -> str | None:
    permission_policy_arn: str
    account_id: str
    oidc_issuer: str
    iam_role_arn: str

    permission_policy_arn = self.create_and_get_eks_fargate_permissions_policy(
      ecr_region=ecr_region, permission_policy_name=self.ecr_iam_policy)

    if permission_policy_arn is None:
      return None

    account_id = self.get_aws_account_id()

    if account_id is None:
      return None

    oidc_issuer = self.get_cluster_oidc_issuer(region=ecr_region)

    if oidc_issuer is None:
      return None

    if service_account == 'crowdstrike-falcon-sa':
      role_name = self.sensor_iam_role
    elif service_account == 'falcon-kac-sa':
      role_name = self.kac_iam_role
    elif service_account == 'image-analyzer-falcon-image-analyzer':
      role_name = self.iar_iam_role
    else:
      return None

    iam_role_arn = self.create_and_get_eks_fargate_role(account_id=account_id,
                                                        region=ecr_region,
                                                        oidc_issuer=oidc_issuer,
                                                        role_name=role_name,
                                                        namespace=namespace,
                                                        service_account=service_account)

    if iam_role_arn is None:
      return None

    if self.attach_policy_to_iam_role(policy_arn=permission_policy_arn, iam_role_arn=iam_role_arn):
      return iam_role_arn
    else:
      return None

  def get_helm_chart(self):
    registry_type, falcon_image_repo, falcon_image_tag, falcon_image_pull_token = self.get_repo_tag_token(
      sensor_type='daemonset', image_tag=self.sensor_image_tag)

    if falcon_image_repo != 'None' and falcon_image_tag != 'None' and falcon_image_pull_token != 'None':
      helm_chart = [
        "helm", "upgrade", "--install", "daemonset-falcon-sensor", "crowdstrike/falcon-sensor",
        "-n", "falcon-system", "--create-namespace",
        "--set", f"falcon.cid={self.falcon_cid}",
        "--set", f"node.image.repository={falcon_image_repo}",
        "--set", f"node.image.tag={falcon_image_tag}",
        "--set", f"node.image.registryConfigJSON={falcon_image_pull_token}",
        "--set", f'node.backend={self.sensor_mode}'
      ]

      if self.cluster_type == 'gke-autopilot':
        helm_chart.append('--set')
        helm_chart.append('node.gke.autopilot=true')

      if self.proxy_server and self.proxy_port:
        helm_chart.append("--set")
        helm_chart.append(f'falcon.apd=false')
        helm_chart.append("--set")
        helm_chart.append(f'falcon.aph=http://{self.proxy_server}')
        helm_chart.append("--set")
        helm_chart.append(f'falcon.app={self.proxy_port}')

      if self.sensor_tags:
        # tags = '\\,'.join(self.tags.strip('"').split(','))
        tags = '\\,'.join(self.sensor_tags.split(','))
        helm_chart.append("--set")
        helm_chart.append(f'falcon.tags="{tags}"')

      return helm_chart
    else:
      return False

  def execute_helm_chart(self):
    try:
      def thread():
        helm_chart = self.get_helm_chart()

        if helm_chart is not False:
          command = ' '.join(helm_chart)

          self.logger.info(f'Running command: {command}')
          output, error = self.run_command(command=command, output=True)

          self.logger.info(output)
          self.logger.error(error)
        else:
          return False

      with MultiThreading() as mt:
        mt.run_with_progress_indicator(thread, 1)
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      return False
    else:
      return True

  def deploy_falcon_sensor_daemonset(self):
    """Deploys the CrowdStrike Falcon Sensor daemonset on a Kubernetes cluster."""

    print(f"{'+' * 26}\nCrowdStrike Falcon Sensor\n{'+' * 26}\n")

    print("Installing Falcon Sensor...")

    k8s = KubectlOps(logger=self.logger)

    falcon_sensor_names = ['daemonset-falcon-sensor', 'falcon-helm-falcon-sensor']

    for falcon_sensor in falcon_sensor_names:
      if k8s.namespace_exists(namespace_name='falcon-system'):
        captured_pods, status = k8s.find_pods_with_status(pod_string=falcon_sensor, namespace='falcon-system')

        if (status is True) and (len(captured_pods['running']) > 0):
          print('Falcon sensors found up and running in falcon-system namespace. Not proceeding with installation.')

          for pod in captured_pods['running']:
            print(pod)

          print(' ')
          return

    if self.execute_helm_chart():
      print("Falcon sensor installation successful\n")

      container = ContainerOps(logger=self.logger)
      container.pod_checker(pod_name='falcon-sensor', namespace='falcon-system', kubeconfig_path='~/.kube/config')
    else:
      print("Falcon sensor installation failed\n")
