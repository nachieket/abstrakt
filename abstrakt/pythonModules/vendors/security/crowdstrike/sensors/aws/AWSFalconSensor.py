import json
import boto3
import base64
import inspect
import subprocess

from botocore.exceptions import ClientError

from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.CrowdStrikeSensors import CrowdStrikeSensors


class AWSFalconSensor(CrowdStrikeSensors):
  def __init__(self, falcon_client_id, falcon_client_secret, logger, image_registry=None,
               sensor_image_tag=None, proxy_server=None, proxy_port=None, sensor_tags=None, cluster_name=None,
               cluster_type=None):
    super().__init__(falcon_client_id, falcon_client_secret, logger, image_registry, proxy_server,
                     proxy_port, sensor_tags, cluster_name, cluster_type)

    self.sensor_image_tag = sensor_image_tag

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
