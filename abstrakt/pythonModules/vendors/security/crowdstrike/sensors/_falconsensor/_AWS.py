import json
import boto3
import base64
import inspect
import subprocess

from pathlib import Path
from botocore.exceptions import ClientError

from abstrakt.pythonModules.customLogging.customLogging import CustomLogger
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors._CrowdStrikeSensors import _CrowdStrikeSensors


class _AWS(_CrowdStrikeSensors):
  def __init__(self, falcon_client_id: str,
               falcon_client_secret: str,
               logger: CustomLogger,
               registry: str,
               repository: str):
    super().__init__(falcon_client_id,
                     falcon_client_secret,
                     logger,
                     registry,
                     repository)

  def login_to_ecr_registry(self, region: str, registry: str) -> bool:
    command: str = (f'aws ecr get-login-password --region {region} | sudo skopeo login --username AWS '
                    f'--password-stdin {registry}')

    return True if self.run_command(command=command) else False

  def check_ecr_registry_exists(self, registry: str) -> bool:
    try:
      # Create an ECR client
      client: boto3 = boto3.client('ecr', region_name=registry.split('.')[3])

      # Check if the repository exists
      client.describe_repositories(registryId=registry.split('.')[0])
      self.logger.info(f'Registry {registry} does exist.')

      return True
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return False

  def check_ecr_repository_exists(self, registry: str, repository: str) -> bool:
    try:
      # Create an ECR client
      client: boto3 = boto3.client('ecr', region_name=registry.split('.')[3])

      # Check if the repository exists
      client.describe_repositories(registryId=registry.split('.')[0], repositoryNames=[repository])
      self.logger.info(f'Repository {repository} does exist.')

      return True
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return False

  # @staticmethod
  # def get_default_repository_name(sensor_type: str):
  #   if sensor_type == 'daemonset':
  #     return 'falcon-daemonset-sensor'
  #   elif sensor_type == 'sidecar':
  #     return 'falcon-sidecar-sensor'
  #   elif sensor_type == 'falcon-kac':
  #     return 'falcon-kac'
  #   elif sensor_type == 'falcon-imageanalyzer':
  #     return 'falcon-iar'

  def create_ecr_repository(self, registry: str, repository: str, sensor_type: str) -> bool:
    if repository is None:
      repository = self.get_default_repository_name(sensor_type=sensor_type)

    # Create a boto3 client for ECR
    ecr_client: boto3 = boto3.client('ecr', region_name=registry.split('.')[3])

    try:
      # Create the repository in the specified registry
      ecr_client.create_repository(
        repositoryName=repository,
        registryId=registry.split('.')[0],  # Specify the registry ID here
        imageScanningConfiguration={
          'scanOnPush': True
        },
        encryptionConfiguration={
          'encryptionType': 'AES256'
        }
      )
      self.logger.info(f"Repository '{repository}' created successfully in registry '{registry}'!")
      return True
    except ecr_client.exceptions.RepositoryAlreadyExistsException:
      self.logger.error(f"Repository '{repository}' already exists in registry '{registry}'.")
      return False
    except Exception as e:
      self.logger.error(f"An error occurred: {e}")
      return False

  def check_image_exists_on_ecr(self, registry: str, repository: str, image_tag: str) -> bool:
    # Create an ECR client
    client: boto3 = boto3.client('ecr', region_name=registry.split('.')[3])

    try:
      response = client.describe_images(
        repositoryName=repository,
        imageIds=[
          {
            'imageTag': image_tag
          }
        ]
      )

      if response['imageDetails']:
        self.logger.info(f"Image with tag '{image_tag}' exists in repository '{repository}'.")
        return True
      else:
        self.logger.error(f"Image with tag '{image_tag}' does not exist in repository '{repository}'.")
        return False
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return False

  def copy_image_to_ecr(self, source_image_registry: str, source_image_tag: str,
                        target_image_registry: str, target_image_tag: str) -> bool:
    command = (f'skopeo copy --multi-arch all docker://{source_image_registry}:{source_image_tag} '
               f'docker://{target_image_registry}:{target_image_tag}')

    if self.run_command(command=command):
      return True
    else:
      return False

  def get_ecr_partial_pull_token(self, region: str) -> str | None:
    try:
      partial_pull_token_command: str = f"aws ecr get-login-password --region {region}"

      stdout = self.run_command(command=partial_pull_token_command)

      if stdout:
        output = f'AWS:{stdout}'
        partial_pull_token = (base64.b64encode(output.encode()).decode())
        return partial_pull_token
      else:
        return None
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return None

  def get_ecr_image_pull_token(self, registry: str) -> str | None:
    partial_pull_token: str = self.get_ecr_partial_pull_token(region=registry.split('.')[3])

    if self.add_crowdstrike_helm_repo() is True:
      try:
        if partial_pull_token != 'None':
          falcon_image_pull_data = {
            "auths": {
              f"{registry}": {
                "auth": partial_pull_token
              }
            }
          }

          falcon_image_pull_token: str = base64.b64encode(json.dumps(falcon_image_pull_data).encode()).decode()

          return falcon_image_pull_token
        else:
          return None
      except Exception as e:
        self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
        self.logger.error(f'{e}')
        return None
    else:
      return None

  def copy_crowdstrike_image_to_ecr(self, source_registry: str, target_registry: str,
                                    repository: str, image_tag: str = 'latest') -> bool:
    try:
      if image_tag == 'None':
        return False

      if not self.login_to_crowdstrike_repo():
        return False

      if not self.login_to_ecr_registry(region=target_registry.split('.')[3], registry=target_registry):
        return False

      if not self.copy_image_to_ecr(source_image_registry=source_registry,
                                    source_image_tag=image_tag,
                                    target_image_registry=f'{target_registry}/{repository}',
                                    target_image_tag=image_tag):
        return False

      self.logger.info(f"{image_tag} copied to {target_registry} successfully.")
      return True
    except subprocess.CalledProcessError as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f"An error occurred while running: {e.cmd}")
      self.logger.error(f"Exit code: {e.returncode}")
      self.logger.error(f"Output: {e.output}")
      self.logger.error(f"{e.stderr}")
      return False

  def get_image_registry(self, registry: str, registry_type: str, sensor_type: str) -> str | None:
    if registry:
      if registry_type == 'ecr':
        return f'{registry}'
      elif registry_type == 'crwd':
        return self.get_crowdstrike_registry(sensor_type=sensor_type)
      else:
        return None
    else:
      return self.get_crowdstrike_registry(sensor_type=sensor_type)

  def get_image_tag(self, registry: str, repository: str, image_tag: str, sensor_type: str) -> str | None:
    registry_type: str = self.check_registry_type(registry=registry)

    if registry_type == 'crwd':
      if 'latest' in image_tag:
        return self.get_crowdstrike_sensor_image_tag(sensor_type=sensor_type, image_tag=image_tag)
      elif self.verify_crowdstrike_sensor_image_tag(image_tag=image_tag, sensor_type=sensor_type):
        return image_tag
      return None

    if registry_type == 'ecr' and self.check_ecr_registry_exists(registry=registry):
      if not self.check_ecr_repository_exists(registry=registry, repository=repository):
        self.create_ecr_repository(registry=registry, repository=repository, sensor_type=sensor_type)

      if 'latest' in image_tag:
        image_tag: str = self.get_crowdstrike_sensor_image_tag(sensor_type=sensor_type, image_tag=image_tag)
      elif not self.verify_crowdstrike_sensor_image_tag(image_tag=image_tag, sensor_type=sensor_type):
        return None

      if self.check_image_exists_on_ecr(registry=registry, repository=repository, image_tag=image_tag):
        return image_tag

      source_registry = self.get_crowdstrike_registry(sensor_type=sensor_type)
      if self.copy_crowdstrike_image_to_ecr(source_registry=source_registry, repository=repository,
                                            target_registry=registry, image_tag=image_tag):
        if self.check_image_exists_on_ecr(registry=registry, repository=repository, image_tag=image_tag):
          return image_tag

    return None

  def get_image_pull_token(self, registry: str) -> str | None:
    registry_type: str = self.check_registry_type(registry=registry)

    if registry_type == 'crwd':
      return self.get_crowdstrike_image_pull_token()
    elif registry_type == 'ecr':
      return self.get_ecr_image_pull_token(registry=registry)
    else:
      return None


class _AWSSpecs(_AWS):
  def __init__(self, falcon_client_id: str,
               falcon_client_secret: str,
               logger: CustomLogger,
               registry: str,
               repository: str,
               iam_policy: str
               ):
    super().__init__(falcon_client_id,
                     falcon_client_secret,
                     logger,
                     registry,
                     repository)
    self.iam_policy: str = iam_policy

  def get_aws_account_id(self) -> str | None:
    command: str = 'aws sts get-caller-identity --query "Account" --output text'
    output = self.run_command(command=command)

    if output is not None:
      return output.strip()
    else:
      return None

  def get_cluster_oidc_issuer(self, cluster_name: str, region: str) -> str | None:
    command: str = (f'aws eks describe-cluster --name {cluster_name} --region {region} --query '
                    '"cluster.identity.oidc.issuer" --output text')

    output = self.run_command(command=command)

    if output is not None:
      return output.split('/')[-1].rstrip()
    else:
      return None

  def check_aws_iam_policy(self, policy_name: str) -> str | None:
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

  def check_aws_iam_role(self, role_name: str) -> str | None:
    iam = boto3.client('iam')

    try:
      # Get the role
      response = iam.get_role(RoleName=role_name)

      # If the role exists, return the ARN
      role_arn: str = response['Role']['Arn']
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

  def attach_policy_to_iam_role(self, policy_arn: str, iam_role_arn: str):
    role_name: str = iam_role_arn.split('role/')[-1]
    command: str = f'aws iam attach-role-policy --role-name {role_name} --policy-arn {policy_arn} --output json'

    try:
      output = self.run_command(command=command)

      if output:
        return True
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return False

  def create_and_get_eks_fargate_permissions_policy(self, permission_policy: str, region: str) -> str | None:
    policy_arn: str = self.check_aws_iam_policy(policy_name=permission_policy)

    if policy_arn:
      return policy_arn
    else:
      permissions_policy_file_path: str = './abstrakt/conf/aws/eks/policies/eks-fargate-permission-policy.json'
      permission_policy_file = Path(permissions_policy_file_path)

      create_policy_command = (
        f'aws iam create-policy --region "{region}" --policy-name {permission_policy} '
        f'--policy-document file://{permission_policy_file} --description "Policy to enable '
        f'Falcon Sensors to pull container image from ECR"')

      output = self.run_command(command=create_policy_command)

      if output:
        output = json.loads(output)

        return output['Policy']['Arn']
      else:
        return None

  def create_eks_fargate_trust_policy_json_file(self, account_id: str, region: str, oidc_issuer: str,
                                                namespace: str, service_account: str) -> str | None:
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
      file_name: str = './abstrakt/conf/aws/eks/policies/sensor-eks-fargate-trust-policy.json'
    elif service_account == 'falcon-kac-sa':
      file_name: str = './abstrakt/conf/aws/eks/policies/kac-eks-fargate-trust-policy.json'
    elif service_account == 'image-analyzer-falcon-image-analyzer':
      file_name: str = './abstrakt/conf/aws/eks/policies/iar-eks-fargate-trust-policy.json'
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

  def create_and_get_eks_fargate_role(self, account_id: str, region: str, oidc_issuer: str,
                                      iam_role: str, namespace: str, service_account: str) -> str | None:
    file_name: str = self.create_eks_fargate_trust_policy_json_file(account_id=account_id,
                                                                    region=region,
                                                                    oidc_issuer=oidc_issuer,
                                                                    namespace=namespace,
                                                                    service_account=service_account)

    if file_name is None:
      return None

    iam_role_arn = self.check_aws_iam_role(iam_role)

    if iam_role_arn is None:
      command = f'aws iam create-role --role-name {iam_role} --assume-role-policy-document file://{file_name}'

      output = self.run_command(command=command)

      if output is not None:
        output = json.loads(output)
        return output['Role']['Arn']

      return None
    else:
      return iam_role_arn

  def set_and_attach_policy_to_iam_role(self, region: str, namespace: str,
                                        service_account: str, iam_role: str, cluster_name: str) -> str | None:
    permission_policy_arn = self.create_and_get_eks_fargate_permissions_policy(permission_policy=self.iam_policy,
                                                                               region=region)
    if not permission_policy_arn:
      return None

    account_id = self.get_aws_account_id()
    if not account_id:
      return None

    oidc_issuer = self.get_cluster_oidc_issuer(region=region, cluster_name=cluster_name)
    if not oidc_issuer:
      return None

    iam_role_arn = self.create_and_get_eks_fargate_role(account_id=account_id,
                                                        region=region,
                                                        oidc_issuer=oidc_issuer,
                                                        iam_role=iam_role,
                                                        namespace=namespace,
                                                        service_account=service_account)
    if not iam_role_arn:
      return None

    if self.attach_policy_to_iam_role(policy_arn=permission_policy_arn, iam_role_arn=iam_role_arn):
      return iam_role_arn
    return None
