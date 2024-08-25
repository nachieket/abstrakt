import json

import boto3
import base64
import inspect
import subprocess

from abstrakt.pythonModules.customLogging.customLogging import CustomLogger
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.falconsensor.daemonset._Daemonset import Daemonset


class AWSDaemonset(Daemonset):
  def __init__(self, client_id: str,
               client_secret: str,
               logger: CustomLogger,
               registry: str,
               repository: str,
               proxy_server: str,
               proxy_port: str,
               image_tag: str,
               sensor_tags: str,
               sensor_mode: str):
    super().__init__(client_id,
                     client_secret,
                     logger,
                     registry,
                     repository,
                     proxy_server,
                     proxy_port,
                     image_tag,
                     sensor_tags,
                     sensor_mode)

  def login_to_ecr_registry(self, ecr_region, ecr_repo):
    command = (f'aws ecr get-login-password --region {ecr_region} | sudo skopeo login --username AWS --password-stdin'
               f' {ecr_repo}')

    return True if self.run_command(command=command) else False

  def check_ecr_registry_exists(self, registry: str) -> bool:
    try:
      # Create an ECR client
      client = boto3.client('ecr', region_name=registry.split('.')[3])

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
      client = boto3.client('ecr', region_name=registry.split('.')[3])

      # Check if the repository exists
      client.describe_repositories(registryId=registry.split('.')[0], repositoryNames=[repository])
      self.logger.info(f'Repository {registry} does exist.')

      return True
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return False

  def create_ecr_repository(self, registry: str, repository: str) -> bool:
    # Create a boto3 client for ECR
    ecr_client = boto3.client('ecr', region_name=registry.split('.')[3])

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

  def check_image_exists_on_ecr(self, registry, repository, image_tag) -> bool:
    # Create an ECR client
    client = boto3.client('ecr', region_name=registry.split('.')[3])

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

  def copy_image_to_ecr(self, source_image_registry, source_image_tag, target_image_registry, target_image_tag) -> bool:
    command = (f'skopeo copy --multi-arch all docker://{source_image_registry}:{source_image_tag} docker:/'
               f'/{target_image_registry}:{target_image_tag}')

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

          falcon_image_pull_token = base64.b64encode(json.dumps(falcon_image_pull_data).encode()).decode()

          return falcon_image_pull_token
        else:
          return None
      except Exception as e:
        self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
        self.logger.error(f'{e}')
        return None
    else:
      return None

  def copy_crowdstrike_image_to_ecr(self, crowdstrike_registry: str, ecr_registry: str,
                                    ecr_repository: str, image_tag: str = 'latest') -> bool:
    try:
      if image_tag == 'None':
        return False

      if not self.login_to_crowdstrike_repo():
        return False

      if not self.login_to_ecr_registry(ecr_region=ecr_registry.split('.')[3], ecr_repo=ecr_repository):
        return False

      if not self.copy_image_to_ecr(source_image_registry=crowdstrike_registry, source_image_tag=image_tag,
                                    target_image_registry=ecr_registry, target_image_tag=image_tag):
        return False

      self.logger.info(f"{image_tag} copied to {ecr_registry} successfully.")
      return True
    except subprocess.CalledProcessError as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f"An error occurred while running: {e.cmd}")
      self.logger.error(f"Exit code: {e.returncode}")
      self.logger.error(f"Output: {e.output}")
      self.logger.error(f"{e.stderr}")
      return False

  def get_daemonset_image_tag(self, registry, repository, image_tag, sensor_type) -> str | None:
    registry_type = self.check_registry_type(image_registry=registry)

    if registry_type == 'crwd':
      if image_tag:
        if self.verify_crowdstrike_sensor_image_tag(image_tag=image_tag):
          return image_tag
      else:
        return self.get_crowdstrike_sensor_image_tag(sensor_type=sensor_type, image_tag=image_tag)
    elif registry_type == 'ecr':
      if self.check_ecr_registry_exists(registry=registry):
        if self.check_ecr_repository_exists(registry=registry, repository=repository):
          if 'latest' in image_tag:
            image_tag = self.get_crowdstrike_sensor_image_tag(sensor_type=sensor_type, image_tag=image_tag)

          if self.check_image_exists_on_ecr(registry=registry, repository=repository, image_tag=image_tag):
            return image_tag
          else:
            crowdstrike_registry = self.get_crowdstrike_registry(sensor_type='daemonset')

            if self.copy_crowdstrike_image_to_ecr(crowdstrike_registry=crowdstrike_registry, ecr_registry=registry,
                                                  ecr_repository=repository, image_tag=image_tag):
              return image_tag
        else:
          self.create_ecr_repository(registry=registry, repository=repository)

          crowdstrike_registry = self.get_crowdstrike_registry(sensor_type='daemonset')
          image_tag = self.get_crowdstrike_sensor_image_tag(sensor_type=sensor_type, image_tag=image_tag)

          if self.copy_crowdstrike_image_to_ecr(crowdstrike_registry=crowdstrike_registry, ecr_registry=registry,
                                                ecr_repository=repository, image_tag=image_tag):
            return image_tag

    return None

  def get_daemonset_image_pull_token(self, registry) -> str | None:
    registry_type = self.check_registry_type(image_registry=registry)

    if registry_type == 'crwd':
      return self.get_crowdstrike_image_pull_token()
    elif registry_type == 'ecr':
      return self.get_ecr_image_pull_token(registry=registry)
    else:
      return None

  def get_helm_chart(self):
    # The registry value below includes repository name - i.e. registry/repository
    registry = self.get_image_registry(image_registry=self.registry,
                                       image_repository=self.repository,
                                       sensor_type='daemonset')

    image_tag = self.get_daemonset_image_tag(registry=self.registry,
                                             repository=self.repository,
                                             image_tag=self.image_tag,
                                             sensor_type='daemonset')

    pull_token = self.get_daemonset_image_pull_token(registry=self.registry)

    if registry and image_tag and pull_token:
      helm_chart = [
        "helm", "upgrade", "--install", "daemonset-falcon-sensor", "crowdstrike/falcon-sensor",
        "-n", "falcon-system", "--create-namespace",
        "--set", f"falcon.cid={self.get_falcon_cid()}",
        "--set", f"node.image.repository={registry}",
        "--set", f"node.image.tag={image_tag}",
        "--set", f"node.image.registryConfigJSON={pull_token}",
        "--set", f'node.backend={self.sensor_mode}'
      ]

      if self.proxy_server and self.proxy_port:
        helm_chart.append("--set")
        helm_chart.append(f'falcon.apd=false')
        helm_chart.append("--set")
        helm_chart.append(f'falcon.aph=http://{self.proxy_server}')
        helm_chart.append("--set")
        helm_chart.append(f'falcon.app={self.proxy_port}')

      if self.sensor_tags:
        tags = '\\,'.join(self.sensor_tags.split(','))
        helm_chart.append("--set")
        helm_chart.append(f'falcon.tags="{tags}"')

      return helm_chart
    else:
      return False

  def execute_daemonset_falcon_sensor_thread(self) -> bool:
    helm_chart = self.get_helm_chart()

    if helm_chart is not False:
      command = ' '.join(helm_chart)

      self.logger.info(f'Running command: {command}')
      if self.run_command(command=command):
        return True
    else:
      return False

  def deploy_falcon_sensor_daemonset(self):
    print(f"{'+' * 26}\nCrowdStrike Falcon Sensor\n{'+' * 26}\n")

    print("Installing Falcon Sensor in Daemonset Mode...")

    if self.check_falcon_sensor_installation(sensor_names=['daemonset-falcon-sensor', 'falcon-helm-falcon-sensor'],
                                             namespace='falcon-system'):
      return

    if self.execute_helm_chart(self.execute_daemonset_falcon_sensor_thread):
      print("Falcon sensor installation successful\n")

      self.check_falcon_sensor_pods(pod_name='falcon-sensor', namespace='falcon-system')
    else:
      print("Falcon sensor installation failed\n")
