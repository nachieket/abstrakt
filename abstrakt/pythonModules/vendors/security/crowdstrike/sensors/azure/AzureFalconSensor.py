import os
import json

from azure.identity import DefaultAzureCredential
from azure.containerregistry import ContainerRegistryClient
from azure.mgmt.containerregistry import ContainerRegistryManagementClient

from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.CrowdStrikeSensors import CrowdStrikeSensors


class AzureFalconSensor(CrowdStrikeSensors):
  def __init__(self, falcon_client_id, falcon_client_secret, logger, image_registry=None, proxy_server=None,
               proxy_port=None, sensor_tags=None, cluster_name=None, cluster_type=None, sensor_image_tag=None,
               acr_resource_group=None, acr_subscription_id=None):
    super().__init__(falcon_client_id, falcon_client_secret, logger, image_registry, proxy_server,
                     proxy_port, sensor_tags, cluster_name, cluster_type)

    self.sensor_image_tag = sensor_image_tag
    self.acr_resource_group = acr_resource_group
    self.acr_subscription_id = acr_subscription_id

  def set_subscription(self, subscription_id: str) -> bool:
    try:
      command: str = f'az account set --subscription {subscription_id}'
      self.run_command(command=command)

      return True

    except Exception as e:
      self.logger.error(e)
      return False

  def login_to_acr(self, acr: str) -> bool:
    try:
      command: str = f'az acr login --name {acr}'
      return True if self.run_command(command=command) else False

    except Exception as e:
      self.logger.error(e)
      return False

  def get_acr_fqdn(self, acr: str) -> str | None:
    try:
      command: str = f'az acr show --name {acr} --query "loginServer"'
      output, error = self.run_command(command=command, output=True)

      if output is not None:
        return output
      else:
        return None

    except Exception as e:
      self.logger.error(e)
      return None

  def check_acr_exists(self, acr: str, subscription_id: str, acr_resource_group: str) -> bool:
    try:
      credential = DefaultAzureCredential()

      client = ContainerRegistryManagementClient(credential, subscription_id)

      acr = client.registries.get(acr_resource_group, acr)
      self.logger.info(f"Azure Container Registry '{acr}' exists.")
      return True

    except Exception as e:
      self.logger.error(e)
      self.logger.error(f"Azure Container Registry '{acr}' does not exist.")
      return False

  def check_if_acr_image_exists(self, registry: str, repository: str, image_tag: str) -> bool:
    try:
      if '.azurecr.io' not in registry:
        registry_url = f"https://{registry}.azurecr.io"
      else:
        registry_url = registry

      credential = DefaultAzureCredential()
      client = ContainerRegistryClient(endpoint=registry_url, credential=credential)

      tags = client.list_tag_properties(repository=repository)

      for tag in tags:
        if tag.name == image_tag:
          self.logger.info(f"Tag '{image_tag}' found in repository '{repository}'.")
          return True

      self.logger.error(f"Tag '{image_tag}' not found in repository '{repository}'.")
      return False

    except Exception as e:
      self.logger.error(f"Error checking image: {e}")
      self.logger.error(f"Tag '{image_tag}' not found in repository '{repository}'.")
      return False

  def get_acr_registry_id(self, acr_registry: str) -> str | None:

    command = f'az acr show --name {acr_registry} --query id --output tsv'

    try:
      output, error = self.run_command(command=command, output=True)

      if output:
        return output.strip()
      else:
        return None

    except Exception as e:
      self.logger.error(e)
      return None

  def create_az_service_principal(self, acr_registry, service_principal) -> str | None:
    try:
      acr_registry_id: str = self.get_acr_registry_id(acr_registry=acr_registry)

      if acr_registry_id:
        command = (f'az ad sp create-for-rbac --name {service_principal} --scopes {acr_registry_id} '
                   f'--role acrpush --query password --output tsv')

        output, error = self.run_command(command=command, output=True)

        return output.strip() if output else None

    except Exception as e:
      print(e)
      self.logger.error(e)
      return None

  def get_az_service_principal_id(self, service_principal_name: str) -> str | None:
    try:
      command: str = f'az ad sp list --display-name {service_principal_name} --query "[].appId" --output tsv'

      output, error = self.run_command(command=command, output=True)

      return output.strip() if output else None

    except Exception as e:
      self.logger.error(e)
      return None

  def get_aks_credentials(self, resource_group, cluster_name) -> bool:
    try:
      command = f'az aks get-credentials --resource-group {resource_group} --name {cluster_name}'

      return self.run_command(command=command)

    except Exception as e:
      self.logger.error(e)
      return False

  def set_az_service_principal_credentials(self, acr_registry, service_principal_name) -> tuple:
    try:
      az_password = self.create_az_service_principal(acr_registry=acr_registry,
                                                     service_principal=service_principal_name)
      az_username = self.get_az_service_principal_id(service_principal_name=service_principal_name)

      filename = './abstrakt/conf/azure/service_principal.conf'

      with open(filename, 'w') as file:
        file.write(f'{az_username}:{az_password}')

      return az_username, az_password

    except Exception as e:
      self.logger.error(e)
      return None, None

  def check_service_principal_exists(self, service_principal_name):
    command = f'az ad sp list --display-name {service_principal_name} --query "[].{{id:appId}}" --output tsv'

    output, error = self.run_command(command=command, output=True)

    return True if output else False

  def get_service_principal_password(self, service_principal_name):
    pass

  def get_service_principal_credentials(self, service_principal_name: str, service_principal_password: str,
                                        image_registry: str) -> tuple:
    try:
      registry_name, repository_name = image_registry.split('.azurecr.io/')

      filename = './abstrakt/conf/azure/service_principal.conf'

      if service_principal_password is not None:
        if self.check_service_principal_exists(service_principal_name=service_principal_name):
          service_principal_id = self.get_az_service_principal_id(service_principal_name=service_principal_name)
          return service_principal_id, service_principal_password
        else:
          return None, None
      elif service_principal_password is None:
        if self.check_service_principal_exists(service_principal_name=service_principal_name):
          service_principal_id = self.get_az_service_principal_id(service_principal_name=service_principal_name)

          if os.path.exists(filename):
            with open(filename, 'r') as file:
              while True:
                line = file.readline()
                if not line:  # If the line is empty, end of file is reached
                  break
                az_username, az_password = line.split(':')
                if az_username == service_principal_id:
                  return az_username, az_password
          else:
            return service_principal_id, None
        else:
          az_username, az_password = self.set_az_service_principal_credentials(
            acr_registry=registry_name, service_principal_name=service_principal_name
          )
          return az_username, az_password

    except Exception as e:
      self.logger.error(e)
      return None, None

  def get_acr_pull_secret(self, acr, az_username, az_password) -> str | None:
    try:
      registry, _ = acr.split('/')

      command = (f'kubectl create secret docker-registry acr-pull-secret --docker-server={registry} '
                 f'--docker-username={az_username} --docker-password={az_password} --dry-run=client -o json')

      output, error = self.run_command(command=command, output=True)

      return output.strip() if output else None

    except Exception as e:
      self.logger.error(e)
      return None

  def get_registry_type_and_url(self, sensor_type, image_registry, acr_resource_group, acr_subscription_id) -> tuple:
    if image_registry:
      registry_name, repository_name = image_registry.split('.azurecr.io/')

      registry_type = self.check_registry_type(image_registry=image_registry)

      if registry_type == 'acr_registry':
        if self.check_acr_exists(subscription_id=acr_subscription_id,
                                 acr_resource_group=acr_resource_group,
                                 acr=registry_name):
          return 'acr_registry', image_registry
        else:
          return None, None
      elif registry_type == 'crwd_registry':
        return 'crwd_registry', self.get_crwd_repo_url(sensor_type=sensor_type)
      else:
        return None, None
    else:
      return 'crwd_registry', self.get_crwd_repo_url(sensor_type=sensor_type)

  def get_crwd_daemonset_sensor_image_tag(self, image_tag) -> str | None:
    if image_tag and 'latest' in image_tag:
      return self.get_crwd_daemonset_image_tag(image_tag=image_tag)
    else:
      if self.verify_daemonset_image_tag(image_tag=image_tag):
        return image_tag

    return None

  def copy_crwd_image_to_acr(self, source_image_repo, source_image_tag, target_registry, az_username, az_password) -> (
    bool):
    command = (f'skopeo copy --src-creds {self.falcon_art_username}:{self.falcon_art_password} '
               f'--dest-creds {az_username}:{az_password} '
               f'--multi-arch all docker://{source_image_repo}:{source_image_tag} '
               f'docker://{target_registry}:{source_image_tag}')

    return True if self.run_command(command=command) else False

  def get_daemonset_image_tag(self, registry_type, image_registry: str, az_username: str,
                              az_password: str, image_tag: str = 'latest') -> str | None:
    if registry_type == 'acr_registry':
      registry_name, repository_name = image_registry.split('.azurecr.io/')

      if 'latest' not in image_tag:
        if self.verify_daemonset_image_tag(image_tag=image_tag):
          if self.check_if_acr_image_exists(registry=registry_name,
                                            repository=repository_name,
                                            image_tag=image_tag):
            return image_tag
          else:
            source_image_repo = self.get_crwd_repo_url(sensor_type='daemonset')
            source_image_tag = self.get_crwd_daemonset_image_tag(image_tag=image_tag)

            self.login_to_acr(acr=registry_name)
            self.set_subscription(subscription_id=self.acr_subscription_id)

            self.copy_crwd_image_to_acr(source_image_repo=source_image_repo,
                                        source_image_tag=source_image_tag,
                                        target_registry=image_registry,
                                        az_username=az_username,
                                        az_password=az_password)
            return source_image_tag
        else:
          return None
      elif 'latest' in image_tag:
        source_image_repo = self.get_crwd_repo_url(sensor_type='daemonset')
        source_image_tag = self.get_crwd_daemonset_image_tag(image_tag=image_tag)

        if self.check_if_acr_image_exists(registry=registry_name,
                                          repository=repository_name,
                                          image_tag=source_image_tag):
          return source_image_tag

        self.login_to_acr(acr=registry_name)
        self.set_subscription(subscription_id=self.acr_subscription_id)

        self.copy_crwd_image_to_acr(source_image_repo=source_image_repo,
                                    source_image_tag=source_image_tag,
                                    target_registry=image_registry,
                                    az_username=az_username,
                                    az_password=az_password)
        return source_image_tag
    else:
      return self.get_crwd_daemonset_image_tag(image_tag=image_tag)

  def get_kac_image_tag(self, registry_type, image_registry: str, az_username: str,
                        az_password: str, image_tag: str = 'latest') -> str | None:
    if registry_type == 'acr_registry':
      registry_name, repository_name = image_registry.split('.azurecr.io/')

      if 'latest' not in image_tag:
        if self.verify_kac_image_tag(image_tag=image_tag):
          if self.check_if_acr_image_exists(registry=registry_name,
                                            repository=repository_name,
                                            image_tag=image_tag):
            return image_tag
          else:
            source_image_repo = self.get_crwd_repo_url(sensor_type='falcon-kac')
            source_image_tag = self.get_crwd_kac_image_tag(image_tag=image_tag)

            self.login_to_acr(acr=registry_name)
            self.set_subscription(subscription_id=self.acr_subscription_id)

            self.copy_crwd_image_to_acr(source_image_repo=source_image_repo,
                                        source_image_tag=source_image_tag,
                                        target_registry=image_registry,
                                        az_username=az_username,
                                        az_password=az_password)
            return source_image_tag
        else:
          return None
      elif 'latest' in image_tag:
        source_image_repo = self.get_crwd_repo_url(sensor_type='falcon-kac')
        source_image_tag = self.get_crwd_kac_image_tag(image_tag=image_tag)

        if self.check_if_acr_image_exists(registry=registry_name,
                                          repository=repository_name,
                                          image_tag=source_image_tag):
          return source_image_tag

        self.login_to_acr(acr=registry_name)
        self.set_subscription(subscription_id=self.acr_subscription_id)

        self.copy_crwd_image_to_acr(source_image_repo=source_image_repo,
                                    source_image_tag=source_image_tag,
                                    target_registry=image_registry,
                                    az_username=az_username,
                                    az_password=az_password)
        return source_image_tag
    else:
      return self.get_crwd_kac_image_tag(image_tag=image_tag)

  def get_iar_image_tag(self, registry_type, image_registry: str, az_username: str,
                        az_password: str, image_tag: str = 'latest') -> str | None:
    if registry_type == 'acr_registry':
      registry_name, repository_name = image_registry.split('.azurecr.io/')

      if 'latest' not in image_tag:
        if self.verify_iar_image_tag(image_tag=image_tag):
          if self.check_if_acr_image_exists(registry=registry_name,
                                            repository=repository_name,
                                            image_tag=image_tag):
            return image_tag
          else:
            source_image_repo = self.get_crwd_repo_url(sensor_type='falcon-iar')
            source_image_tag = self.get_crwd_iar_image_tag(image_tag=image_tag)

            self.login_to_acr(acr=registry_name)
            self.set_subscription(subscription_id=self.acr_subscription_id)

            self.copy_crwd_image_to_acr(source_image_repo=source_image_repo,
                                        source_image_tag=source_image_tag,
                                        target_registry=image_registry,
                                        az_username=az_username,
                                        az_password=az_password)
            return source_image_tag
        else:
          return None
      elif 'latest' in image_tag:
        source_image_repo = self.get_crwd_repo_url(sensor_type='falcon-iar')
        source_image_tag = self.get_crwd_iar_image_tag(image_tag=image_tag)

        if self.check_if_acr_image_exists(registry=registry_name,
                                          repository=repository_name,
                                          image_tag=source_image_tag):
          return source_image_tag

        self.login_to_acr(acr=registry_name)
        self.set_subscription(subscription_id=self.acr_subscription_id)

        self.copy_crwd_image_to_acr(source_image_repo=source_image_repo,
                                    source_image_tag=source_image_tag,
                                    target_registry=image_registry,
                                    az_username=az_username,
                                    az_password=az_password)
        return source_image_tag
    else:
      return self.get_crwd_iar_image_tag(image_tag=image_tag)

  def get_image_pull_token(self, registry_type, registry, az_username, az_password) -> str | None:
    if registry_type == 'crwd_registry':
      return self.get_crwd_image_pull_token()
    elif registry_type == 'acr_registry':
      image_pull_token = self.get_acr_pull_secret(acr=registry, az_username=az_username, az_password=az_password)

      return json.loads(image_pull_token)['data']['.dockerconfigjson']
    else:
      return None

  def get_repo_tag_token(self, sensor_type, image_tag) -> tuple:
    registry_type, registry_uri = self.get_image_repo(sensor_type=sensor_type)

    if registry_type == 'crwd_registry':
      falcon_image_repo, falcon_image_tag, falcon_image_pull_token = self.get_crwd_repo_tag_token(
        sensor_type=sensor_type, image_tag=image_tag)

      return registry_type, falcon_image_repo, falcon_image_tag, falcon_image_pull_token
    else:
      return None, None, None, None
