import os
import json
from time import sleep

from azure.identity import DefaultAzureCredential
from azure.containerregistry import ContainerRegistryClient
from azure.mgmt.containerregistry import ContainerRegistryManagementClient

from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.CrowdStrikeSensors import CrowdStrikeSensors


class Azure(CrowdStrikeSensors):
  def __init__(self, falcon_client_id: str,
               falcon_client_secret: str,
               logger,
               registry: str,
               repository: str,
               rg_name: str,
               rg_location: str,
               acr_rg: str,
               acr_sub_id: str):
    super().__init__(falcon_client_id, falcon_client_secret, logger, registry, repository)

    self.rg_name: str = rg_name
    self.rg_location: str = rg_location
    self.acr_rg: str = acr_rg
    self.acr_sub_id: str = acr_sub_id

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
      output = self.run_command(command=command)

      return output if output else None

    except Exception as e:
      self.logger.error(e)
      return None

  def check_acr_registry_exists(self, registry: str, acr_sub_id: str, acr_rg: str) -> bool:
    try:
      credential = DefaultAzureCredential()

      client = ContainerRegistryManagementClient(credential, acr_sub_id)

      client.registries.get(acr_rg, registry.split('.')[0])
      self.logger.info(f"Azure Container Registry '{registry}' exists.")
      return True

    except Exception as e:
      self.logger.error(e)
      self.logger.error(f"Azure Container Registry '{registry}' does not exist.")
      return False

  def check_acr_repository_exists(self, acr_sub_id: str, acr_rg: str, registry: str, repository: str) -> bool:
    try:
      # Authenticate using DefaultAzureCredential
      credential = DefaultAzureCredential()

      # Initialize the ContainerRegistryManagementClient
      acr_client = ContainerRegistryManagementClient(credential, acr_sub_id)

      # Get the registry's login server
      registry = acr_client.registries.get(acr_rg, registry.split('.')[0])
      login_server = registry.login_server

      # Initialize the ContainerRegistryClient to interact with the registry
      container_registry_client = ContainerRegistryClient(f"https://{login_server}", credential)

      # List all repositories and check if the specified one exists
      repositories = container_registry_client.list_repository_names()

      if repository in repositories:
        self.logger.info(f"Repository '{repository}' exists in registry '{registry}'.")
        return True
      else:
        self.logger.error(f"Repository '{repository}' does not exist in registry '{registry}'.")
        return False
    except Exception as e:
      self.logger.error(e)
      print(f"Repository '{repository}' does not exist in registry '{registry}'.")
      return False

  def check_image_exists_on_acr(self, registry: str, repository: str, image_tag: str) -> bool:
    try:
      if '.azurecr.io' not in registry:
        registry_url = f"https://{registry}.azurecr.io"
      else:
        registry_url = f'https://{registry}'

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

  def get_acr_registry_id(self, registry: str) -> str | None:

    command = f'az acr show --name {registry} --query id --output tsv'

    try:
      output = self.run_command(command=command)

      if output:
        return output.strip()
      else:
        return None

    except Exception as e:
      self.logger.error(e)
      return None

  def create_az_service_principal(self, registry, sp_name) -> str | None:
    try:
      acr_registry_id: str = self.get_acr_registry_id(registry=registry)

      if acr_registry_id:
        command = (f'az ad sp create-for-rbac --name {sp_name} --scopes {acr_registry_id} '
                   f'--role acrpush --query password --output tsv')

        output = self.run_command(command=command)

        return output.strip() if output else None

    except Exception as e:
      print(e)
      self.logger.error(e)
      return None

  def get_az_service_principal_id(self, sp_name: str) -> str | None:
    try:
      command: str = f"""az ad sp list --filter "displayName eq '{sp_name}'" --query "[].appId" -o tsv"""

      output = self.run_command(command=command)

      return output.strip() if output and output != '//EMPTY' else None

    except Exception as e:
      self.logger.error(e)
      return None

  def get_aks_credentials(self, resource_group, cluster_name) -> bool:
    try:
      command = f'az aks get-credentials --resource-group {resource_group} --name {cluster_name}'

      return True if self.run_command(command=command) else False

    except Exception as e:
      self.logger.error(e)
      return False

  def set_az_service_principal_credentials(self, registry, sp_name) -> tuple:
    try:
      az_password = self.create_az_service_principal(registry=registry, sp_name=sp_name)
      az_username = self.get_az_service_principal_id(sp_name=sp_name)

      filename = './abstrakt/conf/azure/service_principal.conf'

      with open(filename, 'a') as file:
        file.write(f'{az_username}:{az_password}\n')

      self.logger.info('Waiting for 30 seconds for Azure to replicate new service principal credentials')
      sleep(30)

      return az_username, az_password

    except Exception as e:
      self.logger.error(e)
      return None, None

  # Check
  def check_service_principal_exists(self, sp_name):
    command = f"""az ad sp list --filter "displayName eq '{sp_name}'" --query "[].appId" -o tsv"""

    output = self.run_command(command=command)

    if output and output != '//EMPTY':
      return True
    else:
      return False

  def get_service_principal_credentials(self, registry: str, sp_name: str, sp_pass: str) -> tuple:
    try:
      registry = registry.split('.azurecr.io/')[0]

      filename = './abstrakt/conf/azure/service_principal.conf'

      if sp_pass is not None:
        if self.check_service_principal_exists(sp_name=sp_name):
          service_principal_id = self.get_az_service_principal_id(sp_name=sp_name)
          return service_principal_id, sp_pass
        else:
          return None, None
      elif sp_pass is None:
        if self.check_service_principal_exists(sp_name=sp_name):
          service_principal_id = self.get_az_service_principal_id(sp_name=sp_name)

          if os.path.exists(filename):
            with open(filename, 'r') as file:
              while True:
                line = file.readline()
                if not line:  # If the line is empty, end of file is reached
                  break
                az_username, az_password = line.rstrip().split(':')
                if az_username == service_principal_id or az_username in service_principal_id:
                  return az_username, az_password

              return service_principal_id, None
          else:
            return service_principal_id, None
        else:
          az_username, az_password = self.set_az_service_principal_credentials(
            registry=registry, sp_name=sp_name
          )
          return az_username, az_password

      return None, None

    except Exception as e:
      self.logger.error(e)
      return None, None

  def get_acr_pull_secret(self, registry: str, sp_name: str, sp_pass: str) -> str | None:
    try:
      command = (f'kubectl create secret docker-registry acr-pull-secret --docker-server={registry} '
                 f'--docker-username={sp_name} --docker-password={sp_pass} --dry-run=client -o json')

      output = self.run_command(command=command)

      return output.strip() if output else None

    except Exception as e:
      self.logger.error(e)
      return None

  def copy_crowdstrike_image_to_acr(self, source_image_repo, source_image_tag, target_registry, repository,
                                    az_username, az_password) -> bool:
    command = (f'skopeo copy --src-creds {self.falcon_art_username}:{self.falcon_art_password} '
               f'--dest-creds {az_username}:{az_password} '
               f'--multi-arch all docker://{source_image_repo}:{source_image_tag} '
               f'docker://{target_registry}/{repository}:{source_image_tag}')

    return True if self.run_command(command=command) else False

  def get_image_registry(self, registry: str, registry_type: str, sensor_type: str) -> str | None:
    if registry:
      if registry_type == 'acr':
        return f'{registry}'
      elif registry_type == 'crwd':
        return self.get_crowdstrike_registry(sensor_type=sensor_type)
      else:
        return None
    else:
      return self.get_crowdstrike_registry(sensor_type=sensor_type)

  def get_azure_image_tag(self, registry: str, registry_type: str, repository: str, image_tag: str,
                          acr_sub_id: str, acr_rg: str, sp_name: str, sp_pass: str, sensor_type: str) -> str | None:
    if registry_type == 'crwd':
      if 'latest' in image_tag:
        return self.get_crowdstrike_sensor_image_tag(sensor_type=sensor_type, image_tag=image_tag)
      elif self.verify_crowdstrike_sensor_image_tag(image_tag=image_tag, sensor_type=sensor_type):
        return image_tag
      return None

    if registry_type == 'acr' and self.check_acr_registry_exists(registry=registry, acr_sub_id=acr_sub_id,
                                                                 acr_rg=acr_rg):
      if 'latest' in image_tag:
        image_tag: str = self.get_crowdstrike_sensor_image_tag(sensor_type=sensor_type, image_tag=image_tag)
      elif not self.verify_crowdstrike_sensor_image_tag(image_tag=image_tag, sensor_type=sensor_type):
        return None

      if self.check_image_exists_on_acr(registry=registry, repository=repository, image_tag=image_tag):
        return image_tag

      source_registry = self.get_crowdstrike_registry(sensor_type=sensor_type)

      if self.copy_crowdstrike_image_to_acr(source_image_repo=source_registry, source_image_tag=image_tag,
                                            target_registry=registry, repository=repository, az_username=sp_name,
                                            az_password=sp_pass):
        if self.check_image_exists_on_acr(registry=registry, repository=repository, image_tag=image_tag):
          return image_tag

    return None

  def get_azure_image_pull_token(self, registry: str, registry_type: str, sp_name: str, sp_pass: str) -> str | None:
    if registry_type == 'crwd':
      return self.get_crowdstrike_image_pull_token()
    elif registry_type == 'acr':
      image_pull_token = self.get_acr_pull_secret(registry=registry, sp_name=sp_name, sp_pass=sp_pass)

      return json.loads(image_pull_token)['data']['.dockerconfigjson']
    else:
      return None
