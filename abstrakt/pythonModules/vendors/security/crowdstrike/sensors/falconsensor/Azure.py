import os
import json
import subprocess
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
               acr_rg: str):
    super().__init__(falcon_client_id, falcon_client_secret, logger, registry, repository)

    self.rg_name: str = rg_name
    self.rg_location: str = rg_location
    self.acr_rg: str = acr_rg

  def set_subscription(self, subscription_id: str, logger=None) -> bool:
    logger = logger or self.logger

    try:
      command: str = f'az account set --subscription {subscription_id}'
      self.run_command(command=command, logger=logger)

      return True

    except Exception as e:
      logger.error(e)
      return False

  def login_to_acr(self, acr: str, logger=None) -> bool:
    logger = logger or self.logger

    try:
      command: str = f'az acr login --name {acr}'
      return True if self.run_command(command=command, logger=logger) else False

    except Exception as e:
      logger.error(e)
      return False

  def get_acr_fqdn(self, acr: str, logger=None) -> str | None:
    logger = logger or self.logger

    try:
      command: str = f'az acr show --name {acr} --query "loginServer"'
      output, error = self.run_command(command=command, logger=logger)

      return output if output else None

    except Exception as e:
      logger.error(e)
      return None

  def get_subscription_id_by_resource_group(self, resource_group_name, logger=None):
    logger = logger or self.logger

    try:
      # Run the Azure CLI command
      result = subprocess.run(
        ['az', 'group', 'show', '--name', resource_group_name, '--query', 'id'],
        capture_output=True,
        text=True,
        check=True
      )

      # Parse the output
      resource_id = json.loads(result.stdout.strip())

      # Extract the subscription ID from the resource ID
      subscription_id = resource_id.split('/')[2]

      return subscription_id
    except subprocess.CalledProcessError as e:
      logger.error(e)
      return None

  def check_acr_registry_exists(self, registry: str, acr_sub_id: str, acr_rg: str, logger=None) -> bool:
    logger = logger or self.logger

    try:
      credential = DefaultAzureCredential()

      client = ContainerRegistryManagementClient(credential, acr_sub_id)

      client.registries.get(acr_rg, registry.split('.')[0])
      logger.info(f"Azure Container Registry '{registry}' exists.")
      return True

    except Exception as e:
      logger.error(e)
      logger.error(f"Azure Container Registry '{registry}' does not exist.")
      return False

  def check_acr_repository_exists(self, acr_sub_id: str, acr_rg: str, registry: str,
                                  repository: str, logger=None) -> bool:
    logger = logger or self.logger

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
        logger.info(f"Repository '{repository}' exists in registry '{registry}'.")
        return True
      else:
        logger.error(f"Repository '{repository}' does not exist in registry '{registry}'.")
        return False
    except Exception as e:
      logger.error(e)
      print(f"Repository '{repository}' does not exist in registry '{registry}'.")
      return False

  def check_image_exists_on_acr(self, registry: str, repository: str, image_tag: str, logger=None) -> bool:
    logger = logger or self.logger

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
          logger.info(f"Tag '{image_tag}' found in repository '{repository}'.")
          return True

      logger.error(f"Tag '{image_tag}' not found in repository '{repository}'.")
      return False

    except Exception as e:
      logger.error(f"Error checking image: {e}")
      logger.error(f"Tag '{image_tag}' not found in repository '{repository}'.")
      return False

  def get_acr_registry_id(self, registry: str, logger=None) -> str | None:
    logger = logger or self.logger

    command = f'az acr show --name {registry} --query id --output tsv'

    try:
      output, error = self.run_command(command=command, logger=logger)

      return output.strip() if output is not None else None

    except Exception as e:
      logger.error(e)
      return None

  def create_az_service_principal(self, registry, sp_name, logger=None) -> str | None:
    logger = logger or self.logger

    try:
      acr_registry_id: str = self.get_acr_registry_id(registry=registry)

      if acr_registry_id:
        command = (f'az ad sp create-for-rbac --name {sp_name} --scopes {acr_registry_id} '
                   f'--role acrpush --query password --output tsv')

        output, error = self.run_command(command=command, logger=logger)

        return output.strip() if output is not None else None

    except Exception as e:
      logger.error(e)
      return None

  def get_az_service_principal_id(self, sp_name: str, logger=None) -> str | None:
    logger = logger or self.logger

    try:
      command: str = f"""az ad sp list --filter "displayName eq '{sp_name}'" --query "[].appId" -o tsv"""

      output, error = self.run_command(command=command, logger=logger)

      return output.strip() if output is not None else None

    except Exception as e:
      logger.error(e)
      return None

  def get_aks_credentials(self, resource_group, cluster_name, logger=None) -> bool:
    logger = logger or self.logger
    try:
      command = f'az aks get-credentials --resource-group {resource_group} --name {cluster_name}'

      output, error = self.run_command(command=command, logger=logger)

      return True if output is not None else False

    except Exception as e:
      logger.error(e)
      return False

  def set_az_service_principal_credentials(self, registry, sp_name, logger=None) -> tuple:
    logger = logger or self.logger

    try:
      az_password = self.create_az_service_principal(registry=registry, sp_name=sp_name)
      az_username = self.get_az_service_principal_id(sp_name=sp_name)

      filename = './abstrakt/conf/azure/service_principal.conf'

      with open(filename, 'a') as file:
        file.write(f'{az_username}:{az_password}\n')

      logger.info('Waiting for 30 seconds for Azure to propagate new service principal credentials')
      sleep(30)

      return az_username, az_password

    except Exception as e:
      logger.error(e)
      return None, None

  def check_service_principal_exists(self, sp_name, logger=None) -> bool:
    logger = logger or self.logger

    command = f"""az ad sp list --filter "displayName eq '{sp_name}'" --query "[].appId" -o tsv"""

    output, error = self.run_command(command=command, logger=logger)

    return True if output is not None else False

  def get_service_principal_credentials(self, registry: str, sp_name: str, sp_pass: str, logger=None) -> tuple:
    logger = logger or self.logger

    try:
      registry = registry.split('.azurecr.io/')[0]

      filename = './abstrakt/conf/azure/service_principal.conf'

      if sp_pass is not None:
        if self.check_service_principal_exists(sp_name=sp_name, logger=logger):
          service_principal_id = self.get_az_service_principal_id(sp_name=sp_name, logger=logger)
          return service_principal_id, sp_pass
        else:
          return None, None
      elif sp_pass is None:
        if self.check_service_principal_exists(sp_name=sp_name, logger=logger):
          service_principal_id = self.get_az_service_principal_id(sp_name=sp_name, logger=logger)

          if os.path.exists(filename):
            with open(filename, 'r') as file:
              while True:
                line = file.readline()
                if not line:  # If the line is empty, end of file is reached
                  break
                az_username, az_password = line.rstrip().split(':')
                if az_username == service_principal_id or az_username in service_principal_id:
                  return az_username, az_password

              logger.error(f'No password was provided for {sp_name} as a runtime parameter or was found from '
                           f'abstrakt/conf/azure/service_principal.conf file.')
              logger.error(f'Provide password for {sp_name} either as a runtime parameter or store under '
                           f'abstrakt/conf/azure/service_principal.conf file')
              return service_principal_id, None
          else:
            return service_principal_id, None
        else:
          az_username, az_password = self.set_az_service_principal_credentials(
            registry=registry, sp_name=sp_name, logger=logger
          )
          return az_username, az_password

      return None, None

    except Exception as e:
      logger.error(e)
      return None, None

  def get_acr_pull_secret(self, registry: str, sp_name: str, sp_pass: str, logger=None) -> str | None:
    logger = logger or self.logger

    try:
      command = (f'kubectl create secret docker-registry acr-pull-secret --docker-server={registry} '
                 f'--docker-username={sp_name} --docker-password={sp_pass} --dry-run=client -o json')

      output, error = self.run_command(command=command, logger=logger)

      return output.strip() if output is not None else None

    except Exception as e:
      logger.error(e)
      return None

  def copy_crowdstrike_image_to_acr(self, source_image_repo, source_image_tag, target_registry, repository,
                                    az_username, az_password, logger=None) -> bool:
    logger = logger or self.logger

    command = (f'skopeo copy --src-creds {self.falcon_art_username}:{self.falcon_art_password} '
               f'--dest-creds {az_username}:{az_password} '
               f'--multi-arch all docker://{source_image_repo}:{source_image_tag} '
               f'docker://{target_registry}/{repository}:{source_image_tag}')

    output, error = self.run_command(command=command, logger=logger)

    return True if output is not None else False

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
                          acr_rg: str, sp_name: str, sp_pass: str, sensor_type: str, logger=None) -> str | None:
    logger = logger or self.logger

    if registry_type == 'crwd':
      if 'latest' in image_tag:
        return self.get_crowdstrike_sensor_image_tag(sensor_type=sensor_type, image_tag=image_tag, logger=logger)
      elif self.verify_crowdstrike_sensor_image_tag(image_tag=image_tag, sensor_type=sensor_type, logger=logger):
        return image_tag
      return None

    acr_sub_id = self.get_subscription_id_by_resource_group(resource_group_name=acr_rg, logger=logger)

    if acr_sub_id is None:
      logger.error(f'Failed to retrieve subscription id of {acr_rg}')
      return None

    if registry_type == 'acr' and self.check_acr_registry_exists(registry=registry, acr_sub_id=acr_sub_id,
                                                                 acr_rg=acr_rg, logger=logger):
      if 'latest' in image_tag:
        image_tag: str = self.get_crowdstrike_sensor_image_tag(sensor_type=sensor_type, image_tag=image_tag,
                                                               logger=logger)
      elif not self.verify_crowdstrike_sensor_image_tag(image_tag=image_tag, sensor_type=sensor_type,
                                                        logger=logger):
        return None

      if self.check_image_exists_on_acr(registry=registry, repository=repository, image_tag=image_tag, logger=logger):
        return image_tag

      source_registry = self.get_crowdstrike_registry(sensor_type=sensor_type)

      if self.copy_crowdstrike_image_to_acr(source_image_repo=source_registry, source_image_tag=image_tag,
                                            target_registry=registry, repository=repository, az_username=sp_name,
                                            az_password=sp_pass, logger=logger):
        if self.check_image_exists_on_acr(registry=registry, repository=repository, image_tag=image_tag, logger=logger):
          return image_tag

    return None

  def get_azure_image_pull_token(self, registry: str, registry_type: str, sp_name: str,
                                 sp_pass: str, logger=None) -> str | None:
    logger = logger or self.logger

    if registry_type == 'crwd':
      return self.get_crowdstrike_image_pull_token()
    elif registry_type == 'acr':
      image_pull_token = self.get_acr_pull_secret(registry=registry, sp_name=sp_name, sp_pass=sp_pass, logger=logger)

      return json.loads(image_pull_token)['data']['.dockerconfigjson']
    else:
      return None
