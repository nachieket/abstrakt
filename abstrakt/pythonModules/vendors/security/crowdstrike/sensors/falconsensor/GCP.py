import json
import base64
import inspect
import subprocess
from time import sleep
from typing import Optional

from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.CrowdStrikeSensors import CrowdStrikeSensors


class GCP(CrowdStrikeSensors):
  def __init__(self, falcon_client_id: str,
               falcon_client_secret: str,
               logger,
               registry: str,
               repository: str,
               project_id: str,
               service_account: str,
               location: str):
    super().__init__(falcon_client_id, falcon_client_secret, logger, registry, repository)

    self.project_id = project_id
    self.service_account = service_account
    self.location = location

  # def run_command(self, command: str) -> Optional[str]:
  #   """
  #   Executes a shell command and captures its output.
  #
  #   Args:
  #       command (str): The shell command to run.
  #
  #   Returns:
  #       Optional[str]: The standard output of the command if successful, None otherwise.
  #   """
  #   try:
  #     result = subprocess.run(
  #       command,
  #       shell=True,
  #       check=True,
  #       text=True,
  #       stdout=subprocess.PIPE,
  #       stderr=subprocess.PIPE
  #     )
  #
  #     # Log stderr if any, but do not treat it as a failure
  #     if result.stderr:
  #       self.logger.error(f"Command stderr: {result.stderr}")
  #
  #     if result.stdout:
  #       self.logger.info(f"Command output: {result.stdout}")
  #
  #     # Return stdout if it exists, else return an empty string
  #     return result.stdout if result.stdout else '//EMPTY'
  #
  #   except subprocess.CalledProcessError as e:
  #     self.logger.error(f"Command failed with error: {e.stderr}")
  #     return None
  #   except Exception as e:
  #     self.logger.error(f"Unexpected error occurred: {e}")
  #     return None

  def get_active_gcp_account(self, logger=None) -> Optional[str]:
    """
    Retrieves the active Google Cloud account from gcloud.

    Returns:
        str: The email of the active GCP account, or None if not found.
    """
    logger = logger or self.logger

    output, error = self.run_command(command='gcloud auth list --format=json', logger=logger)

    if not output:
      return None
    elif output == '//EMPTY':
      logger.info("No output from the gcloud command.")

    try:
      accounts = json.loads(output)
      for account in accounts:
        if account.get('status') == 'ACTIVE':
          return account.get('account')
      logger.info("No active GCP account found.")
      return None
    except (json.JSONDecodeError, Exception) as e:
      logger.error(f"Error parsing JSON: {e}")
      return None

  def check_artifact_repository_exists(self, repository: str, location: str, logger=None) -> bool:
    """
    Checks if a Google Cloud Artifact Repository exists in a given location.

    Args:
        repository (str): The name of the repository to check.
        location (str): The location/region of the repository.
        logger: Logger object

    Returns:
        bool: True if the repository exists, False otherwise.
    """
    logger = logger or self.logger

    command = (f'gcloud artifacts repositories list --location {location} --format=json '
               f'--filter="name:(repositories/{repository})"')

    output, error = self.run_command(command=command, logger=logger)
    output = output.strip()

    if not output or output == '[]':
      return False

    try:
      # Parse the output and check if the repository is found
      repositories = json.loads(output)
      if repositories and any(repo.get('name') for repo in repositories):
        logger.info(f"Repository '{repository}' exists in location '{location}'.")
        return True
      return False
    except (json.JSONDecodeError, Exception) as e:
      logger.error(f"Error parsing JSON output: {e}")
      return False

  def create_artifact_repository(self, repository: str, location: str, logger=None) -> bool:
    """
       Creates a Google Cloud Artifact Registry repository.

       Args:
           repository (str): The name of the repository to create.
           location (str): The location/region for the repository.
           logger: Logger object

       Returns:
           bool: True if the repository was successfully created, False otherwise.
    """
    logger = logger or self.logger

    command = f"""gcloud artifacts repositories create {repository} \
                  --location {location} \
                  --description "Falcon Sensor in Daemonset Mode" \
                  --repository-format docker \
                  --format json"""

    output = self.run_command(command=command, logger=logger)

    if output:
      logger.info(f"Repository '{repository}' created successfully in location '{location}'.")
      return True
    else:
      logger.error(f"Failed to create repository '{repository}' in location '{location}'.")
      return False

  def create_gcp_service_account(self, account_name: str, display_name: str,
                                 description: str, logger=None) -> Optional[str]:
    """
    Creates a Google Cloud service account.

    Args:
        account_name (str): The unique name for the service account.
        display_name (str): The display name for the service account.
        description (str): A description for the service account.
        logger: Logger object

    Returns:
        Optional[str]: The email of the created service account if successful, None otherwise.
    """
    logger = logger or self.logger

    command = f"""gcloud iam service-accounts create {account_name} \
                --description="{description}" \
                --display-name="{display_name}" \
                --format json"""

    output, error = self.run_command(command=command, logger=logger)

    if output:
      try:
        return json.loads(output).get('email')
      except (json.JSONDecodeError, Exception) as e:
        logger.error(f"Error parsing JSON response: {e}")
        return None
    else:
      logger.error("Failed to create the service account or no output received.")
      return None

  def check_service_account_exists(self, account_name: str, logger=None) -> Optional[str]:
    """
    Checks if a Google Cloud service account exists.

    Args:
        account_name (str): The name of the service account to check.
        logger: Logger object

    Returns:
        Optional[str]: The email of the service account if it exists, None otherwise.
    """
    logger = logger or self.logger

    command = f"""gcloud iam service-accounts list \
                --filter="email:({account_name}@)" \
                --format json"""

    output, error = self.run_command(command=command, logger=logger)

    if not output:
      logger.error(f"No output received when checking for service account '{account_name}'.")
      return None

    try:
      service_accounts = json.loads(output)
      if service_accounts:
        return service_accounts[0].get('email')
      else:
        logger.info(f"Service account '{account_name}' does not exist.")
        return None
    except json.JSONDecodeError as e:
      logger.error(f"Error parsing JSON response: {e}")
      return None
    except (IndexError, KeyError, Exception) as e:
      logger.error(f"Unexpected data format: {e}")
      return None

  def assign_role_binding(self, service_account: str, member: str, role: str, logger=None) -> Optional[dict]:
    """
    Assigns the 'roles/iam.serviceAccountUser' role to a member for the specified service account.

    Args:
        service_account (str): The email of the service account.
        member (str): The user or service account to which the role is being assigned.
        role (str): The role that will be assigned to a service account
        logger: Logger object

    Returns:
        Optional[dict]: The updated IAM policy if successful, None otherwise.
    """
    logger = logger or self.logger

    command = f"""gcloud iam service-accounts add-iam-policy-binding {service_account} \
                --member="user:{member}" \
                --role="roles/{role}" \
                --format json"""

    output, error = self.run_command(command=command, logger=logger)

    if not output:
      logger.error(f"Failed to bind 'roles/{role}' to {service_account}")
      return None

    try:
      policy = json.loads(output)
      logger.info(f"Successfully bound 'roles/{role}' to {service_account}")
      return policy
    except (json.JSONDecodeError, Exception) as e:
      logger.error(f"Error parsing JSON response: {e}")
      return None

  def check_role_binding(self, service_account: str, member: str, role: str, logger=None) -> bool:
    """
    Checks if a specific role is bound to a member for a given service account.

    Args:
        service_account (str): The email of the service account.
        member (str): The member to check (e.g., user, group).
        role (str): The role to check (e.g., 'iam.serviceAccountUser').
        logger: Logger object

    Returns:
        bool: True if the role is bound to the member, False otherwise.
    """
    logger = logger or self.logger

    command = f'gcloud iam service-accounts get-iam-policy {service_account} --format json'

    output, error = self.run_command(command=command, logger=logger)

    if not output:
      self.logger.info(f"Failed to get IAM policy for service account: {service_account}")
      return False

    try:
      roles = json.loads(output)

      # Check if 'bindings' exist and iterate over them
      bindings = roles.get('bindings', [])
      for binding in bindings:
        if binding['role'] == f'roles/{role}':
          if f"user:{member}" in binding['members']:
            return True
      return False

    except json.JSONDecodeError as e:
      logger.error(f"Error parsing JSON response: {e}")
      return False
    except Exception as e:
      logger.error(f"Unexpected error: {e}")
      return False

  def assign_iam_policy_binding(self, repository: str, location: str,
                                service_account_email: str, role: str, logger=None) -> Optional[dict]:
    """
    Assigns an IAM policy binding to a Google Cloud Artifact Registry repository.

    Args:
        repository (str): The name of the artifact repository.
        location (str): The location/region of the repository.
        service_account_email (str): The member to assign the role to (e.g., user, group).
        role (str): The role to assign (e.g., 'artifactregistry.reader').
        logger: Logger object

    Returns:
        Optional[dict]: The updated IAM policy if successful, None otherwise.
    """
    logger = logger or self.logger

    command = f"""gcloud artifacts repositories add-iam-policy-binding {repository} \
                    --location={location} \
                    --member="serviceAccount:{service_account_email}" \
                    --role="roles/{role}" \
                    --format json"""

    output, error = self.run_command(command=command, logger=logger)

    if not output:
      logger.error(f"Failed to bind 'roles/{role}' to {repository}")
      return None

    try:
      policy = json.loads(output)
      logger.info(f"Successfully bound '{service_account_email}' with 'roles/{role}' to {repository}")
      return policy
    except json.JSONDecodeError as e:
      logger.error(f"Error parsing JSON response: {e}")
      return None
    except Exception as e:
      logger.error(f"Unexpected error: {e}")
      return None

  def check_iam_policy_binding(self, repository: str, location: str, service_account: str,
                               member: str, role: str, logger=None) -> bool:
    """
        Checks if a specific IAM policy binding exists for a Google Cloud Artifact Registry repository.

        Args:
            repository (str): The name of the artifact repository.
            location (str): The location/region of the repository.
            service_account (str): GCP service account.
            member (str): The member to check (e.g., user, group).
            role (str): The role to check (e.g., 'artifactregistry.admin').
            logger: Logger object

        Returns:
            bool: True if the IAM policy binding exists, False otherwise.
    """
    logger = logger or self.logger

    command = f'gcloud artifacts repositories get-iam-policy {repository} --location {location} --format json'

    output, error = self.run_command(command=command, logger=logger)

    if not output:
      logger.error(f"Failed to get IAM policy for service account: {service_account}")
      return False

    try:
      roles = json.loads(output)

      # Check if 'bindings' exist and iterate over them
      bindings = roles.get('bindings', [])
      for binding in bindings:
        if binding['role'] == f'roles/{role}':
          if f"user:{member}" in binding['members']:
            return True
      return False

    except json.JSONDecodeError as e:
      logger.error(f"Error parsing JSON response: {e}")
      return False
    except Exception as e:
      logger.error(f"Unexpected error: {e}")
      return False

  def generate_access_token(self, service_account_email: str, logger=None) -> Optional[str]:
    """
    Retrieves an access token for the specified service account using impersonation.

    Args:
        service_account_email (str): The email of the service account to impersonate.
        logger: Logger object

    Returns:
        Optional[str]: The access token if successful, None otherwise.
    """
    logger = logger or self.logger

    command = f'gcloud auth print-access-token --impersonate-service-account {service_account_email} --format json'

    output, error = self.run_command(command=command, logger=logger)

    if not output:
      logger.error(f"Failed to get access token for service account: {service_account_email}")
      return None

    try:
      token_data = json.loads(output)
      return token_data.get('token', None)
    except json.JSONDecodeError as e:
      logger.error(f"Error parsing JSON response: {e}")
      return None
    except KeyError:
      logger.error(f"Token not found in the response for service account: {service_account_email}")
      return None
    except Exception as e:
      logger.error(f"Unexpected error: {e}")
      return None

  def get_access_token(self, repository: str, location: str, service_account: str,
                       display_name: str = 'Abstrakt', description: str = 'Abstrakt Service Account',
                       wait_time: int = 100, logger=None) -> Optional[str]:
    """
      Retrieves an access token for a service account, creating the service account and repository if they do not exist.

        Args:
          repository (str): The name of the artifact repository to check or create.
          location (str): The location/region of the repository.
          service_account (str): The name of the service account to check or create.
          display_name (str): The display name for the service account if it needs to be created.
          description (str): A description for the service account if it needs to be created.
          wait_time (int, optional): Time in seconds to wait for the service account and IAM policies to propagate.
                                      Defaults to 100 seconds.
          logger: Logger object

      Returns:
          Optional[str]: The access token for the service account if successful, or None if the operation fails.
    """
    logger = logger or self.logger

    # Get the active GCP account
    active_gcp_account = self.get_active_gcp_account(logger=logger)
    if not active_gcp_account:
      logger.error('Script did not finish: No active GCP account.')
      return None

    # Check if the artifact repository exists; if not, create it
    if not self.check_artifact_repository_exists(repository=repository, location=location, logger=logger):
      if not self.create_artifact_repository(repository=repository, location=location, logger=logger):
        logger.error('Script did not finish: Failed to create artifact repository.')
        return None

    wait_for_service_account_creation = False
    service_account_email = self.check_service_account_exists(account_name=service_account, logger=logger)

    # Create the service account if it does not exist
    if not service_account_email:
      wait_for_service_account_creation = True
      service_account_email = self.create_gcp_service_account(account_name=service_account,
                                                              display_name=display_name,
                                                              description=description,
                                                              logger=logger)
      if not service_account_email:
        logger.error('Script did not finish: Failed to create service account.')
        return None

    # Assign required roles to the service account
    # service_account_roles = ['iam.serviceAccountUser', 'iam.serviceAccountAdmin', 'iam.serviceAccountTokenCreator']
    service_account_roles = ['iam.serviceAccountUser', 'iam.serviceAccountTokenCreator']
    for role in service_account_roles:
      if not self.check_role_binding(service_account=service_account_email, member=active_gcp_account,
                                     role=role, logger=logger):
        if not self.assign_role_binding(service_account=service_account_email, member=active_gcp_account,
                                        role=role, logger=logger):
          logger.error(f'Script did not finish: Failed to assign role {role} to {service_account_email}.')
          return None

    # Assign IAM policy bindings to the artifact repository
    # repository_roles = ['artifactregistry.admin', 'artifactregistry.reader',
    #                     'artifactregistry.repoAdmin', 'artifactregistry.writer']
    repository_roles = ['artifactregistry.reader', 'artifactregistry.writer']
    for role in repository_roles:
      if not self.check_iam_policy_binding(repository=repository,
                                           location=location,
                                           service_account=service_account,
                                           member=active_gcp_account,
                                           role=role,
                                           logger=logger):
        if not self.assign_iam_policy_binding(repository=repository,
                                              location=location,
                                              service_account_email=service_account_email,
                                              role=role,
                                              logger=logger):
          logger.error(f'Script did not finish: Failed to assign IAM policy {role} to {service_account_email}.')
          return None

    # Wait for the service account to propagate in GCP
    if wait_for_service_account_creation:
      logger.info(f'Waiting for {wait_time} seconds to allow the service account to propagate.')
      sleep(wait_time)

    # Get and print the access token
    access_token = self.generate_access_token(service_account_email=service_account_email, logger=logger)
    if access_token:
      return access_token
    else:
      logger.error('Script did not finish: Failed to retrieve access token.')
      return None

  def check_image_exists_on_artifact_repository(self, registry: str, repository: str,
                                                project: str, image_tag: str, logger=None) -> bool:
    """
    Checks if a specific image tag exists in a Google Artifact Registry repository.

    Args:
        registry (str): The atrifact registry fqdn.
        repository (str): The name of the artifact repository.
        project (str): GCP Project ID.
        image_tag (str): The name of the image (e.g., 'my-image').
        logger: Logger object

    Returns:
        bool: True if the image tag exists, False otherwise.
    """
    logger = logger or self.logger

    command = f'gcloud artifacts docker images list {registry}/{project}/{repository}/{image_tag.lower()} --format json'

    try:
      # Run the command and capture the output
      output, error = self.run_command(command=command, logger=logger)
      output = json.loads(output)

      # Check if any of the tags match
      if output:
        return True
      return False

    except subprocess.CalledProcessError as e:
      logger.error(f"Failed to list image tags: {e.stderr}")
      return False
    except json.JSONDecodeError as e:
      logger.error(f"Error parsing JSON response: {e}")
      return False
    except Exception as e:
      logger.error(e)
      return False

  def copy_crowdstrike_image_to_artifact_repository(self, source_registry: str, target_registry: str,
                                                    project: str, repository: str, image_tag: str,
                                                    access_token: str, logger=None) -> bool:
    """
    Copies a container image from the CrowdStrike registry to the Google Artifact Registry.

    Args:
        source_registry (str): The source container registry URL.
        target_registry (str): The target Google Artifact Registry URL.
        project (str): The GCP project ID where the repository is located.
        repository (str): The target Google Artifact Repository
        image_tag (str): The tag of the image to copy.
        access_token (str): The access token to use for authentication.
        logger: Logger object

    Returns:
        bool: True if the image was copied successfully, False otherwise.
    """
    logger = logger or self.logger

    # Construct the skopeo command to copy the image
    command = (f'skopeo copy --src-creds {self.falcon_art_username}:{self.falcon_art_password} '
               f'--dest-creds oauth2accesstoken:{access_token} '
               f'--multi-arch all docker://{source_registry}:{image_tag} '
               f'docker://{target_registry}/{project}/{repository}/{image_tag.lower()}:{image_tag}')

    # Run the command and capture the output
    try:
      result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True,
                              shell=True)
      logger.info(f"Image copied successfully: {result.stdout}")
      return True
    except (subprocess.CalledProcessError, Exception) as e:
      logger.error(f"Error copying image: {e.stderr}")
      return False

  def get_artifact_partial_pull_token(self, access_token: str, logger=None) -> str | None:
    logger = logger or self.logger

    try:
      output = f'oauth2accesstoken:{access_token}'
      partial_pull_token = (base64.b64encode(output.encode()).decode())
      return partial_pull_token
    except Exception as e:
      logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      logger.error(f'{e}')
      return None

  def get_artifact_image_pull_token(self, registry: str, access_token: str, logger=None) -> str | None:
    logger = logger or self.logger

    partial_pull_token: str = self.get_artifact_partial_pull_token(access_token=access_token)

    if self.add_crowdstrike_helm_repo(logger=logger) is True:
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
        logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
        logger.error(f'{e}')
        return None
    else:
      return None

  def get_image_registry(self, registry: str, registry_type: str, sensor_type: str) -> Optional[str]:
    """
    Determines the image registry URL based on the registry type and sensor type.

    Args:
        registry (str): The registry URL provided.
        registry_type (str): The type of the registry ('gcr' or 'crwd').
        sensor_type (str): The sensor type, used to determine the CrowdStrike registry.

    Returns:
        Optional[str]: The registry URL or None if the registry type is invalid.
    """
    if registry:
      if registry_type == 'artifact':
        return registry
      elif registry_type == 'crwd':
        return self.get_crowdstrike_registry(sensor_type=sensor_type)
      return None
    return self.get_crowdstrike_registry(sensor_type=sensor_type)

  def get_image_tag(self, registry: str, registry_type: str, repository: str, image_tag: str, location: str,
                    project: str, access_token: str, sensor_type: str, logger=None) -> Optional[str]:
    """
        Retrieves the full image tag for a specified image in a container registry.

        Args:
            registry (str): The URL of the container registry (e.g., 'europe-west2-docker.pkg.dev').
            registry_type (str): Type of registry (crwd or artifact)
            repository (str): The name of the repository where the image is stored.
            image_tag (str): The specific tag of the image (e.g., 'latest').
            location (str): The location/region of the registry (e.g., 'europe-west2').
            project (str): The GCP project ID where the repository is located.
            access_token (str): The access token used for authentication.
            sensor_type (str): The type of sensor for which the image is intended (used for internal logic).
            logger: Logger object

        Returns:
            Optional[str]: The full image tag if it can be constructed or retrieved successfully,
                           or None if the operation fails or if the image does not exist.
        """
    logger = logger or self.logger

    if registry_type == 'crwd':
      if 'latest' in image_tag:
        return self.get_crowdstrike_sensor_image_tag(sensor_type=sensor_type, image_tag=image_tag, logger=logger)
      elif self.verify_crowdstrike_sensor_image_tag(image_tag=image_tag, sensor_type=sensor_type, logger=logger):
        return image_tag
      return None

    if registry_type == 'artifact':
      if not self.check_artifact_repository_exists(repository=repository, location=location, logger=logger):
        self.create_artifact_repository(repository=repository, location=location, logger=logger)

      if 'latest' in image_tag:
        image_tag: str = self.get_crowdstrike_sensor_image_tag(sensor_type=sensor_type, image_tag=image_tag,
                                                               logger=logger)
      elif not self.verify_crowdstrike_sensor_image_tag(image_tag=image_tag, sensor_type=sensor_type, logger=logger):
        return None

      if self.check_image_exists_on_artifact_repository(registry=registry, repository=repository,
                                                        project=project, image_tag=image_tag, logger=logger):
        return image_tag

      source_registry = self.get_crowdstrike_registry(sensor_type=sensor_type)

      if self.copy_crowdstrike_image_to_artifact_repository(source_registry=source_registry,
                                                            target_registry=registry, project=project,
                                                            repository=repository, image_tag=image_tag,
                                                            access_token=access_token, logger=logger):
        if self.check_image_exists_on_artifact_repository(registry=registry, repository=repository,
                                                          project=project, image_tag=image_tag, logger=logger):
          return image_tag

    return None

  def get_image_pull_token(self, registry: str, access_token: str, logger=None) -> Optional[str]:
    """
    Retrieves an image pull token for the specified container registry.

    Determines the registry type (CrowdStrike or Google Artifact Registry) and returns the appropriate
    image pull token. Returns None if the registry type is unrecognized.

    Args:
        registry (str): The URL of the container registry (e.g., 'europe-west2-docker.pkg.dev' or
        'registry.crowdstrike.com').
        access_token (str): The access token used for authentication
        logger: Logger object

    Returns:
        Optional[str]: The image pull token for the specified registry, or None if the registry type is not recognized.
    """
    logger = logger or self.logger

    registry_type: str = self.check_registry_type(registry=registry, logger=logger)

    if registry_type == 'crwd':
      return self.get_crowdstrike_image_pull_token(logger=logger)

    if registry_type == 'artifact':
      return self.get_artifact_image_pull_token(registry=registry, access_token=access_token, logger=logger)

    # Log an error if the registry type is unrecognized
    logger.error(f"Unrecognized registry type for registry: {registry}")
    return None
