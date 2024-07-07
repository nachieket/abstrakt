import requests
import base64
import json
import subprocess
import inspect
import boto3
import re

from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError

from requests.auth import HTTPBasicAuth
from abstrakt.pythonModules.vendors.security.crowdstrike.crowdstrike import CrowdStrike


class CrowdStrikeSensors(CrowdStrike):
  def __init__(self, falcon_client_id, falcon_client_secret, sensor_mode, logger,
               falcon_image_repo=None, falcon_image_tag=None, proxy_server=None, proxy_port=None, tags=None):
    super().__init__(falcon_client_id, falcon_client_secret, logger)
    self.falcon_client_id = falcon_client_id
    self.falcon_client_secret = falcon_client_secret
    self.falcon_cid, self.falcon_cloud_api, self.falcon_cloud_region = self.get_cid_api_region()
    self.sensor_mode = sensor_mode
    self.logger = logger
    self.falcon_image_repo = falcon_image_repo
    self.falcon_image_tag = falcon_image_tag
    self.proxy_server = proxy_server
    self.proxy_port = proxy_port
    self.tags = tags

    self.falcon_art_username = ''
    self.falcon_art_password = ''

  def run_command(self, command, output=False):
    try:
      result = subprocess.run(command, shell=True, check=True, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)

      if result.returncode == 0:
        if output is True:
          if result.stdout and result.stderr:
            self.logger.info(result.stdout)
            self.logger.error(result.stderr)
            return result.stdout, result.stderr
          elif result.stdout and not result.stderr:
            self.logger.info(result.stdout)
            return result.stdout, None
          elif result.stderr and not result.stdout:
            self.logger.info(result.stderr)
            return None, result.stderr
        else:
          if result.stdout:
            self.logger.info(result.stdout)
          if result.stderr:
            self.logger.error(result.stderr)
          return True
      else:
        return False
    except subprocess.CalledProcessError as e:
      self.logger.error(f"Command failed with error: {e.stderr}")
      return False

  def get_falcon_api_bearer_token(self):
    try:
      # Get Falcon API Bearer Token
      token_url = f"https://{self.falcon_cloud_api}/oauth2/token"
      token_data = {
        "client_id": self.falcon_client_id,
        "client_secret": self.falcon_client_secret,
      }
      response = requests.post(token_url, data=token_data,
                               headers={"Content-Type": "application/x-www-form-urlencoded"})
      falcon_api_bearer_token = response.json()['access_token']

      return falcon_api_bearer_token
    except requests.exceptions.RequestException as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      return False
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      return False

  def get_falcon_art_password(self):
    try:
      falcon_api_bearer_token = self.get_falcon_api_bearer_token()

      if falcon_api_bearer_token:
        # Get Falcon Art Password
        url = f"https://{self.falcon_cloud_api}/container-security/entities/image-registry-credentials/v1"
        headers = {"authorization": f"Bearer {falcon_api_bearer_token}"}
        response = requests.get(url, headers=headers)
        self.falcon_art_password = response.json()['resources'][0]['token']
      else:
        self.falcon_art_password = None
    except requests.exceptions.RequestException as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      self.falcon_art_password = None
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      self.falcon_art_password = None

  def get_falcon_art_username(self):
    try:
      # Get Falcon Art Username
      self.falcon_art_username = f"fc-{self.falcon_cid.lower().split('-')[0]}"
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      self.falcon_art_username = None

  @staticmethod
  def get_sensor_type(sensor_type):
    if sensor_type == 'kernel' or sensor_type == 'bpf':
      return 'falcon-sensor'
    elif sensor_type == 'sidecar':
      return 'falcon-container'

  def get_registry_bearer_token(self):
    try:
      self.get_falcon_art_password()
      self.get_falcon_art_username()

      sensor_type = self.get_sensor_type(self.sensor_mode)

      if self.falcon_art_username and self.falcon_art_password:
        # Get Registry Bearer Token
        registry_bearer_url = (f"https://registry.crowdstrike.com/v2/token?={self.falcon_art_username}&scope=repository"
                               f":{sensor_type}/{self.falcon_cloud_region}/release/falcon-sensor:pull&service=registry."
                               f"crowdstrike.com")
        response = requests.get(registry_bearer_url, auth=HTTPBasicAuth(self.falcon_art_username,
                                                                        self.falcon_art_password))
        registry_bearer = response.json()['token']

        return registry_bearer, sensor_type
      else:
        return False, False
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      return False, False

  def get_latest_sensor(self):
    try:
      registry_bearer, sensor_type = self.get_registry_bearer_token()

      # Get Latest Sensor
      if registry_bearer and sensor_type:
        latest_sensor_url = f"https://registry.crowdstrike.com/v2/{sensor_type}/{self.falcon_cloud_region}" \
                            f"/release/falcon-sensor/tags/list"
        headers = {"authorization": f"Bearer {registry_bearer}"}
        response = requests.get(latest_sensor_url, headers=headers)

        if sensor_type == 'falcon-sensor':
          sensors = response.json()['tags']
          sensor_tags = []

          for sensor in sensors:
            if 'sha256' not in sensor:
              sensor_tags.append(sensor)

          return sensor_tags[-1]
        else:
          latest_sensor = response.json()['tags'][-1]
          return latest_sensor
      else:
        return None
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      return None

  def check_valid_ecr_repository(self, url: str) -> bool:
    try:
      ecr_regex = re.compile(
        r"^\d{12}\.dkr\.ecr\.[a-z]+-[a-z]+-[0-9]+\.amazonaws\.com/[a-zA-Z0-9._\-]+$"
      )

      return bool(ecr_regex.match(url))
    except Exception as e:
      self.logger.error(f'{e}')
      return False

  def check_crwd_registry_url(self, url: str) -> bool:
    try:
      # Define the regex pattern for the valid URL formats
      pattern = re.compile(
        r"^registry\.crowdstrike\.com/(falcon-sensor|falcon-container)/(us-1|us-2|eu-1)/release/("
        r"falcon-sensor|falcon-container)$"
      )
      # Match the URL against the pattern
      return bool(pattern.match(url))
    except Exception as e:
      self.logger.error(f'{e}')
      return False

  def check_registry_url(self, url: str) -> str:
    try:
      ecr_regex = re.compile(
        r"^\d{12}\.dkr\.ecr\.[a-z]+-[a-z]+-[0-9]+\.amazonaws\.com/[a-zA-Z0-9._\-]+$"
      )

      crwd_regex = re.compile(
        r"^registry\.crowdstrike\.com/(falcon-sensor|falcon-container)/(us-1|us-2|eu-1)/release/("
        r"falcon-sensor|falcon-container)$"
      )

      if bool(ecr_regex.match(url)):
        return "ecr_registry"
      elif bool(crwd_regex.match(url)):
        return "crwd_registry"
      else:
        return "unsupported_registry"
    except Exception as e:
      self.logger.error(f'{e}')
      return "unsupported_registry"

  def get_falcon_image_repo(self):
    if self.falcon_image_repo:
      return self.falcon_image_repo
    else:
      sensor_type = self.get_sensor_type(self.sensor_mode)
      return f"registry.crowdstrike.com/{sensor_type}/{self.falcon_cloud_region}/release/falcon-sensor"

  def get_falcon_image_tag(self):
    if self.falcon_image_tag:
      return self.falcon_image_tag
    else:
      return self.get_latest_sensor()

  def execute_docker_commands(self, image_repo: str, image_tag: str, local_registry: str, local_tag: str) -> None:
    commands = [
      f"echo {self.falcon_art_password} | sudo docker login -u {self.falcon_art_username} --password-stdin "
      f"registry.crowdstrike.com",
      f"sudo docker pull {image_repo}:{image_tag}",
      f"sudo docker tag {image_repo}:{image_tag} {local_registry}:{local_tag}",
      f"sudo docker push {local_registry}:{local_tag}"
    ]

    for command in commands:
      if not self.run_command(command):
        self.logger.error(f"Failed to execute: {command}")
        break
      else:
        print(f"Successfully executed: {command}")

  def check_valid_falcon_sensor_image_tag(self, tag: str) -> bool:
    try:
      falcon_sensor = self.get_sensor_type(sensor_type=self.sensor_mode)

      command = (f'./abstrakt/conf/crowdstrike/scripts/falcon-container-sensor-pull.sh -u '
                 f'{self.falcon_client_id} -s {self.falcon_client_secret} --list-tags -t {falcon_sensor}')

      stdout, stderr = self.run_command(command=command, output=True)
      output = json.loads(stdout)

      if stdout is not None:
        if tag in output['tags']:
          return True

      return False
    except Exception as e:
      self.logger.error(e)
      return False

  def add_crowdstrike_helm_repo(self) -> bool:
    try:
      # Add Helm Repo
      process = subprocess.run(["helm", "repo", "add", "crowdstrike", "https://crowdstrike.github.io/falcon-helm"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

      if process.stdout:
        self.logger.info(process.stdout)
      if process.stderr:
        self.logger.info(process.stderr)

      return True
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      return False

  def get_crowdstrike_partial_pull_token(self):
    try:
      if self.add_crowdstrike_helm_repo() is True:
        # Generate partial pull token
        partial_pull_token = (base64.b64encode(f"{self.falcon_art_username}:{self.falcon_art_password}".encode())
                              .decode())
        return partial_pull_token
      else:
        return None
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      return None

  def get_crowdstrike_image_pull_token(self):
    try:
      partial_pull_token = self.get_crowdstrike_partial_pull_token()

      if partial_pull_token is not None:
        falcon_image_pull_data = {
          "auths": {
            "registry.crowdstrike.com": {
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
      self.logger.error(f'Error: {e}')
      return None

  def get_ecr_partial_pull_token(self, ecr_registry_uri):
    try:
      ecr_region = ecr_registry_uri.split('.')[3]

      partial_pull_token_command = f"aws ecr get-login-password --region {ecr_region}"

      stdout, stderr = self.run_command(command=partial_pull_token_command, output=True)

      if stdout is not None:
        output = f'AWS:{stdout}'
        partial_pull_token = (base64.b64encode(output.encode()).decode())
        return partial_pull_token
      else:
        return None
    except Exception as e:
      self.logger.error(e)
      return None

  def get_ecr_image_pull_token(self, partial_pull_token):
    if self.add_crowdstrike_helm_repo() is True:
      try:
        ecr_registry = self.falcon_image_repo.split('/')[0]

        if partial_pull_token is not None:
          falcon_image_pull_data = {
            "auths": {
              f"{ecr_registry}": {
                "auth": partial_pull_token
              }
            }
          }

          falcon_image_pull_token = base64.b64encode(json.dumps(falcon_image_pull_data).encode()).decode()

          return falcon_image_pull_token
        else:
          return None
      except Exception as e:
        self.logger.error(e)
        return None
    else:
      return None

  def get_crowdstrike_image_repo(self):
    try:
      sensor_type = self.get_sensor_type(self.sensor_mode)
      return f"registry.crowdstrike.com/{sensor_type}/{self.falcon_cloud_region}/release/falcon-sensor"
    except Exception as e:
      self.logger.error(e)
      return None

  def check_ecr_repository_exists(self, ecr_registry) -> bool:
    try:
      repository_name = ecr_registry.split('amazonaws.com/')[-1]
      registry_id = ecr_registry.split('.')[0]
      region = ecr_registry.split('.')[3]

      # Create an ECR client
      client = boto3.client('ecr', region_name=region)

      # Check if the repository exists
      try:
        client.describe_repositories(registryId=registry_id, repositoryNames=[repository_name])
        self.logger.info(f'Repository {ecr_registry} exists.')
        return True
      except (client.exceptions.RepositoryNotFoundException, Exception) as e:
        self.logger.error(e)
        return False
    except (NoCredentialsError, PartialCredentialsError):
      self.logger.error("AWS credentials not found.")
      return False
    except (ClientError, Exception) as e:
      self.logger.error(f"Unexpected error: {e}")
      return False

  def check_ecr_image_exists(self, ecr_registry, ecr_image_tag) -> bool:
    # Check if the image tag exists in the repository
    repository_name = ecr_registry.split('amazonaws.com/')[-1]
    region = ecr_registry.split('.')[3]

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
    except (client.exceptions.ImageNotFoundException, Exception):
      self.logger.error(f"Image with tag '{ecr_image_tag}' does not exist in repository '{repository_name}'.")
      return False

  def check_ecr_repository_and_image_exists(self, falcon_repository_uri, falcon_image_tag) -> bool:
    try:
      repository_name = falcon_repository_uri.split('amazonaws.com/')[-1]
      registry_id = falcon_repository_uri.split('.')[0]
      region = falcon_repository_uri.split('.')[3]

      # Create an ECR client
      client = boto3.client('ecr', region_name=region)

      # Check if the repository exists
      try:
        client.describe_repositories(registryId=registry_id, repositoryNames=[repository_name])
        self.logger.info(f'Repository {falcon_repository_uri} does exist.')
      except (client.exceptions.RepositoryNotFoundException, Exception) as e:
        self.logger.error(e)
        return False

      # Check if the image tag exists in the repository
      try:
        response = client.describe_images(
          repositoryName=repository_name,
          imageIds=[
            {
              'imageTag': falcon_image_tag
            }
          ]
        )

        if response['imageDetails']:
          self.logger.info(f"Image with tag '{falcon_image_tag}' exists in repository '{repository_name}'.")
          return True
        else:
          self.logger.error(f"Image with tag '{falcon_image_tag}' does not exist in repository '{repository_name}'.")
          return False
      except (client.exceptions.ImageNotFoundException, Exception):
        self.logger.error(f"Image with tag '{falcon_image_tag}' does not exist in repository '{repository_name}'.")
        return False

    except (NoCredentialsError, PartialCredentialsError):
      self.logger.error("AWS credentials not found.")
      return False
    except (ClientError, Exception) as e:
      self.logger.error(f"Unexpected error: {e}")
      return False

  def download_crwd_image_and_push_to_ecr(self, falcon_art_username, falcon_art_password, crowdstrike_image_repo,
                                          crowdstrike_image_tag, ecr_image_repo, ecr_image_tag) -> tuple:
    try:
      region = ecr_image_repo.split('.')[3]
      image_repo = ecr_image_repo.split('/')[0]

      if ecr_image_tag is None:
        ecr_image_tag = self.get_falcon_image_tag()

      crwd_login_command = (f'echo {falcon_art_password} | sudo skopeo login -u {falcon_art_username} '
                            f'--password-stdin registry.crowdstrike.com')

      if not self.run_command(command=crwd_login_command):
        return None, None

      ecr_login_command = (f'aws ecr get-login-password --region {region} | sudo skopeo login --username AWS '
                           f'--password-stdin {image_repo}')

      if not self.run_command(command=ecr_login_command):
        return None, None

      # Copy from CrowdStrike registry to ECR
      image_copy_command = (f'skopeo copy --multi-arch all  docker://{crowdstrike_image_repo}:{crowdstrike_image_tag} '
                            f'docker://{ecr_image_repo}:{ecr_image_tag}')

      if not self.run_command(command=image_copy_command):
        return None, None

      self.logger.info("Docker commands executed successfully.")
      return ecr_image_repo, ecr_image_tag
    except subprocess.CalledProcessError as e:
      print(f"An error occurred while running command: {e.cmd}")
      print(f"Exit code: {e.returncode}")
      print(f"Output: {e.output}")
      print(f"Error: {e.stderr}")
      return None, None

  def execute_image_tag_no_repo(self):
    if self.check_valid_falcon_sensor_image_tag(tag=self.falcon_image_tag):
      if (crowdstrike_image_repo := self.get_crowdstrike_image_repo()) is not None:
        if (crowdstrike_repo_image_pull_token := self.get_crowdstrike_image_pull_token()) is not None:
          return 'crwd_registry', crowdstrike_image_repo, self.falcon_image_tag, crowdstrike_repo_image_pull_token
    else:
      self.logger.error('Falcon image tag passed at runtime is not valid. Abstrakt will use latest image tag.')

      if (crowdstrike_image_repo := self.get_crowdstrike_image_repo()) is not None:
        if (crowdstrike_image_tag := self.get_falcon_image_tag()) is not None:
          if (crowdstrike_repo_image_pull_token := self.get_crowdstrike_image_pull_token()) is not None:
            return 'crwd_registry', crowdstrike_image_repo, crowdstrike_image_tag, crowdstrike_repo_image_pull_token

    return None, None, None, None

  def execute_image_repo_image_tag(self):
    image_registry_type = self.check_registry_url(url=self.falcon_image_repo)

    if image_registry_type == 'crwd_registry' and self.check_valid_falcon_sensor_image_tag(tag=self.falcon_image_tag):
      crowdstrike_repo_image_pull_token = self.get_crowdstrike_image_pull_token()

      return 'crwd_registry', self.falcon_image_repo, self.falcon_image_tag, crowdstrike_repo_image_pull_token
    elif image_registry_type == 'crwd_registry' and not self.check_valid_falcon_sensor_image_tag(
      tag=self.falcon_image_tag):
      self.logger.error('Falcon image tag passed at runtime is not valid. Abstrakt will use latest image tag.')

      if (crowdstrike_image_tag := self.get_falcon_image_tag()) is not None:
        if (crowdstrike_repo_image_pull_token := self.get_crowdstrike_image_pull_token()) is not None:
          return 'crwd_registry', self.falcon_image_repo, crowdstrike_image_tag, crowdstrike_repo_image_pull_token
    elif image_registry_type == 'ecr_registry':
      if (self.check_ecr_repository_exists(ecr_registry=self.falcon_image_repo) and self.check_ecr_image_exists(
        ecr_registry=self.falcon_image_repo, ecr_image_tag=self.falcon_image_tag)):
        if (partial_ecr_pull_token := (self.get_ecr_partial_pull_token(ecr_registry_uri=self.falcon_image_repo)) is
                                      not None):
          if (falcon_ecr_image_pull_token := self.get_ecr_image_pull_token(
            partial_pull_token=partial_ecr_pull_token)) is not None:
            return 'ecr_registry', self.falcon_image_repo, self.falcon_image_tag, falcon_ecr_image_pull_token
      elif (self.check_ecr_repository_exists(ecr_registry=self.falcon_image_repo) and not
            self.check_ecr_image_exists(ecr_registry=self.falcon_image_repo, ecr_image_tag=self.falcon_image_tag)):
        if (crowdstrike_image_repo := self.get_crowdstrike_image_repo()) is not None:
          if (crowdstrike_image_tag := self.get_falcon_image_tag()) is not None:
            ecr_registry_uri, ecr_image_tag = self.download_crwd_image_and_push_to_ecr(
              falcon_art_username=self.falcon_art_username, falcon_art_password=self.falcon_art_password,
              crowdstrike_image_repo=crowdstrike_image_repo, crowdstrike_image_tag=crowdstrike_image_tag,
              ecr_image_repo=self.falcon_image_repo, ecr_image_tag=self.falcon_image_tag)

            if ecr_registry_uri is not None and ecr_image_tag is not None:
              if ((partial_ecr_pull_token := (self.get_ecr_partial_pull_token(ecr_registry_uri=ecr_registry_uri))) is
                 not None):
                if (falcon_ecr_image_pull_token := self.get_ecr_image_pull_token(
                  partial_pull_token=partial_ecr_pull_token)) is not None:
                  return 'ecr_registry', ecr_registry_uri, ecr_image_tag, falcon_ecr_image_pull_token

    return None, None, None, None

  def execute_image_repo_no_tag(self):
    image_registry_type = self.check_registry_url(url=self.falcon_image_repo)

    if image_registry_type == 'crwd_registry':
      if (crowdstrike_image_repo := self.get_crowdstrike_image_repo()) is not None:
        if (crowdstrike_image_tag := self.get_falcon_image_tag()) is not None:
          if (crowdstrike_repo_image_pull_token := self.get_crowdstrike_image_pull_token()) is not None:
            return 'crwd_registry', crowdstrike_image_repo, crowdstrike_image_tag, crowdstrike_repo_image_pull_token
    elif image_registry_type == 'ecr_registry':
      if self.check_ecr_repository_exists(ecr_registry=self.falcon_image_repo):
        if (crowdstrike_image_tag := self.get_falcon_image_tag()) is not None:
          if self.check_ecr_image_exists(ecr_registry=self.falcon_image_repo, ecr_image_tag=crowdstrike_image_tag):
            if ((partial_ecr_pull_token := self.get_ecr_partial_pull_token(
              ecr_registry_uri=self.falcon_image_repo)) is not None):
              if (falcon_ecr_image_pull_token := self.get_ecr_image_pull_token(
                partial_pull_token=partial_ecr_pull_token)) is not None:
                return 'ecr_registry', self.falcon_image_repo, crowdstrike_image_tag, falcon_ecr_image_pull_token
          else:
            if (crowdstrike_image_repo := self.get_crowdstrike_image_repo()) is not None:
              ecr_registry_uri, ecr_image_tag = self.download_crwd_image_and_push_to_ecr(
                falcon_art_username=self.falcon_art_username, falcon_art_password=self.falcon_art_password,
                crowdstrike_image_repo=crowdstrike_image_repo, crowdstrike_image_tag=crowdstrike_image_tag,
                ecr_image_repo=self.falcon_image_repo, ecr_image_tag=self.falcon_image_tag)

              if ecr_registry_uri is not None and ecr_image_tag is not None:
                if ((partial_ecr_pull_token := self.get_ecr_partial_pull_token(ecr_registry_uri=ecr_registry_uri))
                   is not None):
                  if (falcon_ecr_image_pull_token := self.get_ecr_image_pull_token(
                    partial_pull_token=partial_ecr_pull_token)) is not None:
                    return 'ecr_registry', ecr_registry_uri, ecr_image_tag, falcon_ecr_image_pull_token

    return None, None, None, None

  def execute_no_repo_no_tag(self):
    if (crowdstrike_image_repo := self.get_crowdstrike_image_repo()) is not None:
      if (crowdstrike_image_tag := self.get_falcon_image_tag()) is not None:
        if (crowdstrike_repo_image_pull_token := self.get_crowdstrike_image_pull_token()) is not None:
          return 'crwd_registry', crowdstrike_image_repo, crowdstrike_image_tag, crowdstrike_repo_image_pull_token

    return None, None, None, None

  def get_image_repo_tag_pull_token(self) -> tuple:
    if self.falcon_image_tag and not self.falcon_image_repo:
      registry_type, image_repo, image_tag, image_pull_token = self.execute_image_tag_no_repo()
      return registry_type, image_repo, image_tag, image_pull_token
    elif self.falcon_image_repo and self.falcon_image_tag:
      registry_type, image_repo, image_tag, image_pull_token = self.execute_image_repo_image_tag()
      return registry_type, image_repo, image_tag, image_pull_token
    elif self.falcon_image_repo and not self.falcon_image_tag:
      registry_type, image_repo, image_tag, image_pull_token = self.execute_image_repo_no_tag()
      return registry_type, image_repo, image_tag, image_pull_token
    elif not self.falcon_image_repo and not self.falcon_image_tag:
      registry_type, image_repo, image_tag, image_pull_token = self.execute_no_repo_no_tag()
      return registry_type, image_repo, image_tag, image_pull_token
    else:
      return None, None, None, None

  def get_helm_chart(self):
    pass

  def execute_helm_chart(self):
    pass
