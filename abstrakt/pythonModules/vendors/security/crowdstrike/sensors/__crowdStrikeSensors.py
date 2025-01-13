import re
import json
import base64
import inspect
import requests
import subprocess

from requests import Response

from requests.auth import HTTPBasicAuth
from abstrakt.pythonModules.vendors.security.crowdstrike.__crowdstrike import CrowdStrike


class CrowdStrikeSensors(CrowdStrike):
  def __init__(self, falcon_client_id, falcon_client_secret, logger, image_registry=None, proxy_server=None,
               proxy_port=None, sensor_tags=None, cluster_name=None, cluster_type=None):
    super().__init__(falcon_client_id, falcon_client_secret, logger)
    self.falcon_client_id = falcon_client_id
    self.falcon_client_secret = falcon_client_secret
    self.falcon_cid, self.falcon_cloud_api, self.falcon_cloud_region = self.get_cid_api_region()

    self.image_registry = image_registry
    self.proxy_server = proxy_server
    self.proxy_port = proxy_port
    self.logger = logger
    self.sensor_tags = sensor_tags
    self.cluster_name = cluster_name
    self.cluster_type = cluster_type

    self.falcon_art_username = None
    self.falcon_art_password = None

  def get_falcon_api_bearer_token(self):
    try:
      token_url = f"https://{self.falcon_cloud_api}/oauth2/token"
      token_data = {
        "client_id": self.falcon_client_id,
        "client_secret": self.falcon_client_secret,
      }
      response = requests.post(token_url, data=token_data,
                               headers={"Content-Type": "application/x-www-form-urlencoded"})
      falcon_api_bearer_token = response.json()['access_token']

      return falcon_api_bearer_token
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return False

  def get_falcon_art_password(self):
    try:
      falcon_api_bearer_token = self.get_falcon_api_bearer_token()

      if falcon_api_bearer_token:
        url = f"https://{self.falcon_cloud_api}/container-security/entities/image-registry-credentials/v1"
        headers = {"authorization": f"Bearer {falcon_api_bearer_token}"}
        response = requests.get(url, headers=headers)
        self.falcon_art_password = response.json()['resources'][0]['token']
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')

  def get_falcon_art_username(self):
    try:
      self.falcon_art_username = f"fc-{self.falcon_cid.lower().split('-')[0]}"
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')

  def get_registry_bearer_token(self, sensor_type):
    try:
      self.get_falcon_art_password()
      self.get_falcon_art_username()

      if self.falcon_art_username and self.falcon_art_password:
        if sensor_type == '_sidecar':
          registry_bearer_url = (
            f"https://registry.crowdstrike.com/v2/token?={self.falcon_art_username}&scope=repository"
            f":falcon-container/{self.falcon_cloud_region}/release/falcon-sensor:pull&service=registry."
            f"crowdstrike.com")
        elif sensor_type == '_daemonset':
          registry_bearer_url = (
            f"https://registry.crowdstrike.com/v2/token?={self.falcon_art_username}&scope=repository"
            f":falcon-sensor/{self.falcon_cloud_region}/release/falcon-sensor:pull&service=registry."
            f"crowdstrike.com")
        else:
          registry_bearer_url = (
            f"https://registry.crowdstrike.com/v2/token?={self.falcon_art_username}&scope=repository"
            f":{sensor_type}/{self.falcon_cloud_region}/release/{sensor_type}:pull&service=registry."
            f"crowdstrike.com")

        response = requests.get(registry_bearer_url, auth=HTTPBasicAuth(self.falcon_art_username,
                                                                        self.falcon_art_password))
        registry_bearer = response.json()['token']

        return registry_bearer
      else:
        return None
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return None

  def check_registry_type(self, image_registry: str) -> str:
    try:
      ecr_regex = re.compile(
        r"^\d{12}\.dkr\.ecr\.[a-z]+-[a-z]+-[0-9]+\.amazonaws\.com/[a-zA-Z0-9._\-]+$"
      )

      crwd_regex = re.compile(
        r"^registry\.crowdstrike\.com/(falcon-sensor|falcon-container|falcon-kac|falcon-imageanalyzer)/("
        r"us-1|us-2|eu-1)/release/(falcon-sensor|falcon-container|falcon-kac|falcon-imageanalyzer)$"
      )

      acr_regex = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{3,48}[a-zA-Z0-9])?\.azurecr\.io/[a-zA-Z0-9._\-]+$")

      if bool(ecr_regex.match(image_registry)):
        return 'ecr_registry'
      elif bool(crwd_regex.match(image_registry)):
        return 'crwd_registry'
      elif bool(acr_regex.match(image_registry)):
        return 'acr_registry'
      else:
        return 'unsupported_registry'
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return 'unsupported_registry'

  def get_crwd_repo_url(self, sensor_type) -> str:
    if sensor_type == '_daemonset':
      return f"registry.crowdstrike.com/falcon-sensor/{self.falcon_cloud_region}/release/falcon-sensor"
    elif sensor_type == '_sidecar':
      return f"registry.crowdstrike.com/falcon-container/{self.falcon_cloud_region}/release/falcon-sensor"
    elif sensor_type == 'falcon-kac':
      return f"registry.crowdstrike.com/falcon-kac/{self.falcon_cloud_region}/release/falcon-kac"
    elif sensor_type == 'falcon-iar':
      return f"registry.crowdstrike.com/falcon-imageanalyzer/{self.falcon_cloud_region}/release/falcon-imageanalyzer"

  def verify_daemonset_image_tag(self, image_tag: str) -> bool:
    daemonset_pattern: str = r'^\d+\.\d+\.\d+-\d+-\d+\.falcon-linux\.Release\.(US|EU)-\d+$'

    try:
      if re.match(daemonset_pattern, image_tag):
        registry_bearer: str = self.get_registry_bearer_token(sensor_type='_daemonset')

        if registry_bearer:
          daemonset_sensor_url = f"https://registry.crowdstrike.com/v2/falcon-sensor/{self.falcon_cloud_region}" \
                       f"/release/falcon-sensor/tags/list"

          headers: dict[str, str] = {"authorization": f"Bearer {registry_bearer}"}
          response: Response = requests.get(daemonset_sensor_url, headers=headers)

          sensors: dict = response.json()['tags']
          sensor_tags: list = []

          for sensor in sensors:
            if 'sha256' not in sensor:
              sensor_tags.append(sensor)

          if image_tag in sensor_tags:
            return True
      else:
        self.logger.error(f'{image_tag} does not match CrowdStrike _daemonset image tag pattern.')
        return False
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return False

  def get_crwd_daemonset_image_tag(self, image_tag: str = 'latest') -> str | None:
    try:
      registry_bearer: str = self.get_registry_bearer_token(sensor_type='_daemonset')

      if registry_bearer:
        daemonset_sensor_url = f"https://registry.crowdstrike.com/v2/falcon-sensor/{self.falcon_cloud_region}" \
                               f"/release/falcon-sensor/tags/list"

        headers: dict[str, str] = {"authorization": f"Bearer {registry_bearer}"}
        response: Response = requests.get(daemonset_sensor_url, headers=headers)

        sensors: dict = response.json()['tags']
        sensor_tags: list = []

        for sensor in sensors:
          if 'sha256' not in sensor:
            sensor_tags.append(sensor)

        if image_tag == 'latest':
          return sensor_tags[-1]
        else:
          return sensor_tags[-int(image_tag.split('-')[1])]

    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return None

  def verify_sidecar_image_tag(self, image_tag: str) -> bool:
    sidecar_pattern: str = r'^\d+\.\d+\.\d+-\d+\.container\.x86_64\.Release\.(US|EU)-\d+$'

    try:
      if re.match(sidecar_pattern, image_tag):
        registry_bearer: str = self.get_registry_bearer_token(sensor_type='_sidecar')

        if registry_bearer:
          sidecar_sensor_url = f"https://registry.crowdstrike.com/v2/falcon-container/{self.falcon_cloud_region}" \
                               f"/release/falcon-sensor/tags/list"

          headers: dict[str, str] = {"authorization": f"Bearer {registry_bearer}"}
          response: Response = requests.get(sidecar_sensor_url, headers=headers)

          sensors: dict = response.json()['tags']
          sensor_tags: list = []

          for sensor in sensors:
            if 'sha256' not in sensor:
              sensor_tags.append(sensor)

          if image_tag in sensor_tags:
            return True
      else:
        self.logger.error(f'{image_tag} does not match CrowdStrike _sidecar image tag pattern.')
        return False
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return False

  def get_crwd_sidecar_image_tag(self, image_tag: str = 'latest') -> str | None:
    try:
      registry_bearer: str = self.get_registry_bearer_token(sensor_type='_sidecar')

      if registry_bearer:
        sidecar_sensor_url = f"https://registry.crowdstrike.com/v2/falcon-container/{self.falcon_cloud_region}" \
                             f"/release/falcon-sensor/tags/list"

        headers: dict[str, str] = {"authorization": f"Bearer {registry_bearer}"}
        response: Response = requests.get(sidecar_sensor_url, headers=headers)

        sensors: dict = response.json()['tags']
        sensor_tags: list = []

        for sensor in sensors:
          if 'sha256' not in sensor:
            sensor_tags.append(sensor)

        if image_tag == 'latest':
          return sensor_tags[-1]
        else:
          return sensor_tags[-int(image_tag.split('-')[1])]

    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return None

  def verify_kac_image_tag(self, image_tag: str) -> bool:
    kac_pattern = r'^\d+\.\d+\.\d+-\d+\.container\.x86_64\.Release\.(US|EU)-\d+$'

    try:
      if re.match(kac_pattern, image_tag):
        registry_bearer: str = self.get_registry_bearer_token(sensor_type='falcon-kac')

        if registry_bearer:
          kac_sensor_url = f"https://registry.crowdstrike.com/v2/falcon-kac/{self.falcon_cloud_region}" \
                       f"/release/falcon-kac/tags/list"

          headers: dict[str, str] = {"authorization": f"Bearer {registry_bearer}"}
          response: Response = requests.get(kac_sensor_url, headers=headers)

          sensors: dict = response.json()['tags']
          sensor_tags: list = []

          for sensor in sensors:
            if 'sha256' not in sensor:
              sensor_tags.append(sensor)

          if image_tag in sensor_tags:
            return True
      else:
        self.logger.error(f'{image_tag} does not match CrowdStrike falcon-kac image tag pattern.')
        return False
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return False

  def get_crwd_kac_image_tag(self, image_tag: str = 'latest') -> str | None:
    try:
      registry_bearer: str = self.get_registry_bearer_token(sensor_type='falcon-kac')

      if registry_bearer:
        kac_sensor_url = f"https://registry.crowdstrike.com/v2/falcon-kac/{self.falcon_cloud_region}" \
                         f"/release/falcon-kac/tags/list"

        headers: dict[str, str] = {"authorization": f"Bearer {registry_bearer}"}
        response: Response = requests.get(kac_sensor_url, headers=headers)

        sensors: dict = response.json()['tags']
        sensor_tags: list = []

        for sensor in sensors:
          if 'sha256' not in sensor:
            sensor_tags.append(sensor)

        if image_tag == 'latest':
          return sensor_tags[-1]
        else:
          return sensor_tags[-int(image_tag.split('-')[1])]

    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return None

  def verify_iar_image_tag(self, image_tag: str) -> bool:
    iar_pattern = r'^\d+\.\d+\.\d+'

    try:
      if re.match(iar_pattern, image_tag):
        registry_bearer: str = self.get_registry_bearer_token(sensor_type='falcon-imageanalyzer')

        if registry_bearer:
          iar_sensor_url = f"https://registry.crowdstrike.com/v2/falcon-imageanalyzer/{self.falcon_cloud_region}" \
                       f"/release/falcon-imageanalyzer/tags/list"

          headers: dict[str, str] = {"authorization": f"Bearer {registry_bearer}"}
          response: Response = requests.get(iar_sensor_url, headers=headers)

          sensors: dict = response.json()['tags']
          sensor_tags: list = []

          for sensor in sensors:
            if 'sha256' not in sensor:
              sensor_tags.append(sensor)

          if image_tag in sensor_tags:
            return True
      else:
        self.logger.error(f'{image_tag} does not match CrowdStrike falcon-imageanalyzer image tag pattern.')
        return False
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return False

  def get_crwd_iar_image_tag(self, image_tag: str = 'latest') -> str | None:
    try:
      registry_bearer: str = self.get_registry_bearer_token(sensor_type='falcon-imageanalyzer')

      if registry_bearer:
        iar_sensor_url = f"https://registry.crowdstrike.com/v2/falcon-imageanalyzer/{self.falcon_cloud_region}" \
                         f"/release/falcon-imageanalyzer/tags/list"

        headers: dict[str, str] = {"authorization": f"Bearer {registry_bearer}"}
        response: Response = requests.get(iar_sensor_url, headers=headers)

        sensors: dict = response.json()['tags']
        sensor_tags: list = []

        for sensor in sensors:
          if 'sha256' not in sensor:
            sensor_tags.append(sensor)

        if image_tag == 'latest':
          return sensor_tags[-1]
        else:
          return sensor_tags[-int(image_tag.split('-')[1])]

    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return None

  def get_crwd_sensor_tag(self, sensor_type: str, image_tag: str) -> str:
    daemonset_pattern = r'^\d+\.\d+\.\d+-\d+-\d+\.falcon-linux\.Release\.(US|EU)-\d+$'
    sidecar_pattern = r'^\d+\.\d+\.\d+-\d+\.container\.x86_64\.Release\.(US|EU)-\d+$'
    kac_pattern = r'^\d+\.\d+\.\d+-\d+\.container\.x86_64\.Release\.(US|EU)-\d+$'
    iar_pattern = r'^\d+\.\d+\.\d+'

    if re.match(daemonset_pattern, image_tag) or re.match(sidecar_pattern, image_tag) \
       or re.match(kac_pattern, image_tag) or re.match(iar_pattern, image_tag):
      tag = True
    else:
      tag = False

    try:
      registry_bearer: str = self.get_registry_bearer_token(sensor_type=sensor_type)

      if registry_bearer:
        if sensor_type == '_sidecar':
          sensor_url = f"https://registry.crowdstrike.com/v2/falcon-container/{self.falcon_cloud_region}" \
                       f"/release/falcon-sensor/tags/list"
        elif sensor_type == '_daemonset':
          sensor_url = f"https://registry.crowdstrike.com/v2/falcon-sensor/{self.falcon_cloud_region}" \
                       f"/release/falcon-sensor/tags/list"
        else:
          sensor_url = f"https://registry.crowdstrike.com/v2/{sensor_type}/{self.falcon_cloud_region}" \
                       f"/release/{sensor_type}/tags/list"

        headers: dict[str, str] = {"authorization": f"Bearer {registry_bearer}"}
        response: Response = requests.get(sensor_url, headers=headers)

        sensors: dict = response.json()['tags']
        sensor_tags: list = []

        for sensor in sensors:
          if 'sha256' not in sensor:
            sensor_tags.append(sensor)

        if tag is True:
          if image_tag in sensor_tags:
            return image_tag
          else:
            return 'None'

        if '-' in image_tag:
          version_number: int = int(image_tag.split('-')[1])
        else:
          version_number: int = 0

        return sensor_tags[-version_number - 1]

      else:
        return 'None'

    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return 'None'

  def login_to_crowdstrike_repo(self):
    command = (f'echo {self.falcon_art_password} | sudo skopeo login -u {self.falcon_art_username} --password-stdin '
               'registry.crowdstrike.com')

    return True if self.run_command(command=command) else False

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
      self.logger.error(f'{e}')
      return False

  def get_crwd_partial_pull_token(self) -> str:
    try:
      if self.add_crowdstrike_helm_repo() is True:
        # Generate partial pull token
        partial_pull_token = (base64.b64encode(f"{self.falcon_art_username}:{self.falcon_art_password}".encode())
                              .decode())
        return partial_pull_token
      else:
        return 'None'
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return 'None'

  def get_crwd_image_pull_token(self) -> str:
    try:
      partial_pull_token = self.get_crwd_partial_pull_token()

      if partial_pull_token != 'None':
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
        return 'None'
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return 'None'

  def get_image_repo(self, sensor_type) -> tuple:
    if self.image_registry is None:
      return 'crwd_registry', self.get_crwd_repo_url(sensor_type=sensor_type)
    elif self.image_registry:
      registry_type = self.check_registry_type(image_registry=self.image_registry)

      if registry_type == 'crwd_registry':
        return 'crwd_registry', self.image_registry
      elif registry_type == 'ecr_registry':
        return 'ecr_registry', self.image_registry
      else:
        return 'unsupported', self.image_registry
    else:
      return 'None', 'None'

  def get_crwd_image_tag(self, sensor_type, image_tag) -> str:
    if sensor_type == '_daemonset':
      return self.get_crwd_sensor_tag(sensor_type='_daemonset', image_tag=image_tag)
    elif sensor_type == '_sidecar':
      return self.get_crwd_sensor_tag(sensor_type='_sidecar', image_tag=image_tag)
    elif sensor_type == 'falcon-kac':
      return self.get_crwd_sensor_tag(sensor_type='falcon-kac', image_tag=image_tag)
    elif sensor_type == 'falcon-iar':
      return self.get_crwd_sensor_tag(sensor_type='falcon-imageanalyzer', image_tag=image_tag)
    else:
      return 'None'

  def get_crwd_repo_tag_token(self, sensor_type, image_tag='latest') -> tuple:
    registry_type, registry_uri = self.get_image_repo(sensor_type=sensor_type)
    image_tag = self.get_crwd_image_tag(sensor_type=sensor_type, image_tag=image_tag)
    image_pull_token = self.get_crwd_image_pull_token()

    return registry_uri, image_tag, image_pull_token

  # def get_repo_tag_token(self, sensor_type, image_tag) -> tuple:
  #   registry_type, registry_uri = self.get_image_repo(sensor_type=sensor_type)
  #
  #   if registry_type == 'crwd_registry':
  #     falcon_image_repo, falcon_image_tag, falcon_image_pull_token = self.get_crwd_repo_tag_token(
  #       sensor_type=sensor_type, image_tag=image_tag)
  #
  #     return registry_type, falcon_image_repo, falcon_image_tag, falcon_image_pull_token
  #   elif registry_type == 'ecr_registry':
  #     falcon_image_repo, falcon_image_tag, falcon_image_pull_token = self.get_ecr_repo_tag_token(
  #       sensor_type=sensor_type, ecr_registry_uri=registry_uri, image_tag=image_tag)
  #
  #     return registry_type, falcon_image_repo, falcon_image_tag, falcon_image_pull_token
  #   else:
  #     return 'None', 'None', 'None', 'None'
