import os
import json
import string
import random
import base64
import inspect

import requests
import subprocess

from requests import Response
from falconpy import SensorDownload
from subprocess import CompletedProcess
from requests.auth import HTTPBasicAuth

from abstrakt.pythonModules.customLogging.customLogging import CustomLogger


class CrowdStrike:
  def __init__(self, falcon_client_id: str,
               falcon_client_secret: str,
               logger: CustomLogger(logger_name='CrowdStrike', log_file='/var/log/crowdstrike/crowdstrike.log')):
    self.falcon_client_id: str = falcon_client_id
    self.falcon_client_secret: str = falcon_client_secret
    self.logger = logger

    self.falcon_cid: str = self.get_falcon_cid()
    self.falcon_region: str = self.get_falcon_region()
    self.falcon_api: str = self.get_falcon_api()

    self.falcon_art_password: str = self.get_falcon_art_password()
    self.falcon_art_username: str = self.get_falcon_art_username()

  def get_falcon_response(self) -> dict[str, int | dict] | None:
    try:
      falcon: SensorDownload = SensorDownload(client_id=self.falcon_client_id, client_secret=self.falcon_client_secret)

      return falcon.get_sensor_installer_ccid()
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return None

  def get_falcon_cid(self) -> str | None:
    try:
      response: dict[str, int | dict] = self.get_falcon_response()

      return response["body"]["resources"][0].strip()
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return None

  def get_falcon_api(self) -> str | None:
    try:
      response: dict[str, int | dict] = self.get_falcon_response()

      if response['headers']['X-Cs-Region'] == 'us-2':
        return 'api.us-2.crowdstrike.com'
      elif response['headers']['X-Cs-Region'] == 'eu-1':
        return 'api.eu-1.crowdstrike.com'
      else:
        return 'api.crowdstrike.com'
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return None

  def get_falcon_region(self) -> str | None:
    try:
      response: dict[str, int | dict] = self.get_falcon_response()

      return response['headers']['X-Cs-Region'].strip()
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return None

  def get_falcon_api_bearer_token(self) -> str | None:
    try:
      token_url: str = f"https://{self.falcon_api}/oauth2/token"
      token_data: dict = {
        "client_id": self.falcon_client_id,
        "client_secret": self.falcon_client_secret,
      }
      response = requests.post(token_url, data=token_data,
                               headers={"Content-Type": "application/x-www-form-urlencoded"})
      falcon_api_bearer_token: str = response.json()['access_token']

      return falcon_api_bearer_token
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return None

  def get_falcon_art_password(self) -> str | None:
    try:
      falcon_api_bearer_token: str = self.get_falcon_api_bearer_token()

      if falcon_api_bearer_token:
        url: str = f"https://{self.falcon_api}/container-security/entities/image-registry-credentials/v1"
        headers: dict[str, str] = {"authorization": f"Bearer {falcon_api_bearer_token}"}
        response: Response = requests.get(url, headers=headers)
        return response.json()['resources'][0]['token']
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return None

  def get_falcon_art_username(self) -> str | None:
    try:
      return f"fc-{self.falcon_cid.lower().split('-')[0]}"
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return None

  def get_registry_bearer_token(self, sensor_type: str) -> str | None:
    try:
      if self.falcon_art_username and self.falcon_art_password:
        if sensor_type == 'daemonset':
          registry_bearer_url = (
            f"https://registry.crowdstrike.com/v2/token?={self.falcon_art_username}&scope=repository"
            f":falcon-sensor/{self.falcon_region}/release/falcon-sensor:pull&service=registry."
            f"crowdstrike.com")
        elif sensor_type == 'sidecar':
          registry_bearer_url = (
            f"https://registry.crowdstrike.com/v2/token?={self.falcon_art_username}&scope=repository"
            f":falcon-container/{self.falcon_region}/release/falcon-sensor:pull&service=registry."
            f"crowdstrike.com")
        else:
          registry_bearer_url = (
            f"https://registry.crowdstrike.com/v2/token?={self.falcon_art_username}&scope=repository"
            f":{sensor_type}/{self.falcon_region}/release/{sensor_type}:pull&service=registry."
            f"crowdstrike.com")

        response = requests.get(registry_bearer_url, auth=HTTPBasicAuth(self.falcon_art_username,
                                                                        self.falcon_art_password))
        registry_bearer: str = response.json()['token']

        return registry_bearer
      else:
        return None
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return None

  def login_to_crowdstrike_repo(self):
    command: str = (f'echo {self.falcon_art_password} | sudo skopeo login -u {self.falcon_art_username} '
                    f'--password-stdin registry.crowdstrike.com')

    return True if self.run_command(command=command) else False

  def add_crowdstrike_helm_repo(self) -> bool:
    try:
      command: list = ["helm", "repo", "add", "crowdstrike", "https://crowdstrike.github.io/falcon-helm"]
      process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

      if process.stdout:
        self.logger.info(process.stdout)
      if process.stderr:
        self.logger.info(process.stderr)

      return True
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return False

  def get_crowdstrike_partial_pull_token(self) -> str | None:
    try:
      if self.add_crowdstrike_helm_repo() is True:
        # Generate partial pull token
        partial_pull_token: str = (base64.b64encode(
          f"{self.falcon_art_username}:{self.get_falcon_art_password()}".encode()).decode()
                              )
        return partial_pull_token
      else:
        return None
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return None

  def get_crowdstrike_image_pull_token(self) -> str | None:
    try:
      partial_pull_token: str = self.get_crowdstrike_partial_pull_token()

      if partial_pull_token:
        falcon_image_pull_data = {
          "auths": {
            "registry.crowdstrike.com": {
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

  def get_crowdstrike_registry(self, sensor_type) -> str:
    if sensor_type == 'daemonset':
      return f"registry.crowdstrike.com/falcon-sensor/{self.falcon_region}/release/falcon-sensor"
    elif sensor_type == 'sidecar':
      return f"registry.crowdstrike.com/falcon-container/{self.falcon_region}/release/falcon-sensor"
    elif sensor_type == 'falcon-kac':
      return f"registry.crowdstrike.com/falcon-kac/{self.falcon_region}/release/falcon-kac"
    elif sensor_type == 'falcon-imageanalyzer':
      return f"registry.crowdstrike.com/falcon-imageanalyzer/{self.falcon_region}/release/falcon-imageanalyzer"

  def get_crowdstrike_sensor_tag_list_url(self, sensor_type: str) -> str:
    if sensor_type == 'daemonset':
      return (f"https://registry.crowdstrike.com/v2/falcon-sensor/{self.falcon_region}"
              f"/release/falcon-sensor/tags/list")
    elif sensor_type == 'sidecar':
      return (f"https://registry.crowdstrike.com/v2/falcon-container/{self.falcon_region}"
              f"/release/falcon-sensor/tags/list")
    else:
      return (f"https://registry.crowdstrike.com/v2/{sensor_type}/{self.falcon_region}/release"
              f"/{sensor_type}/tags/list")

  def verify_crowdstrike_sensor_image_tag(self, image_tag: str, sensor_type: str) -> bool:
    # daemonset_pattern: str = r'^\d+\.\d+\.\d+-\d+-\d+\.falcon-linux\.Release\.(US|EU)-\d+$'
    # sidecar_pattern: str = r'^\d+\.\d+\.\d+-\d+\.container\.x86_64\.Release\.(US|EU)-\d+$'
    # kac_pattern: str = r'^\d+\.\d+\.\d+-\d+\.container\.x86_64\.Release\.(US|EU)-\d+$'
    # iar_pattern: str = r'^\d+\.\d+\.\d+'

    try:
      if sensor_type == 'daemonset':
        registry_bearer: str = self.get_registry_bearer_token(sensor_type='daemonset')
      elif sensor_type == 'sidecar':
        registry_bearer: str = self.get_registry_bearer_token(sensor_type='sidecar')
      elif sensor_type == 'falcon-kac':
        registry_bearer: str = self.get_registry_bearer_token(sensor_type='falcon-kac')
      elif sensor_type == 'falcon-imageanalyzer':
        registry_bearer: str = self.get_registry_bearer_token(sensor_type='falcon-imageanalyzer')
      else:
        return False
      # if re.match(daemonset_pattern, image_tag):
      #   registry_bearer: str = self.get_registry_bearer_token(sensor_type='daemonset')
      #   sensor_type: str = 'daemonset'
      # elif re.match(sidecar_pattern, image_tag):
      #   registry_bearer: str = self.get_registry_bearer_token(sensor_type='sidecar')
      #   sensor_type: str = 'sidecar'
      # elif re.match(kac_pattern, image_tag):
      #   registry_bearer: str = self.get_registry_bearer_token(sensor_type='falcon-kac')
      #   sensor_type: str = 'falcon-kac'
      # elif re.match(iar_pattern, image_tag):
      #   registry_bearer: str = self.get_registry_bearer_token(sensor_type='falcon-imageanalyzer')
      #   sensor_type: str = 'falcon-imageanalyzer'
      # else:
      #   return False

      if registry_bearer:
        headers: dict[str, str] = {"authorization": f"Bearer {registry_bearer}"}
        response: Response = requests.get(
          self.get_crowdstrike_sensor_tag_list_url(sensor_type=sensor_type), headers=headers)

        sensors: dict = response.json()['tags']
        sensor_tags: list = []

        for sensor in sensors:
          if 'sha256' not in sensor:
            sensor_tags.append(sensor)

        if image_tag in sensor_tags:
          return True
      else:
        self.logger.error(f'{image_tag} does not match CrowdStrike image tag pattern.')
        return False
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return False

  def get_crowdstrike_sensor_image_tag(self, sensor_type: str, image_tag: str) -> str | None:
    try:
      if 'latest' not in image_tag:
        if self.verify_crowdstrike_sensor_image_tag(image_tag=image_tag, sensor_type=sensor_type):
          return image_tag
        else:
          return None

      registry_bearer: str = self.get_registry_bearer_token(sensor_type=sensor_type)

      if registry_bearer:
        headers: dict[str, str] = {"authorization": f"Bearer {registry_bearer}"}

        response: Response = requests.get(
          self.get_crowdstrike_sensor_tag_list_url(sensor_type=sensor_type), headers=headers)

        sensors: dict = response.json()['tags']
        sensor_tags: list = []

        for sensor in sensors:
          if 'sha256' not in sensor:
            sensor_tags.append(sensor)

        if '-' in image_tag:
          version_number: int = int(image_tag.split('-')[1])
        else:
          version_number: int = 0

        if sensor_type == 'falcon-imageanalyzer':
          sensor_tags.sort(key=lambda s: [int(part) for part in s.split('.')])

        return sensor_tags[-version_number - 1]
      else:
        return None
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return None

  def get_random_string(self, length=5):
    string_file = './abstrakt/conf/aws/eks/string.txt'

    try:
      if os.path.exists(string_file):
        with open(string_file, 'r') as file:
          append_string = file.readline()
          return append_string
      else:
        # Use ascii letters and digits for the string pool
        characters = string.ascii_letters + string.digits
        # Generate a random string
        random_string = ''.join(random.choices(characters, k=length))

        with open(string_file, 'w') as file:
          file.write(f'-{random_string}')

        return f'-{random_string}'
    except Exception as e:
      self.logger.error(e)
      return '-qwert'

  def run_command(self, command: str) -> str | None:
    try:
      result: CompletedProcess[str] = subprocess.run(command,
                                                     shell=True,
                                                     check=True,
                                                     text=True,
                                                     stdout=subprocess.PIPE,
                                                     stderr=subprocess.PIPE)

      if result.returncode == 0:
        if result.stderr:
          self.logger.error(result.stderr)

        if result.stdout:
          self.logger.info(result.stdout)
          return result.stdout
        else:
          return '//EMPTY'
      else:
        return None
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return None
