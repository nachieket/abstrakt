import requests
import base64
import json
import subprocess
import inspect

from requests.auth import HTTPBasicAuth


class CrowdStrikeSensors:
  def __init__(self, falcon_client_id, falcon_client_secret, falcon_cid,
               falcon_cloud_region, falcon_cloud_api, sensor_mode, logger,
               proxy_server=None, proxy_port=None, tags=None):
    self.falcon_client_id = falcon_client_id
    self.falcon_client_secret = falcon_client_secret
    self.falcon_cid = falcon_cid
    self.falcon_cloud_region = falcon_cloud_region
    self.falcon_cloud_api = falcon_cloud_api
    self.sensor_mode = sensor_mode
    self.logger = logger
    self.proxy_server = proxy_server
    self.proxy_port = proxy_port
    self.tags = tags

    self.falcon_art_username = ''
    self.falcon_art_password = ''

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

      if falcon_api_bearer_token is not False:
        # Get Falcon Art Password
        url = f"https://{self.falcon_cloud_api}/container-security/entities/image-registry-credentials/v1"
        headers = {"authorization": f"Bearer {falcon_api_bearer_token}"}
        response = requests.get(url, headers=headers)
        falcon_art_password = response.json()['resources'][0]['token']

        return falcon_art_password
      else:
        return False
    except requests.exceptions.RequestException as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      return False
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      return False

  def get_falcon_art_username(self):
    try:
      # Get Falcon Art Username
      falcon_art_username = f"fc-{self.falcon_cid.lower().split('-')[0]}"

      return falcon_art_username
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      return False

  @staticmethod
  def get_sensor_type(sensor_type):
    return 'falcon-sensor' if sensor_type == 'kernel' or 'bpf' else 'falcon-container'

  def get_registry_bearer_token(self):
    try:
      self.falcon_art_username = self.get_falcon_art_username()
      self.falcon_art_password = self.get_falcon_art_password()
      sensor_type = self.get_sensor_type(self.sensor_mode)

      if (self.falcon_art_username or self.falcon_art_password) is not False:
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
      if (registry_bearer or sensor_type) is not False:
        latest_sensor_url = f"https://registry.crowdstrike.com/v2/{sensor_type}/{self.falcon_cloud_region}" \
                            f"/release/falcon-sensor/tags/list"
        headers = {"authorization": f"Bearer {registry_bearer}"}
        response = requests.get(latest_sensor_url, headers=headers)
        latest_sensor = response.json()['tags'][-1]

        return latest_sensor
      else:
        return False
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      return False

  def get_falcon_image_repo(self):
    sensor_type = self.get_sensor_type(self.sensor_mode)
    return f"registry.crowdstrike.com/{sensor_type}/{self.falcon_cloud_region}/release/falcon-sensor"

  def get_falcon_image_tag(self):
    return self.get_latest_sensor()

  def add_helm_repo(self):
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

  def get_partial_pull_token(self):
    try:
      if self.add_helm_repo() is True:
        # Generate partial pull token
        partial_pull_token = (base64.b64encode(f"{self.falcon_art_username}:{self.falcon_art_password}".encode())
                              .decode())
        return partial_pull_token
      else:
        return False
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      return False

  def get_falcon_image_pull_token(self):
    try:
      partial_pull_token = self.get_partial_pull_token()

      if partial_pull_token is not False:
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
        return False
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      return False

  def get_helm_chart(self):
    pass

  def execute_helm_chart(self):
    pass
