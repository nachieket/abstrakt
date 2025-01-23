import os
import json
import string
import random
import base64
import inspect

import requests
import subprocess
from typing import Optional, Tuple

from requests import Response
from falconpy import SensorDownload
from requests.auth import HTTPBasicAuth


class CrowdStrike:
  def __init__(self, falcon_client_id: str,
               falcon_client_secret: str,
               logger):
    self.falcon_client_id: str = falcon_client_id
    self.falcon_client_secret: str = falcon_client_secret
    self.logger = logger

    self.falcon_cid: str = self.get_falcon_cid()
    self.falcon_region: str = self.get_falcon_region(logger=self.logger)
    self.falcon_api: str = self.get_falcon_api()

    self.falcon_art_password: str = self.get_falcon_art_password()
    self.falcon_art_username: str = self.get_falcon_art_username(logger=self.logger)

  def get_falcon_response(self, logger=None) -> dict[str, int | dict] | None:
    logger = logger or self.logger

    try:
      falcon: SensorDownload = SensorDownload(client_id=self.falcon_client_id, client_secret=self.falcon_client_secret)

      return falcon.get_sensor_installer_ccid()
    except Exception as e:
      logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      logger.error(f'{e}')
      return None

  def get_falcon_cid(self, logger=None) -> str | None:
    logger = logger or self.logger
    try:
      response: dict[str, int | dict] = self.get_falcon_response()

      return response["body"]["resources"][0].strip()
    except Exception as e:
      logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      logger.error(f'{e}')
      return None

  def get_falcon_api(self, logger=None) -> str | None:
    logger = logger or self.logger

    try:
      response: dict[str, int | dict] = self.get_falcon_response()

      if response['headers']['X-Cs-Region'] == 'us-2':
        return 'api.us-2.crowdstrike.com'
      elif response['headers']['X-Cs-Region'] == 'eu-1':
        return 'api.eu-1.crowdstrike.com'
      else:
        return 'api.crowdstrike.com'
    except Exception as e:
      logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      logger.error(f'{e}')
      return None

  def get_falcon_region(self, logger=None) -> str | None:
    logger = logger or self.logger

    try:
      response: dict[str, int | dict] = self.get_falcon_response()

      return response['headers']['X-Cs-Region'].strip()
    except Exception as e:
      logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      logger.error(f'{e}')
      return None

  def get_falcon_api_bearer_token(self, logger=None) -> str | None:
    logger = logger or self.logger

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
      logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      logger.error(f'{e}')
      return None

  def get_falcon_art_password(self, logger=None) -> str | None:
    logger = logger or self.logger

    try:
      falcon_api_bearer_token: str = self.get_falcon_api_bearer_token()

      if falcon_api_bearer_token:
        url: str = f"https://{self.falcon_api}/container-security/entities/image-registry-credentials/v1"
        headers: dict[str, str] = {"authorization": f"Bearer {falcon_api_bearer_token}"}
        response: Response = requests.get(url, headers=headers)
        return response.json()['resources'][0]['token']
    except Exception as e:
      logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      logger.error(f'{e}')
      return None

  def get_falcon_art_username(self, logger=None) -> str | None:
    logger = logger or self.logger

    try:
      return f"fc-{self.falcon_cid.lower().split('-')[0]}"
    except Exception as e:
      logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      logger.error(f'{e}')
      return None

  def get_registry_bearer_token(self, sensor_type: str, logger=None) -> str | None:
    logger = logger or self.logger

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
      logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      logger.error(f'{e}')
      return None

  def login_to_crowdstrike_repo(self, logger=None):
    logger = logger or self.logger

    command: str = (f'echo {self.falcon_art_password} | sudo skopeo login -u {self.falcon_art_username} '
                    f'--password-stdin registry.crowdstrike.com')

    output, error = self.run_command(command=command, logger=logger)

    return True if output else False

  def add_crowdstrike_helm_repo(self, logger=None) -> bool:
    logger = logger or self.logger

    try:
      command: list = ["helm", "repo", "add", "crowdstrike", "https://crowdstrike.github.io/falcon-helm"]
      process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

      if process.stdout:
        logger.info(process.stdout)
      if process.stderr:
        logger.info(process.stderr)

      return True
    except Exception as e:
      logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      logger.error(f'{e}')
      return False

  def get_crowdstrike_partial_pull_token(self, logger=None) -> str | None:
    logger = logger or self.logger

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
      logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      logger.error(f'{e}')
      return None

  def get_crowdstrike_image_pull_token(self, logger=None) -> str | None:
    logger = logger or self.logger

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
      logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      logger.error(f'{e}')
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

  def verify_crowdstrike_sensor_image_tag(self, image_tag: str, sensor_type: str, logger=None) -> bool:
    logger = logger or self.logger

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
        logger.error(f'{image_tag} does not match CrowdStrike image tag pattern.')
        return False
    except Exception as e:
      logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      logger.error(f'{e}')
      return False

  def get_crowdstrike_sensor_image_tag(self, sensor_type: str, image_tag: str, logger=None) -> str | None:
    logger = logger or self.logger

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

        sensor_tags = [sensor for sensor in sensors if all(
          tag not in sensor for tag in ['sha256', '_aarch64', '_x86_64'])]

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
      logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      logger.error(f'{e}')
      return None

  def get_random_string(self, length=5, logger=None):
    logger = logger or self.logger
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
      logger.error(e)
      return '-qwert'

  def run_command(self, command: str, logger=None) -> Tuple[Optional[str], Optional[str]]:
    """
    Executes a shell command and captures its output.

    Args:
        command (str): The shell command to run.
        logger: Logger

    Returns:
        Tuple[Optional[str], Optional[str]]: The standard output and error of the command.
                                             Both can be None if there's no output.
    """
    logger = logger or self.logger

    try:

      # Run the command
      result = subprocess.run(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True  # Don't raise an exception for non-zero return codes
      )

      # Log and capture stdout
      stdout_output = []
      for line in result.stdout.splitlines():
        logger.info(line)
        stdout_output.append(line)

      # Log and capture stderr
      stderr_output = []
      for line in result.stderr.splitlines():
        logger.error(line)
        stderr_output.append(line)

      # Check return code
      if result.returncode != 0:
        logger.error(f"Command failed with return code: {result.returncode}")
        return None, '\n'.join(stderr_output) if stderr_output else None

      return '\n'.join(stdout_output) if stdout_output else None, '\n'.join(stderr_output) if stderr_output else None

    except Exception as e:
      logger.error(f"Unexpected error occurred: {e}")
      return None, str(e)

  # def run_command(self, command: str) -> Tuple[Optional[str], Optional[str]]:
  #   """
  #   Executes a shell command and captures its output in real-time.
  #
  #   Args:
  #       command (str): The shell command to run.
  #
  #   Returns:
  #       Tuple[Optional[str], Optional[str]]: The standard output and error of the command.
  #                                            Both can be None if there's no output.
  #   """
  #   try:
  #     process = subprocess.Popen(
  #       shlex.split(command),
  #       stdout=subprocess.PIPE,
  #       stderr=subprocess.PIPE,
  #       text=True,
  #       bufsize=1,
  #       universal_newlines=True
  #     )
  #
  #     stdout_output = []
  #     stderr_output = []
  #
  #     while True:
  #       stdout_line = process.stdout.readline()
  #       stderr_line = process.stderr.readline()
  #
  #       if stdout_line:
  #         self.logger.info(stdout_line.strip())
  #         stdout_output.append(stdout_line)
  #       if stderr_line:
  #         self.logger.error(stderr_line.strip())
  #         stderr_output.append(stderr_line)
  #
  #       if process.poll() is not None:
  #         break
  #
  #     remaining_stdout, remaining_stderr = process.communicate()
  #
  #     if remaining_stdout:
  #       self.logger.info(remaining_stdout)
  #       stdout_output.append(remaining_stdout)
  #     if remaining_stderr:
  #       self.logger.error(remaining_stderr)
  #       stderr_output.append(remaining_stderr)
  #
  #     if process.returncode != 0:
  #       self.logger.error(f"Command failed with return code: {process.returncode}")
  #       return None, ''.join(stderr_output) if stderr_output else None
  #
  #     return ''.join(stdout_output) if stdout_output else None, ''.join(stderr_output) if stderr_output else None
  #
  #   except Exception as e:
  #     self.logger.error(f"Unexpected error occurred: {e}")
  #     return None, str(e)
