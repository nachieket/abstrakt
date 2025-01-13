import inspect
import subprocess

from falconpy import SensorDownload


class CrowdStrike:
  def __init__(self, falcon_client_id, falcon_client_secret, logger):
    self.falcon_client_id = falcon_client_id
    self.falcon_client_secret = falcon_client_secret
    self.logger = logger

  def get_cid_api_region(self):
    try:
      falcon = SensorDownload(client_id=self.falcon_client_id, client_secret=self.falcon_client_secret)

      response = falcon.get_sensor_installer_ccid()

      falcon_cid = response["body"]["resources"][0]
      falcon_region = response['headers']['X-Cs-Region']

      if response['headers']['X-Cs-Region'] == 'us-2':
        falcon_api = 'api.us-2.crowdstrike.com'
      elif response['headers']['X-Cs-Region'] == 'eu-1':
        falcon_api = 'api.eu-1.crowdstrike.com'
      else:
        falcon_api = 'api.crowdstrike.com'

      return falcon_cid, falcon_api, falcon_region
    except Exception as e:
      self.logger.error(e)
      return None, None, None

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
            return None, None
        else:
          if result.stdout:
            self.logger.info(result.stdout)
          if result.stderr:
            self.logger.error(result.stderr)
          return True
      else:
        if output is True:
          return None, None
        else:
          return False
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      if output is True:
        return None, None
      else:
        return False
