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
