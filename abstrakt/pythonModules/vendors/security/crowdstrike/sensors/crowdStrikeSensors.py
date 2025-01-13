import re
import inspect

from abstrakt.pythonModules.customLogging.customLogging import CustomLogger
from abstrakt.pythonModules.vendors.security.crowdstrike.CrowdStrike import CrowdStrike


class CrowdStrikeSensors(CrowdStrike):
  def __init__(self, falcon_client_id: str,
               falcon_client_secret: str,
               logger: CustomLogger,
               registry: str,
               repository: str):
    super().__init__(falcon_client_id,
                     falcon_client_secret,
                     logger)
    self.registry = registry
    self.repository = repository

  @staticmethod
  def get_default_repository_name(sensor_type: str):
    if sensor_type == 'daemonset':
      return 'falcon-daemonset-sensor'
    elif sensor_type == 'sidecar':
      return 'falcon-sidecar-sensor'
    elif sensor_type == 'falcon-kac':
      return 'falcon-kac'
    elif sensor_type == 'falcon-imageanalyzer':
      return 'falcon-iar'

  def check_registry_type(self, registry: str) -> str:
    try:
      if registry:
        ecr_regex = re.compile(
          r"^\d{12}\.dkr\.ecr\.[a-z]+-[a-z]+-[0-9]+\.amazonaws\.com"
        )

        crwd_regex = re.compile(
          r"^registry\.crowdstrike\.com/(falcon-sensor|falcon-container|falcon-kac|falcon-imageanalyzer)/("
          r"us-1|us-2|eu-1)/release/(falcon-sensor|falcon-container|falcon-kac|falcon-imageanalyzer)$"
        )

        acr_regex = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{3,48}[a-zA-Z0-9])?\.azurecr\.io")

        artifact_regex = re.compile(r"^[a-z]+-[a-z0-9]+-docker\.pkg\.dev$")

        if bool(ecr_regex.match(registry)):
          return 'ecr'
        elif bool(crwd_regex.match(registry)):
          return 'crwd'
        elif bool(acr_regex.match(registry)):
          return 'acr'
        elif bool(artifact_regex.match(registry)):
          return 'artifact'
        else:
          return 'unsupported'
      else:
        return 'crwd'
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return 'unsupported'

  def get_image_repo(self, sensor_type) -> tuple:
    if self.registry is None:
      return 'crwd_registry', self.get_crowdstrike_registry(sensor_type=sensor_type)
    elif self.registry:
      registry_type = self.check_registry_type(registry=self.registry)

      if registry_type == 'crwd_registry':
        return 'crwd_registry', self.registry
      elif registry_type == 'ecr_registry':
        return 'ecr_registry', self.registry
      else:
        return 'unsupported', self.registry
    else:
      return 'None', 'None'

  def get_crwd_image_tag(self, sensor_type, image_tag) -> str:
    if sensor_type == 'daemonset':
      return self.get_crowdstrike_sensor_image_tag(sensor_type='daemonset', image_tag=image_tag)
    elif sensor_type == 'sidecar':
      return self.get_crowdstrike_sensor_image_tag(sensor_type='sidecar', image_tag=image_tag)
    elif sensor_type == 'falcon-kac':
      return self.get_crowdstrike_sensor_image_tag(sensor_type='falcon-kac', image_tag=image_tag)
    elif sensor_type == 'falcon-imageanalyzer':
      return self.get_crowdstrike_sensor_image_tag(sensor_type='falcon-imageanalyzer', image_tag=image_tag)
    else:
      return 'None'

  def get_crwd_repo_tag_token(self, sensor_type, image_tag='latest') -> tuple:
    registry_type, registry_uri = self.get_image_repo(sensor_type=sensor_type)
    image_tag = self.get_crwd_image_tag(sensor_type=sensor_type, image_tag=image_tag)
    image_pull_token = self.get_crowdstrike_image_pull_token()

    return registry_uri, image_tag, image_pull_token
