from abstrakt.pythonModules.customLogging.customLogging import CustomLogger
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.falconsensor._FalconSensor import FalconSensor


class Daemonset(FalconSensor):
  def __init__(self, client_id: str,
               client_secret: str,
               logger: CustomLogger,
               registry: str,
               repository: str,
               proxy_server: str,
               proxy_port: str,
               image_tag: str,
               sensor_tags: str,
               sensor_mode: str):
    super().__init__(client_id,
                     client_secret,
                     logger,
                     registry,
                     repository,
                     proxy_server,
                     proxy_port,
                     image_tag,
                     sensor_tags)
    self.sensor_mode = sensor_mode

  def get_image_registry(self, image_registry, image_repository, sensor_type) -> str | None:
    if image_registry:
      registry_type = self.check_registry_type(image_registry=image_registry)

      if registry_type == 'ecr':
        return f'{image_registry}/{image_repository}'
      else:
        return None
    else:
      return self.get_crowdstrike_registry(sensor_type=sensor_type)
