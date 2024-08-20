from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.CrowdStrikeSensors import CrowdStrikeSensors


class GCPFalconSensor(CrowdStrikeSensors):
  def __init__(self, falcon_client_id, falcon_client_secret, logger, image_registry=None, proxy_server=None,
               proxy_port=None, sensor_tags=None, cluster_name=None, cluster_type=None):
    super().__init__(falcon_client_id, falcon_client_secret, logger, image_registry, proxy_server,
                     proxy_port, sensor_tags, cluster_name, cluster_type)

  def get_repo_tag_token(self, sensor_type, image_tag) -> tuple:
    registry_type, registry_uri = self.get_image_repo(sensor_type=sensor_type)

    if registry_type == 'crwd_registry':
      falcon_image_repo, falcon_image_tag, falcon_image_pull_token = self.get_crwd_repo_tag_token(
        sensor_type=sensor_type, image_tag=image_tag)

      return registry_type, falcon_image_repo, falcon_image_tag, falcon_image_pull_token
    else:
      return None, None, None, None
