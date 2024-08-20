# import json
# import boto3
# import base64
# import inspect
# import subprocess
#
# from pathlib import Path
from azure.identity import DefaultAzureCredential
from azure.containerregistry import ContainerRegistryClient
from azure.mgmt.containerregistry import ContainerRegistryManagementClient

from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.CrowdStrikeSensors import CrowdStrikeSensors


class Daemonset(CrowdStrikeSensors):
  def __init__(self, falcon_client_id=None, falcon_client_secret=None, logger=None, image_registry=None,
               proxy_server=None, proxy_port=None, sensor_tags=None, cluster_name=None, cluster_type=None,
               sensor_mode=None, sensor_image_tag=None):
    super().__init__(falcon_client_id, falcon_client_secret, logger, image_registry, proxy_server, proxy_port,
                     sensor_tags, cluster_name, cluster_type)

    self.sensor_mode = sensor_mode
    self.sensor_image_tag = sensor_image_tag

  def get_crwd_daemonset_sensor_image_tag(self, image_tag) -> str | None:
    if image_tag and 'latest' in image_tag:
      return self.get_crwd_daemonset_image_tag(image_tag=image_tag)
    else:
      if self.verify_daemonset_image_tag(image_tag=image_tag):
        return image_tag

    return None
