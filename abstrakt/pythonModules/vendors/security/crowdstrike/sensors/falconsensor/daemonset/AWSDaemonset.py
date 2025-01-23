from abstrakt.pythonModules.customLogging.customLogging import CustomLogger
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.falconsensor.AWSFalconSensor import (
  AWSFalconSensor)
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.falconsensor.AWS import AWS


class AWSDaemonsetInstall(AWS, AWSFalconSensor):
  def __init__(self, falcon_client_id: str,
               falcon_client_secret: str,
               logger: CustomLogger,
               registry: str,
               repository: str,
               proxy_server: str,
               proxy_port: int,
               sensor_image_tag: str,
               sensor_tags: str,
               sensor_mode: str):
    super().__init__(falcon_client_id,
                     falcon_client_secret,
                     logger,
                     registry,
                     repository)
    self.proxy_server: str = proxy_server
    self.proxy_port: int = proxy_port
    self.sensor_image_tag: str = sensor_image_tag
    self.sensor_tags: str = sensor_tags
    self.sensor_mode: str = sensor_mode

  def get_daemonset_image_registry(self, registry: str, registry_type: str, sensor_type: str) -> str | None:
    if registry:
      if registry_type == 'ecr':
        return f'{registry}'
      elif registry_type == 'crwd':
        return self.get_crowdstrike_registry(sensor_type=sensor_type)
      else:
        return None
    else:
      return self.get_crowdstrike_registry(sensor_type=sensor_type)

  def get_daemonset_image_tag(self, registry: str, repository: str, image_tag: str,
                              sensor_type: str, logger=None) -> str | None:
    logger = logger or self.logger

    registry_type: str = self.check_registry_type(registry=registry)

    if registry_type == 'crwd':
      if 'latest' in image_tag:
        return self.get_crowdstrike_sensor_image_tag(sensor_type=sensor_type, image_tag=image_tag, logger=logger)
      elif self.verify_crowdstrike_sensor_image_tag(image_tag=image_tag, sensor_type=sensor_type, logger=logger):
        return image_tag
      return None

    if registry_type == 'ecr' and self.check_ecr_registry_exists(registry=registry, logger=logger):
      if not self.check_ecr_repository_exists(registry=registry, repository=repository, logger=logger):
        self.create_ecr_repository(registry=registry, repository=repository, sensor_type=sensor_type, logger=logger)

      if 'latest' in image_tag:
        image_tag: str = self.get_crowdstrike_sensor_image_tag(sensor_type=sensor_type,
                                                               image_tag=image_tag,
                                                               logger=logger)
      elif not self.verify_crowdstrike_sensor_image_tag(image_tag=image_tag, sensor_type=sensor_type, logger=logger):
        return None

      if self.check_image_exists_on_ecr(registry=registry, repository=repository, image_tag=image_tag, logger=logger):
        return image_tag

      source_registry = self.get_crowdstrike_registry(sensor_type=sensor_type)
      if self.copy_crowdstrike_image_to_ecr(source_registry=source_registry, repository=repository,
                                            target_registry=registry, image_tag=image_tag, logger=logger):
        if self.check_image_exists_on_ecr(registry=registry, repository=repository, image_tag=image_tag, logger=logger):
          return image_tag

    return None

  def get_daemonset_image_pull_token(self, registry: str) -> str | None:
    registry_type: str = self.check_registry_type(registry=registry)

    if registry_type == 'crwd':
      return self.get_crowdstrike_image_pull_token()
    elif registry_type == 'ecr':
      return self.get_ecr_image_pull_token(registry=registry)
    else:
      return None

  def get_helm_chart(self, logger=None) -> str | None:
    logger = logger or self.logger

    if self.repository:
      repository: str = self.repository
    else:
      repository: str = self.get_default_repository_name(sensor_type='daemonset')

    registry_type: str = self.check_registry_type(registry=self.registry, logger=logger)

    registry: str = self.get_daemonset_image_registry(registry=self.registry,
                                                      registry_type=registry_type,
                                                      sensor_type='daemonset')

    image_tag: str = self.get_daemonset_image_tag(registry=registry,
                                                  repository=repository,
                                                  image_tag=self.sensor_image_tag,
                                                  sensor_type='daemonset',
                                                  logger=logger)

    pull_token: str = self.get_daemonset_image_pull_token(registry=registry)

    if registry and image_tag and pull_token:
      helm_chart: list = [
        "helm", "upgrade", "--install", "daemonset-falcon-sensor", "crowdstrike/falcon-sensor",
        "-n", "falcon-system", "--create-namespace",
        "--set", f"falcon.cid={self.falcon_cid}",
        "--set", f"node.image.tag={image_tag}",
        "--set", f"node.image.registryConfigJSON={pull_token}",
        "--set", f'node.backend={self.sensor_mode}'
      ]

      if registry_type == 'crwd':
        helm_chart.append('--set')
        helm_chart.append(f'node.image.repository={registry}')
      elif registry_type == 'ecr':
        helm_chart.append('--set')
        helm_chart.append(f'node.image.repository={registry}/{repository}')

      if self.proxy_server and self.proxy_port:
        helm_chart.append("--set")
        helm_chart.append(f'falcon.apd=false')
        helm_chart.append("--set")
        helm_chart.append(f'falcon.aph=http://{self.proxy_server}')
        helm_chart.append("--set")
        helm_chart.append(f'falcon.app={self.proxy_port}')

      if self.sensor_tags:
        tags = '\\,'.join(self.sensor_tags.split(','))
        helm_chart.append("--set")
        helm_chart.append(f'falcon.tags="{tags}"')

      return ' '.join(helm_chart)
    else:
      return None

  def execute_daemonset_falcon_sensor_thread(self, logger=None) -> bool:
    logger = logger or self.logger

    helm_chart: str = self.get_helm_chart(logger)

    if helm_chart:
      logger.info(f'Running command: {helm_chart}')
      if self.run_command(command=helm_chart):
        return True
    else:
      return False

  def deploy_falcon_sensor_daemonset(self, logger=None):
    logger = logger or self.logger

    print(f"{'+' * 26}\nCrowdStrike Falcon Sensor\n{'+' * 26}\n")

    print("Installing Falcon Sensor in Daemonset Mode...")

    if self.check_falcon_sensor_installation(sensor_names=['daemonset-falcon-sensor',
                                                           'falcon-helm-falcon-sensor',
                                                           'falcon-sensor'],
                                             namespace='falcon-system',
                                             logger=logger):
      return

    if self.execute_helm_chart(self.execute_daemonset_falcon_sensor_thread, logger=logger):
      print("Falcon sensor installation successful\n")

      self.check_falcon_sensor_pods(pod_name='falcon-sensor', namespace='falcon-system', logger=logger)
    else:
      print("Falcon sensor installation failed\n")
