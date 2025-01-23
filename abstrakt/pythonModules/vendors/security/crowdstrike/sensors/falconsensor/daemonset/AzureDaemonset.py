import inspect

from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
# from abstrakt.pythonModules.multiThread.multithreading import MultiThreading
from abstrakt.pythonModules.multiProcess.multiProcessing import MultiProcessing
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.falconsensor.Azure import Azure


class AzureDaemonset(Azure):
  def __init__(self, falcon_client_id: str,
               falcon_client_secret: str,
               logger,
               registry: str,
               repository: str,
               rg_name: str,
               rg_location: str,
               acr_rg: str,
               sensor_image_tag: str,
               proxy_server: str,
               proxy_port: int,
               sensor_tags: str,
               sensor_mode: str,
               sp_name: str,
               sp_pass: str):
    super().__init__(falcon_client_id,
                     falcon_client_secret,
                     logger,
                     registry,
                     repository,
                     rg_name,
                     rg_location,
                     acr_rg)

    self.sensor_image_tag: str = sensor_image_tag
    self.proxy_server: str = proxy_server
    self.proxy_port: int = proxy_port
    self.sensor_tags: str = sensor_tags
    self.sensor_mode: str = sensor_mode
    self.sp_name: str = sp_name
    self.sp_pass: str = sp_pass

  def get_helm_chart(self, logger=None):
    logger = logger or self.logger

    if self.repository:
      repository: str = self.repository
    else:
      repository: str = self.get_default_repository_name(sensor_type='daemonset')

    registry_type: str = self.check_registry_type(registry=self.registry)

    registry: str = self.get_image_registry(registry=self.registry,
                                            registry_type=registry_type,
                                            sensor_type='daemonset')

    if registry_type == 'acr':
      sp_name, sp_pass = self.get_service_principal_credentials(registry=registry,
                                                                sp_name=self.sp_name,
                                                                sp_pass=self.sp_pass,
                                                                logger=logger)

      if sp_name is None or sp_pass is None:
        return False
    else:
      sp_name, sp_pass = None, None
      self.logger.info(f'None Service Principal Credentials {sp_name} {sp_pass}')

    image_tag = self.get_azure_image_tag(registry=registry,
                                         registry_type=registry_type,
                                         repository=repository,
                                         image_tag=self.sensor_image_tag,
                                         acr_rg=self.acr_rg,
                                         sp_name=sp_name,
                                         sp_pass=sp_pass,
                                         sensor_type='daemonset')
    if image_tag is None:
      self.logger.error('No image tag found.')
      return False

    image_pull_token = self.get_azure_image_pull_token(registry=registry,
                                                       registry_type=registry_type,
                                                       sp_name=sp_name,
                                                       sp_pass=sp_pass)
    if image_pull_token is None:
      self.logger.error('No image pull token found.')
      return False

    if registry and image_tag and image_pull_token:
      helm_chart = [
        "helm", "upgrade", "--install", "daemonset-falcon-sensor", "crowdstrike/falcon-sensor",
        "-n", "falcon-system", "--create-namespace",
        "--set", f"falcon.cid={self.falcon_cid}",
        "--set", f"node.image.tag={image_tag}",
        "--set", f"node.image.registryConfigJSON={image_pull_token}",
        "--set", f'node.backend={self.sensor_mode}'
      ]

      if registry_type == 'crwd':
        helm_chart.append('--set')
        helm_chart.append(f'node.image.repository={registry}')
      elif registry_type == 'acr':
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

      return helm_chart
    else:
      return False

  def azure_daemonset_falcon_sensor_thread(self, logger=None):
    logger = logger or self.logger

    helm_chart = self.get_helm_chart()

    if helm_chart:
      command = ' '.join(helm_chart)

      self.logger.info(f'Running command: {command}')
      self.run_command(command=command, logger=logger)

      return True
    else:
      return False

  def execute_helm_chart(self, logger=None):
    logger = logger or self.logger

    try:
      with MultiProcessing() as mp:
        return True if mp.execute_with_progress_indicator(self.azure_daemonset_falcon_sensor_thread,
                                                          logger,
                                                          0.5,
                                                          900) else False
      # with MultiThreading() as mt:
      #   return True if mt.run_with_progress_indicator(self.azure_daemonset_falcon_sensor_thread, 1, 300) else False
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      return False

  def deploy_azure_daemonset_falcon_sensor(self, logger=None):
    """Deploys the CrowdStrike Falcon Sensor _daemonset on a Kubernetes cluster."""
    logger = logger or self.logger

    print(f"{'+' * 26}\nCrowdStrike Falcon Sensor\n{'+' * 26}\n")

    print("Installing Falcon Sensor...")

    k8s = KubectlOps(logger=logger)

    falcon_sensor_names = ['daemonset-falcon-sensor', 'falcon-helm-falcon-sensor']

    for falcon_sensor in falcon_sensor_names:
      if k8s.namespace_exists(namespace_name='falcon-system'):
        captured_pods, status = k8s.find_pods_with_status(pod_string=falcon_sensor, namespace='falcon-system')

        if (status is True) and (len(captured_pods['running']) > 0):
          print('Falcon sensors found up and running in falcon-system namespace. Not proceeding with installation.')

          for pod in captured_pods['running']:
            print(pod)

          print(' ')
          return

    if self.execute_helm_chart(logger=logger):
      print("Falcon sensor installation successful\n")

      container = ContainerOps(logger=logger)
      container.pod_checker(pod_name='falcon-sensor', namespace='falcon-system', kubeconfig_path='~/.kube/config')
    else:
      print("Falcon sensor installation failed\n")
