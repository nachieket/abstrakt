import inspect

from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.falconsensor.GCP import GCP


class GCPDaemonset(GCP):
  def __init__(self, falcon_client_id: str,
               falcon_client_secret: str,
               logger,
               registry: str,
               repository: str,
               project_id: str,
               service_account: str,
               location: str,
               sensor_image_tag: str,
               sensor_tags: str,
               proxy_server: str,
               proxy_port: int,
               cluster_type: str):
    super().__init__(falcon_client_id,
                     falcon_client_secret,
                     logger,
                     registry,
                     repository,
                     project_id,
                     service_account,
                     location)

    self.sensor_image_tag: str = sensor_image_tag
    self.sensor_tags: str = sensor_tags
    self.proxy_server: str = proxy_server
    self.proxy_port: int = proxy_port
    self.cluster_type: str = cluster_type

  def get_helm_chart(self):
    if self.repository:
      repository: str = self.repository
    else:
      repository: str = self.get_default_repository_name(sensor_type='daemonset')

    registry_type: str = self.check_registry_type(registry=self.registry)

    if registry_type == 'artifact':
      # Get the access token for the target Google Artifact Registry
      access_token = self.get_access_token(repository=repository, location=self.location,
                                           service_account=self.service_account)
      if not access_token:
        self.logger.error("Failed to retrieve access token for the Google Artifact Registry.")
        return None
    else:
      access_token = None

    registry: str = self.get_image_registry(registry=self.registry,
                                            registry_type=registry_type,
                                            sensor_type='daemonset')

    image_tag: str = self.get_image_tag(registry=registry,
                                        registry_type=registry_type,
                                        repository=repository,
                                        image_tag=self.sensor_image_tag,
                                        location=self.location,
                                        project=self.project_id,
                                        access_token=access_token,
                                        sensor_type='daemonset')

    pull_token: str = self.get_image_pull_token(registry=registry, access_token=access_token)

    if registry and image_tag and pull_token:
      helm_chart = [
        "helm", "upgrade", "--install", "daemonset-falcon-sensor", "crowdstrike/falcon-sensor",
        "-n", "falcon-system", "--create-namespace",
        "--set", f"falcon.cid={self.falcon_cid}",
        "--set", f"node.image.tag={image_tag}",
        "--set", f"node.image.registryConfigJSON={pull_token}",
        "--set", f'node.backend=bpf'
      ]

      if registry_type == 'crwd':
        helm_chart.append('--set')
        helm_chart.append(f'node.image.repository={registry}')
      elif registry_type == 'artifact':
        helm_chart.append('--set')
        helm_chart.append(f'node.image.repository={registry}/{self.project_id}/{repository}/{image_tag.lower()}')

      if self.cluster_type == 'gke-autopilot':
        helm_chart.append('--set')
        helm_chart.append('node.gke.autopilot=true')

      if self.proxy_server and self.proxy_port:
        helm_chart.append("--set")
        helm_chart.append(f'falcon.apd=false')
        helm_chart.append("--set")
        helm_chart.append(f'falcon.aph=http://{self.proxy_server}')
        helm_chart.append("--set")
        helm_chart.append(f'falcon.app={self.proxy_port}')

      if self.sensor_tags:
        # tags = '\\,'.join(self.tags.strip('"').split(','))
        tags = '\\,'.join(self.sensor_tags.split(','))
        helm_chart.append("--set")
        helm_chart.append(f'falcon.tags="{tags}"')

      return helm_chart
    else:
      return None

  def default_app_thread(self):
    command = 'kubectl apply -f abstrakt/conf/crowdstrike/detections-container/default-vulnerable-app.yaml'

    self.logger.info(f'Running command: {command}')
    self.run_command(command=command)

  def execute_default_app(self):
    try:
      self.default_app_thread()
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      return False
    else:
      return True

  def daemonset_thread(self, cluster_type):
    helm_chart = self.get_helm_chart()

    if helm_chart:
      command = ' '.join(helm_chart)

      self.logger.info(f'Running command: {command}')
      self.run_command(command=command)

      if cluster_type == 'gke-autopilot':
        command = 'kubectl delete -f abstrakt/conf/crowdstrike/detections-container/default-vulnerable-app.yaml'

        self.logger.info(f'Running command: {command}')
        self.run_command(command=command)

      return True
    else:
      return False

  def execute_helm_chart(self, cluster_type):
    try:
      with MultiThreading() as mt:
        return True if mt.run_with_progress_indicator(self.daemonset_thread, 1, 300, cluster_type) else False
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      return False

  def deploy_falcon_sensor_daemonset(self):
    if self.cluster_type == 'gke-autopilot':
      print(f"{'+' * 14}\nGKE Autopilot\n{'+' * 14}\n")

      print("Spinning up GKE Autopilot Nodes...")

      self.execute_default_app()

      container = ContainerOps(logger=self.logger)
      container.pod_checker(pod_name='vulnerable-example-com', namespace='default',
                            kubeconfig_path='~/.kube/config', timeout=600)

      print('\nAll these pods are temporary, were created to spin up nodes, and will be deleted in a few moments.\n')

    print(f"{'+' * 26}\nCrowdStrike Falcon Sensor\n{'+' * 26}\n")

    print("Installing Falcon Sensor...")

    k8s = KubectlOps(logger=self.logger)

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

    if self.execute_helm_chart(cluster_type=self.cluster_type):
      print("Falcon sensor installation successful\n")

      container = ContainerOps(logger=self.logger)
      container.pod_checker(pod_name='falcon-sensor', namespace='falcon-system', kubeconfig_path='~/.kube/config')
    else:
      print("Falcon sensor installation failed\n")
