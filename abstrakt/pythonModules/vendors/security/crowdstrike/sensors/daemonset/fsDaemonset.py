import inspect

from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.crowdStrikeSensors import CrowdStrikeSensors
from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf
from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading


class FalconSensorDaemonset(CrowdStrikeSensors):
  def __init__(self, falcon_client_id, falcon_client_secret, sensor_mode, logger, falcon_image_repo=None,
               falcon_image_tag=None, proxy_server=None, proxy_port=None, tags=None, cluster_type=None):
    super().__init__(falcon_client_id, falcon_client_secret, sensor_mode, logger, falcon_image_repo, falcon_image_tag,
                     proxy_server, proxy_port, tags)

    self.cluster_type = cluster_type

  def get_helm_chart(self):
    self.get_falcon_art_password()
    self.get_falcon_art_username()

    registry_type, falcon_image_repo, falcon_image_tag, falcon_image_pull_token = self.get_image_repo_tag_pull_token()

    if falcon_image_repo is not None and falcon_image_tag is not None and falcon_image_pull_token is not None:
      helm_chart = [
        "helm", "upgrade", "--install", "daemonset-falcon-sensor", "crowdstrike/falcon-sensor",
        "-n", "falcon-system", "--create-namespace",
        "--set", f"falcon.cid={self.falcon_cid}",
        "--set", f"node.image.repository={falcon_image_repo}",
        "--set", f"node.image.tag={falcon_image_tag}",
        "--set", f"node.image.registryConfigJSON={falcon_image_pull_token}",
        "--set", f'node.backend={self.sensor_mode}'
      ]

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

      if self.tags:
        # tags = '\\,'.join(self.tags.strip('"').split(','))
        tags = '\\,'.join(self.tags.split(','))
        helm_chart.append("--set")
        helm_chart.append(f'falcon.tags="{tags}"')

      return helm_chart
    else:
      return False

  def execute_helm_chart(self):
    try:
      def thread():
        helm_chart = self.get_helm_chart()

        if helm_chart is not False:
          command = ' '.join(helm_chart)

          self.logger.info(f'Running command: {command}')
          output, error = self.run_command(command=command, output=True)

          self.logger.info(output)
          self.logger.error(error)
        else:
          return False

      with MultiThreading() as mt:
        mt.run_with_progress_indicator(thread, 1)
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      return False
    else:
      return True

  def deploy_falcon_sensor_daemonset(self):
    """Deploys the CrowdStrike Falcon Sensor daemonset on a Kubernetes cluster."""

    printf(f"{'+' * 26}\nCrowdStrike Falcon Sensor\n{'+' * 26}\n", logger=self.logger)

    # if region and cluster_name:
    #   kube = UpdateKubeConfig(logger=self.logger)
    #   kube.update_kubeconfig(cloud='aws', region=region, cluster_name=cluster_name)
    # elif cluster_name and resource_group:
    #   kube = UpdateKubeConfig(logger=self.logger)
    #   kube.update_kubeconfig(cloud='azure', cluster_name=cluster_name, resource_group=resource_group)
    # elif cloud_type == 'gcp':
    #   pass
    #   kube = UpdateKubeConfig(logger=self.logger)
    #   kube.update_kubeconfig(cloud='gcp', cluster_name=cluster_name, region=region)

    printf("Installing Falcon Sensor...", logger=self.logger)

    k8s = KubectlOps(logger=self.logger)

    falcon_sensor_names = ['daemonset-falcon-sensor', 'falcon-helm-falcon-sensor']

    for falcon_sensor in falcon_sensor_names:
      if k8s.namespace_exists(namespace_name='falcon-system'):
        captured_pods, status = k8s.find_pods_with_status(pod_string=falcon_sensor, namespace='falcon-system')

        if (status is True) and (len(captured_pods['running']) > 0):
          print('Falcon sensors found up and running in falcon-system namespace. Not proceeding with installation.')

          for pod in captured_pods['running']:
            print(pod)

          print()
          return

    if self.execute_helm_chart():
      printf("Falcon sensor installation successful\n", logger=self.logger)

      container = ContainerOps(logger=self.logger)
      container.pod_checker(pod_name='falcon-sensor', namespace='falcon-system', kubeconfig_path='~/.kube/config')
    else:
      printf("Falcon sensor installation failed\n", logger=self.logger)
