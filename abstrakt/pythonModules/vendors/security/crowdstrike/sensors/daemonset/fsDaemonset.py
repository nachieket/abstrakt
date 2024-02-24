import subprocess
import inspect

from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.crowdStrikeSensors import CrowdStrikeSensors
from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf
from abstrakt.pythonModules.kubernetesOps.updateKubeConfig import UpdateKubeConfig
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading


class FalconSensorDaemonset(CrowdStrikeSensors):
  def __init__(self, falcon_client_id, falcon_client_secret, falcon_cid,
               falcon_cloud_region, falcon_cloud_api, sensor_mode, logger,
               proxy_server=None, proxy_port=None, tags=None):
    super().__init__(falcon_client_id, falcon_client_secret, falcon_cid,
                     falcon_cloud_region, falcon_cloud_api, sensor_mode,
                     logger, proxy_server, proxy_port, tags)

  def get_helm_chart(self):
    falcon_image_repo = self.get_falcon_image_repo()
    falcon_image_tag = self.get_falcon_image_tag()
    falcon_image_pull_token = self.get_falcon_image_pull_token()

    if (falcon_image_repo or falcon_image_tag or falcon_image_pull_token) is not False:
      helm_chart = [
        "helm", "upgrade", "--install", "falcon-helm", "crowdstrike/falcon-sensor",
        "-n", "falcon-system", "--create-namespace",
        "--set", f"falcon.cid={self.falcon_cid}",
        "--set", f"node.image.repository={falcon_image_repo}",
        "--set", f"node.image.tag={falcon_image_tag}",
        "--set", f"node.image.registryConfigJSON={falcon_image_pull_token}",
        "--set", f'node.backend={self.sensor_mode}'
      ]

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
        helm_chart.append(f"falcon.tags={tags}")

      return helm_chart
    else:
      return False

  def execute_helm_chart(self):
    try:
      def thread():
        helm_chart = self.get_helm_chart()

        if helm_chart is not False:
          helm_process = subprocess.run(helm_chart, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

          if helm_process.stdout:
            self.logger.info(helm_process.stdout)

          if helm_process.stderr:
            self.logger.info(helm_process.stderr)
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

  def deploy_falcon_sensor_daemonset(self, cloud, region=None, cluster_name=None, resource_group=None):
    """Deploys the CrowdStrike Falcon Sensor daemonset on a Kubernetes cluster."""

    printf(f"{'+' * 26}\nCrowdStrike Falcon Sensor\n{'+' * 26}\n", logger=self.logger)

    if region and cluster_name:
      kube = UpdateKubeConfig(logger=self.logger)
      kube.update_kubeconfig(cloud='aws', region=region, cluster_name=cluster_name)
    elif cluster_name and resource_group:
      kube = UpdateKubeConfig(logger=self.logger)
      kube.update_kubeconfig(cloud='azure', cluster_name=cluster_name, resource_group=resource_group)
    elif cloud == 'gcp':
      pass

    printf("Installing Falcon Sensor...", logger=self.logger)

    if self.execute_helm_chart():
      printf("Falcon sensor installation successful\n", logger=self.logger)

      container = ContainerOps(logger=self.logger)
      container.pod_checker(pod_name='falcon-sensor', namespace='falcon-system', kubeconfig_path='~/.kube/config')
    else:
      printf("Falcon sensor installation failed\n", logger=self.logger)
