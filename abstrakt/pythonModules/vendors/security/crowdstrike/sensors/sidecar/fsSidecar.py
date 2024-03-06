import subprocess

from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.crowdStrikeSensors import CrowdStrikeSensors
from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf
from abstrakt.pythonModules.kubernetesOps.updateKubeConfig import UpdateKubeConfig
from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading


class FalconSensorSidecar(CrowdStrikeSensors):
  def __init__(self, falcon_client_id, falcon_client_secret, monitor_namespaces,
               exclude_namespaces, sensor_mode, logger):
    super().__init__(falcon_client_id, falcon_client_secret, sensor_mode, logger)

    self.monitor_namespaces = monitor_namespaces
    self.exclude_namespaces = exclude_namespaces

  def get_helm_chart(self, namespaces=None, proxy_ip=None, proxy_port=None, tags=None):
    falcon_image_repo = self.get_falcon_image_repo()
    falcon_image_tag = self.get_falcon_image_tag()
    falcon_image_pull_token = self.get_falcon_image_pull_token()

    if (falcon_image_repo or falcon_image_tag or falcon_image_pull_token) is not False:
      helm_chart = [
        "helm", "upgrade", "--install", "falcon-container", "crowdstrike/falcon-sensor",
        "-n", "falcon-system", "--create-namespace",
        "--set", "node.enabled=false",
        "--set", "container.enabled=true",
        "--set", f"falcon.cid={self.falcon_cid}",
        "--set", f"container.image.repository={falcon_image_repo}",
        "--set", f"container.image.tag={falcon_image_tag}",
        "--set", "container.image.pullSecrets.enable=true",
        "--set", f"container.image.pullSecrets.registryConfigJSON={falcon_image_pull_token}"
        # "--set", "container.image.pullSecrets.namespaces=default\\,ns2"
      ]

      kube = KubectlOps(logger=self.logger)

      if self.monitor_namespaces.lower() == 'all' and self.exclude_namespaces:
        updated_namespaces = []
        for ns in namespaces:
          if ns in self.exclude_namespaces:
            kube.run_kubectl_command(
              f'kubectl label namespace {ns} sensor.falcon-system.crowdstrike.com/injection=disabled'
            )
          else:
            updated_namespaces.append(ns)
        temp = '\\,'.join(updated_namespaces)
        helm_chart.append("--set")
        helm_chart.append(f'container.image.pullSecrets.namespaces={temp}')
      elif self.monitor_namespaces.lower() == 'all':
        temp = '\\,'.join(namespaces)
        helm_chart.append("--set")
        helm_chart.append(f'container.image.pullSecrets.namespaces={temp}')
      elif self.monitor_namespaces.lower() != 'all' and not self.exclude_namespaces:
        if len(self.monitor_namespaces.split(',')) == 1:
          for ns in namespaces:
            if ns != self.monitor_namespaces:
              kube.run_kubectl_command(
                f'kubectl label namespace {ns} sensor.falcon-system.crowdstrike.com/injection=disabled'
              )
          helm_chart.append(f"container.image.pullSecrets.namespaces=default\\,{self.monitor_namespaces}")
        else:
          for ns in namespaces:
            if ns not in self.monitor_namespaces:
              kube.run_kubectl_command(
                f'kubectl label namespace {ns} sensor.falcon-system.crowdstrike.com/injection=disabled'
              )
          temp = '\\,'.join(self.monitor_namespaces.split(','))
          helm_chart.append("--set")
          helm_chart.append(f'container.image.pullSecrets.namespaces={temp}')

      if proxy_ip and proxy_port:
        helm_chart.append("--set")
        helm_chart.append(f'falcon.apd=false')
        helm_chart.append("--set")
        helm_chart.append(f'falcon.aph=http://{proxy_ip}')
        helm_chart.append("--set")
        helm_chart.append(f'falcon.app={proxy_port}')

      if tags:
        tags = '\\,'.join(tags)
        helm_chart.append("--set")
        helm_chart.append(f"falcon.tags={tags}")

      return helm_chart
    else:
      return False

  def execute_helm_chart(self, namespaces=None, proxy_ip=None, proxy_port=None, tags=None):
    try:
      helm_chart = self.get_helm_chart(namespaces, proxy_ip, proxy_port, tags)

      if helm_chart is not False:
        helm_process = subprocess.run(helm_chart, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if helm_process.stdout:
          self.logger.info(helm_process.stdout)

        if helm_process.stderr:
          self.logger.info(helm_process.stderr)
      else:
        return False
    except Exception as e:
      printf(f"An error occurred: {e}\n", logger=self.logger)
      return False
    else:
      return True

  def deploy_falcon_sensor_sidecar(self, cloud, region=None, cluster_name=None, resource_group=None,
                                   proxy_ip=None, proxy_port=None, tags=None):
    """Deploys the CrowdStrike Falcon Sensor sidecar on a Kubernetes cluster."""

    def thread():
      if region and cluster_name:
        kube = UpdateKubeConfig(logger=self.logger)
        kube.update_kubeconfig(cloud='aws', region=region, cluster_name=cluster_name)
      elif cluster_name and resource_group:
        kube = UpdateKubeConfig(logger=self.logger)
        kube.update_kubeconfig(cloud='azure', cluster_name=cluster_name, resource_group=resource_group)
      elif cloud == 'gcp':
        pass

      kube = KubectlOps(logger=self.logger)

      crowdstrike_namespaces = ['falcon-kubernetes-protection', 'falcon-kac', 'crowdstrike-detections']

      try:
        for namespace in crowdstrike_namespaces:
          kube.run_kubectl_command(f'kubectl create namespace {namespace}')
          kube.run_kubectl_command(
            f'kubectl label namespace {namespace} sensor.falcon-system.crowdstrike.com/injection=disabled'
          )
      except Exception as e:
        self.logger.error(f'{e}')

      generic_namespaces = ['ns1', 'ns2']

      try:
        for namespace in generic_namespaces:
          kube.run_kubectl_command(f'kubectl create namespace {namespace}')
      except Exception as e:
        self.logger.error(f'{e}')

      namespaces: list = kube.get_all_namespaces('~/.kube/config')
      namespaces = [ns for ns in namespaces if 'kube-' not in ns]
      namespaces = [ns for ns in namespaces if ns not in crowdstrike_namespaces]

      if self.execute_helm_chart(namespaces, proxy_ip, proxy_port, tags):
        return True
      else:
        return False

    printf(f"\n{'+' * 26}\nCrowdStrike Falcon Sensor\n{'+' * 26}\n", logger=self.logger)

    printf("Installing Falcon Sensor...", logger=self.logger)

    with MultiThreading() as mt:
      if mt.run_with_progress_indicator(thread, 1):
        printf("Falcon sensor installation successful\n", logger=self.logger)
        container = ContainerOps(logger=self.logger)
        container.pod_checker(pod_name='falcon-sensor', namespace='falcon-system', kubeconfig_path='~/.kube/config')
      else:
        printf("Falcon sensor installation failed\n", logger=self.logger)
