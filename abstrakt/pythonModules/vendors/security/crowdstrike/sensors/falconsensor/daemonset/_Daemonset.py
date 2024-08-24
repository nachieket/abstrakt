import inspect

from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.falconsensor._FalconSensor import FalconSensor


class Daemonset(FalconSensor):
  kernel_mode: bool
  ebpf_mode: bool

  def get_helm_chart(self):
    registry_type, falcon_image_repo, falcon_image_tag, falcon_image_pull_token = self.get_repo_tag_token(
      sensor_type='daemonset', image_tag=self.sensor_image_tag)

    if falcon_image_repo != 'None' and falcon_image_tag != 'None' and falcon_image_pull_token != 'None':
      helm_chart = [
        "helm", "upgrade", "--install", "daemonset-falcon-sensor", "crowdstrike/falcon-sensor",
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

      if self.sensor_tags:
        tags = '\\,'.join(self.sensor_tags.split(','))
        helm_chart.append("--set")
        helm_chart.append(f'falcon.tags="{tags}"')

      return helm_chart
    else:
      return False

  def aws_daemonset_falcon_sensor_thread(self):
    helm_chart = self.get_helm_chart()

    if helm_chart is not False:
      command = ' '.join(helm_chart)

      self.logger.info(f'Running command: {command}')
      self.run_command(command=command)
    else:
      return False

  def execute_helm_chart(self):
    try:
      with MultiThreading() as mt:
        mt.run_with_progress_indicator(self.aws_daemonset_falcon_sensor_thread, 1)
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      return False
    else:
      return True

  def check_falcon_sensor_installation(self) -> bool:
    k8s = KubectlOps(logger=self.logger)

    falcon_sensor_names = ['daemonset-falcon-sensor', 'falcon-helm-falcon-sensor']

    for falcon_sensor in falcon_sensor_names:
      if k8s.namespace_exists(namespace_name='falcon-system'):
        captured_pods, status = k8s.find_pods_with_status(pod_string=falcon_sensor, namespace='falcon-system')

        if (status is True) and (len(captured_pods['running']) > 0):
          print('Falcon sensors found up and running in falcon-system namespace. Skipping installation...')

          for pod in captured_pods['running']:
            print(pod)

          print()
          return True

    return False

  def deploy_falcon_sensor_daemonset(self):
    """Deploys the CrowdStrike Falcon Sensor daemonset on a Kubernetes cluster."""

    print(f"{'+' * 26}\nCrowdStrike Falcon Sensor\n{'+' * 26}\n")

    print("Installing Falcon Sensor in Daemonset Mode...")

    if self.check_falcon_sensor_daemonset_installation():
      return

    if self.execute_helm_chart():
      print("Falcon sensor installation successful\n")

      container = ContainerOps(logger=self.logger)
      container.pod_checker(pod_name='falcon-sensor', namespace='falcon-system', kubeconfig_path='~/.kube/config')
    else:
      print("Falcon sensor installation failed\n")
