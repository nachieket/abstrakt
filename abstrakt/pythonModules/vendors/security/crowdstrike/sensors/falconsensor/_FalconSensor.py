import inspect

from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.customLogging.customLogging import CustomLogger
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading

from abstrakt.pythonModules.vendors.security.crowdstrike.sensors._CrowdStrikeSensors import CrowdStrikeSensors


class FalconSensor(CrowdStrikeSensors):
  def __init__(self, client_id: str,
               client_secret: str,
               logger: CustomLogger,
               registry: str,
               repository: str,
               proxy_server: str,
               proxy_port: str,
               image_tag: str,
               sensor_tags: str):
    super().__init__(client_id,
                     client_secret,
                     logger,
                     registry,
                     repository,
                     proxy_server,
                     proxy_port)
    self.image_tag: str = image_tag
    self.sensor_tags: str = sensor_tags

  def check_falcon_sensor_installation(self, sensor_names: list, namespace: str) -> bool:
    k8s = KubectlOps(logger=self.logger)

    for falcon_sensor in sensor_names:
      if k8s.namespace_exists(namespace_name=namespace):
        captured_pods, status = k8s.find_pods_with_status(pod_string=falcon_sensor, namespace=namespace)

        if (status is True) and (len(captured_pods['running']) > 0):
          print('Falcon sensors found up and running in falcon-system namespace. Skipping installation...')

          for pod in captured_pods['running']:
            print(pod)

          print()
          return True

    return False

  def check_falcon_sensor_pods(self, pod_name: str, namespace: str):
    container = ContainerOps(logger=self.logger)
    container.pod_checker(pod_name=pod_name, namespace=namespace, kubeconfig_path='~/.kube/config')

  def execute_helm_chart(self, thread) -> bool:
    try:
      with MultiThreading() as mt:
        mt.run_with_progress_indicator(thread, 1)
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      return False
    else:
      return True
