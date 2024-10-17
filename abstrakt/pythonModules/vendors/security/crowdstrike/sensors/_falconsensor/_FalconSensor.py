import inspect

from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading


class _FalconSensor:
  @staticmethod
  def check_falcon_sensor_installation(sensor_names: list, namespace: str, logger) -> bool:
    k8s = KubectlOps(logger=logger)

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

  @staticmethod
  def check_falcon_sensor_pods(pod_name: str, namespace: str, logger):
    container = ContainerOps(logger=logger)
    container.pod_checker(pod_name=pod_name, namespace=namespace, kubeconfig_path='~/.kube/config')

  @staticmethod
  def execute_helm_chart(thread, logger) -> bool:
    try:
      with MultiThreading() as mt:
        mt.run_with_progress_indicator(thread, 1)
    except Exception as e:
      logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      logger.error(f'Error: {e}')
      return False
    else:
      return True
