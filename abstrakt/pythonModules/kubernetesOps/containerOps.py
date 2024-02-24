import subprocess
# import json
# import logging
# from typing import Tuple

from kubernetes import client
from kubernetes import config
from kubernetes.client import ApiException

from time import sleep

from abstrakt.pythonModules.multiThread.multithreading import MultiThreading
from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf


class ContainerOps:
  def __init__(self, logger):
    self.logger = logger

  def get_running_container_name(self, container_name, container_namespace='default'):
    try:
      sensors = []

      # Run the kubectl command to get pod names in the specified namespace
      cmd = (f"kubectl get pods -n {container_namespace} -o custom-columns=NAME:.metadata.name,"
             f"CONTAINERS:.spec.containers[*].name,STATUS:.status.phase --no-headers=true")

      self.logger.info(f'Executing command: {cmd}')

      output = subprocess.check_output(cmd, shell=True, stderr=subprocess.PIPE, text=True)

      # Split the output into lines
      lines = output.strip().split('\n')

      # Iterate through the lines and find the running container with a name
      for line in lines:
        parts = line.split()
        pod_name = parts[0]

        if container_name in pod_name:
          cmd = (f"kubectl get pod {pod_name} -n {container_namespace} -o custom-columns=NAME:.metadata.name,"
                 f"CONTAINERS:.spec.containers[*].name,STATUS:.status.phase --no-headers=true")

          self.logger.info(f'Executing command: {cmd}')

          counter = 0

          while counter < 60:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.PIPE, text=True).split()

            self.logger.info(output)

            if output[-1] == 'Running':
              sensors.append(output[0])
              break
            else:
              counter += 1
              sleep(5)
      else:
        return sensors if sensors else 'None'
    except subprocess.CalledProcessError as e:
      # Handle any errors that occur when running the kubectl command
      printf(f"Error running kubectl: {e}", logger=self.logger)
      return 'None'

  def check_namespace_exists(self, namespace, kubeconfig_path):
    """Checks if a namespace exists in the Kubernetes cluster.

    Args:
        namespace (str): The name of the namespace to check.
        kubeconfig_path (str, optional): Path to the kubeconfig file. Defaults to None.

    Returns:
        bool: True if the namespace exists, False otherwise.
    """
    try:
      config.load_kube_config(config_file=kubeconfig_path)
      v1 = client.CoreV1Api()
      v1.read_namespace(namespace)  # Raises exception if not found

      return True
    except ApiException as e:
      self.logger.error(e)
      return False

  def are_pod_and_containers_running(self, pod_name: str, namespace: str, kubeconfig_path: str) -> tuple[dict, int]:
    """
      Check if pods with a given name substring are running in a Kubernetes namespace.

      Args:
          pod_name (str): Substring to match in pod names.
          namespace (str): The Kubernetes namespace to search for pods.
          kubeconfig_path (str): Path to the Kubernetes configuration file.

      Returns:
          tuple[dict, int]: A tuple containing a dictionary of pod statuses and a counter of stopped pods.
              - The dictionary (pods) has pod names as keys and their status as values.
              - The counter (counter) represents the number of stopped pods.
    """
    if self.check_namespace_exists(namespace=namespace, kubeconfig_path=kubeconfig_path):
      try:
        # Load Kubernetes configuration
        config.load_kube_config(config_file=kubeconfig_path)
        v1 = client.CoreV1Api()

        # Initialize variables
        pods: dict = {}
        down: int = 0

        # Get pods in the specified namespace
        pod_list = v1.list_namespaced_pod(namespace)

        for pod in pod_list.items:
          if pod_name in pod.metadata.name:  # Check for pod name substring match
            while True:
              pod_status = v1.read_namespaced_pod_status(name=pod.metadata.name, namespace=namespace)

              # Check if the pod phase is 'Running'
              if pod_status.status.phase == 'Running':
                pods[pod.metadata.name] = {'podStatus': 'Running'}

                # Check if all containers within the pod are running
                for container_status in pod_status.status.container_statuses:
                  pods[pod.metadata.name]['containerName'] = container_status.name
                  pods[pod.metadata.name]['containerStatus'] = container_status.state.running
                break
              elif pod_status.status.phase == ('Pending' or 'ContainerCreating'):
                continue
              elif pod_status.status.phase == 'Failed':
                pods[pod.metadata.name]['podStatus'] = 'Failed'
                down += 1
                break
              elif pod_status.status.phase == 'Unknown':
                pods[pod.metadata.name]['podStatus'] = 'Unknown'
                down += 1
                break
              else:
                pods[pod.metadata.name]['podStatus'] = 'Undefined'
                down += 1
                break

        return pods, down
      except ApiException as e:
        self.logger.error(f"Exception when calling CoreV1Api: {e}")
        return {}, -1  # Return an error code
    else:
      self.logger.error(f'Namespace {namespace} does not exist\n')
      return {}, -1  # Return an error code

  def pod_checker(self, pod_name: str, namespace: str, kubeconfig_path: str = '~/.kube/config') -> list:
    print(f"Checking {pod_name} status...")
    sleep(5)
    pod_names: list = []

    with MultiThreading() as mt:
      pods: dict
      down: int

      pods, down = mt.run_with_progress_indicator(
        self.are_pod_and_containers_running, 1, pod_name, namespace, kubeconfig_path)

      if down == -1:
        print(f"Unable to check running status of {pod_name}\n")
      elif pods and down == 0:
        print(f'All {pod_name} pods found up and running:')
        for sensor in pods:
          print(sensor)
          pod_names.append(sensor)
      elif pods and 0 < down < len(pods):
        print(f'Some {pod_name} pods were found not running. Running pods are:')
        for sensor in pods:
          print(sensor)
          pod_names.append(sensor)
      else:
        print(f'No {pod_name} pods were found running.')

    return pod_names


# # Create a logger object
# logger = logging.getLogger(__name__)
#
# # Set logging level
# logger.setLevel(logging.INFO)  # Can be DEBUG, INFO, WARNING, ERROR, CRITICAL
#
# # Create a file handler to log to a file
# file_handler = logging.FileHandler('app.log')
# file_handler.setLevel(logging.INFO)  # Set level for file handler
#
# # Create a console handler to log to the console
# console_handler = logging.StreamHandler()
# console_handler.setLevel(logging.DEBUG)  # Set level for console handler
#
# # Create a formatter for formatting log messages
# formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#
# # Add formatter to both handlers
#
# file_handler.setFormatter(formatter)
# console_handler.setFormatter(formatter)
#
# # Add handlers to logger
# logger.addHandler(file_handler)
# logger.addHandler(console_handler)
#
# x = ContainerOps(logger=logger)
# if sensors := x.pod_checker(pod_name='falcon-sensor', namespace='falcon-system', kubeconfig_path='~/.kube/config'):
#   print('Sensors:', sensors)

# def are_pod_and_containers_running(self, pod_name, namespace, kubeconfig_path) -> tuple[dict, int]:
#   try:
#     pods: dict = {}
#     counter = 0
#
#     config.load_kube_config(config_file=kubeconfig_path)
#     v1 = client.CoreV1Api()
#
#     # Get pods in the specified namespace
#     pod_list = v1.list_namespaced_pod(namespace)
#
#     for pod in pod_list.items:
#       if pod_name in pod.metadata.name:  # Check for pod name substring match
#         pods[pod.metadata.name] = {}
#         pod_status = v1.read_namespaced_pod_status(name=pod.metadata.name, namespace=namespace)
#
#         # Check if the pod phase is 'Running'
#         if pod_status.status.phase == 'Running':
#           pods[pod.metadata.name]['podStatus'] = 'Running'
#           # Check if all containers within the pod are running
#           for container_status in pod_status.status.container_statuses:
#             pods[pod.metadata.name]['containerName'] = container_status.name
#             pods[pod.metadata.name]['containerStatus'] = container_status.state.running
#         else:
#           pods[pod.metadata.name]['podStatus'] = 'Stopped'
#           counter += 1
#     return pods, counter
#   except ApiException as e:
#     raise  # Re-raise the exception for proper handling

# if x.check_namespace_exists(namespace_name='falcon-system', kubeconfig_path='~/.kube/config'):
#   print('Success\n')
# else:
#   print('Fail\n')
#
# pods = x.check_pod_exists(pod_name='falcon-sensor', namespace='falcon-system', kubeconfig_path='~/.kube/config')
# if pods:
#   for pod in pods:
#     print(pod)
# else:
#   print('No pods\n')
#
# if x.is_container_running(container_name='falcon-node-sensor', namespace='falcon-system',
#                           kubeconfig_path='~/.kube/config'):
#   print('Success\n')
# else:
#   print('Fail\n')

# def check_pod_exists(self, pod_name, namespace, kubeconfig_path=None):
#   try:
#     pods = []
#     config.load_kube_config(config_file=kubeconfig_path)
#     v1 = client.CoreV1Api()
#
#     # Get all pods in the namespace
#     pod_list = v1.list_namespaced_pod(namespace)
#
#     # Check if any pod has a container with the specified name
#     for pod in pod_list.items:
#       if pod_name in pod.metadata.name:
#         pods.append(pod.metadata.name)
#         # for container in pod.spec.containers:
#         #   if container_name in container.env_from[0].config_map_ref.name:
#         #     return True
#
#     return pods
#   except ApiException as e:
#     self.logger.error(e)
#     return False

# def is_container_running(self, container_name, namespace, kubeconfig_path=None):
#   """Checks if any container with a specified substring in its name is running in a given namespace.
#
#   Args:
#       container_name (str): The substring to search for in container names.
#       namespace (str): The namespace to search in.
#       kubeconfig_path (str, optional): Path to the kubeconfig file. Defaults to None.
#
#   Returns:
#       bool: True if at least one matching container is running, False otherwise.
#   """
#
#   try:
#     if kubeconfig_path:
#       config.load_kube_config(config_file=kubeconfig_path)
#     v1 = client.CoreV1Api()
#
#     pod_list = v1.list_namespaced_pod(namespace)
#
#     for pod in pod_list.items:
#       for container_status in pod.status.container_statuses:
#         if container_name in container_status.name and container_status.state.running is not None:
#           return True
#
#     return False
#   except ApiException as e:
#     self.logger.error(e)

# def find_containers_with_name_substring(self, container_name, namespace, kubeconfig_path=None):
#   """Finds and lists containers in a namespace that have a specified substring in their names.
#
#   Args:
#       container_name (str): The container name substring to search for in container names.
#       namespace (str): The namespace to search in.
#       kubeconfig_path (str, optional): Path to the kubeconfig file. Defaults to None.
#
#   Returns:
#       list: A list of container names that contain the specified substring.
#   """
#
#   try:
#     if kubeconfig_path:
#       config.load_kube_config(config_file=kubeconfig_path)
#     v1 = client.CoreV1Api()
#
#     matching_containers = []
#     pod_list = v1.list_namespaced_pod(namespace)
#
#     for pod in pod_list.items:
#       for container in pod.spec.containers:
#         # print(container.env_from[0].config_map_ref.name)
#         if container_name in container.name:
#           matching_containers.append(container.name)
#
#     return matching_containers
#   except ApiException as e:
#     self.logger.error(e)
#     return False
