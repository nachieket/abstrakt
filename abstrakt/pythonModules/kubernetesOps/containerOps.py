import subprocess

from kubernetes import client, config
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

  def check_namespace_exists(self, namespace, kubeconfig_path: str = '~/.kube/config'):
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

  def are_pods_and_containers_running(self, pod_name: str, namespace: str,
                                      kubeconfig_path: str = '~/.kube/config') -> tuple[dict, int]:
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
              elif pod_status.status.phase == 'ContainerCreating':
                continue
              elif pod_status.status.phase == 'Pending':
                if (pod_status.status and pod_status.status.init_container_statuses and len(
                  pod_status.status.init_container_statuses) > 0 and
                  pod_status.status.init_container_statuses[0].state and
                  pod_status.status.init_container_statuses[0].state.waiting and
                  pod_status.status.init_container_statuses[0].state.waiting.reason):

                  if pod_status.status.init_container_statuses[0].state.waiting.reason == 'ErrImagePull':
                    pods[pod.metadata.name] = {'podStatus': 'ErrImagePull'}
                    down += 1
                    break
                  elif pod_status.status.init_container_statuses[0].state.waiting.reason == 'CrashLoopBackOff':
                    pods[pod.metadata.name] = {'podStatus': 'CrashLoopBackOff'}
                    down += 1
                    break
                  elif pod_status.status.init_container_statuses[0].state.waiting.reason == 'ImagePullBackOff':
                    pods[pod.metadata.name] = {'podStatus': 'ImagePullBackOff'}
                    down += 1
                    break
                  elif pod_status.status.init_container_statuses[0].state.waiting.reason == 'Failed':
                    pods[pod.metadata.name] = {'podStatus': 'Failed'}
                    down += 1
                    break
                  else:
                    continue
                elif (pod_status.status and pod_status.status.container_statuses and len(
                      pod_status.status.container_statuses) > 0 and
                      pod_status.status.container_statuses[0].state and
                      pod_status.status.container_statuses[0].state.waiting and
                      pod_status.status.container_statuses[0].state.waiting.reason):

                  if pod_status.status.container_statuses[0].state.waiting.reason == 'ErrImagePull':
                    pods[pod.metadata.name] = {'podStatus': 'ErrImagePull'}
                    down += 1
                    break
                  elif pod_status.status.container_statuses[0].state.waiting.reason == 'CrashLoopBackOff':
                    pods[pod.metadata.name] = {'podStatus': 'CrashLoopBackOff'}
                    down += 1
                    break
                  elif pod_status.status.container_statuses[0].state.waiting.reason == 'ImagePullBackOff':
                    pods[pod.metadata.name] = {'podStatus': 'ImagePullBackOff'}
                    down += 1
                    break
                  elif pod_status.status.container_statuses[0].state.waiting.reason == 'Failed':
                    pods[pod.metadata.name] = {'podStatus': 'Failed'}
                    down += 1
                    break
                  else:
                    continue
                else:
                  continue
              elif pod_status.status.phase == 'Failed':
                pods[pod.metadata.name] = {'podStatus': 'Failed'}
                down += 1
                break
              elif pod_status.status.phase == 'Unknown':
                pods[pod.metadata.name] = {'podStatus': 'Unknown'}
                down += 1
                break
              elif pod_status.status.phase == 'CrashLoopBackOff':
                pods[pod.metadata.name] = {'podStatus': 'CrashLoopBackOff'}
                down += 1
                break
              elif pod_status.status.phase == 'ImagePullBackOff':
                pods[pod.metadata.name] = {'podStatus': 'ImagePullBackOff'}
                down += 1
                break
              elif pod_status.status.phase == 'ErrImagePull':
                pods[pod.metadata.name] = {'podStatus': 'ErrImagePull'}
                down += 1
                break
              else:
                pods[pod.metadata.name] = {'podStatus': 'Undefined'}
                down += 1
                break

        return pods, down
      except Exception as e:
        self.logger.error(f"Exception when calling CoreV1Api: {e}")
        return {}, -1  # Return an error code
    else:
      self.logger.error(f'Namespace {namespace} does not exist\n')
      return {}, -1  # Return an error code

  def pod_checker(self, pod_name: str, namespace: str, kubeconfig_path: str = '~/.kube/config',
                  timeout: int = 300) -> list:
    try:
      print(f"Checking {pod_name} status...")
      sleep(5)
      pod_names: list = []

      pods: dict
      down: int

      with MultiThreading() as mt:
        pods, down = mt.run_with_progress_indicator(
          self.are_pods_and_containers_running, 1, timeout, pod_name, namespace, kubeconfig_path)

      if down == -1:
        print(f"Unable to check running status of {pod_name}\n")
      elif pods and down == 0:
        print(f'All {pod_name} pods found up and running:')
        for sensor in pods:
          print(sensor)
          pod_names.append(sensor)
        return pod_names
      elif pods and 0 < down < len(pods):
        print(f'Some {pod_name} pods were found not running. Running pods are:')
        for sensor in pods:
          print(sensor)
          pod_names.append(sensor)
        return pod_names
      else:
        print(f'No {pod_name} pods were found running.')
        return pod_names
    except Exception as e:
      self.logger.error(f'Error: {e}')
      return []

  def get_service_ip_address(self, service_name, namespace, kubeconfig_path: str = '~/.kube/config'):
    try:
      config.load_kube_config(config_file=kubeconfig_path)
      v1 = client.CoreV1Api()
    except config.config_exception.ConfigException:
      print("Error: Could not load configuration from ~/.kube/config.")
      return False

    try:
      service = v1.read_namespaced_service(service_name, namespace=namespace)

      # Extract IP address from service object (considering different service types)
      if service.spec.type == "ClusterIP":
        # ClusterIP service type
        ip_address = service.spec.cluster_ip

        if service.spec.ports:
          port = service.spec.ports[0].port
          self.logger.info(f"Service {service_name}: IP Address - {ip_address}, Potential Port - {port}")
        else:
          self.logger.error(f"Service {service_name}: IP Address - {ip_address}, Port information not available in "
                            f"service definition.")
          port = 0
      elif service.spec.type == "LoadBalancer":
        # LoadBalancer service type - might have multiple ingress points
        if service.status.load_balancer is None:
          raise Exception("LoadBalancer service has no ingress information yet")
        ingress = service.status.load_balancer.ingress[0]  # Assuming single ingress for simplicity
        ip_address = ingress.ip  # Use IP address if available

        if service.spec.ports:
          port = service.spec.ports[0].port  # Assuming single port for simplicity
          self.logger.info(f"Service {service_name}: IP Address - {ip_address}, Potential Port - {port}")
        else:
          self.logger.error(f"Service {service_name}: IP Address - {ip_address}, Port information not available in "
                            f"service definition. Checking ingress rules...")
          port = 0
      else:
        raise Exception(f"Service type '{service.spec.type}' not currently supported")

      return ip_address, port
    except client.ApiException as e:
      print(f"Error retrieving service information: {e}")
      return False

  def list_pods_in_namespace(self, namespace) -> list | None:
    # Load Kubernetes configuration from the default location (~/.kube/config)
    config.load_kube_config()

    # Create a client for the CoreV1 API
    v1 = client.CoreV1Api()

    try:
      # List all the pods in the specified namespace
      pod_list = v1.list_namespaced_pod(namespace)

      # Extract the names of the pods and return them as a list
      pod_names = [pod.metadata.name for pod in pod_list.items]
      return pod_names

    except Exception as e:
      self.logger.error(f"An error occurred: {e}")
      return None
