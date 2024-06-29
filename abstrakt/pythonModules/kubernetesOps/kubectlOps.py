import subprocess

from kubernetes import client, config
from kubernetes.client.rest import ApiException


class KubectlOps:
  def __init__(self, logger):
    self.logger = logger

  def run_kubectl_command(self, command):
    try:
      # Use subprocess to run the Kubernetes command
      result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)

      # Check if the command was successful (return code 0)
      if result.returncode == 0:
        self.logger.info(f'{result.stdout}')
        return True
      else:
        self.logger.info(f'{result.stderr}')
        return False
    except Exception as e:
      self.logger.error(f'{e}')
      return False

  def get_all_namespaces(self, kubeconfig_path) -> list:
    """Retrieves a list of all Kubernetes namespaces."""

    try:
      # Load the configuration from your kubeconfig file
      config.load_kube_config(kubeconfig_path)

      # Create a Kubernetes client object
      v1 = client.CoreV1Api()

      # Get a list of all namespaces
      namespaces = v1.list_namespace()

      # Extract the namespace names
      namespace_names = [namespace.metadata.name for namespace in namespaces.items]

      return namespace_names
    except Exception as e:
      self.logger.error(f'{e}')
      return []

  def namespace_exists(self, namespace_name):
    try:
      # Load the kubeconfig file
      config.load_kube_config()

      # Create a client for the CoreV1Api
      v1 = client.CoreV1Api()

      # Try to get the namespace
      v1.read_namespace(name=namespace_name)
      return True
    except ApiException as e:
      if e.status == 404:
        self.logger.error(f"Namespace '{namespace_name}' does not exist.")
        return False
      else:
        self.logger.error(f"An error occurred: {e}")
        return False

  def find_pods_with_status(self, pod_string, namespace):
    try:
      status = True

      # Load the kubeconfig file
      config.load_kube_config()

      # Create a client for the CoreV1Api
      v1 = client.CoreV1Api()

      # List all pods in the specified namespace
      pods = v1.list_namespaced_pod(namespace)

      captured_pods = {'running': [], 'initiating': [], 'failed': [], 'succeeded': [], 'terminated': [], 'evicted': []}

      for pod in pods.items:
        if pod_string in pod.metadata.name:
          if pod.status.phase == 'Running':
            captured_pods['running'].append(pod.metadata.name)
          elif pod.status.phase == ('Pending' or 'ContainerCreating'):
            captured_pods['initiating'].append(pod.metadata.name)
            status = False
          elif pod.status.phase == ('Failed' or 'CrashLoopBackOff' or 'ImagePullBackOff' or 'Unknown'):
            captured_pods['failed'].append(pod.metadata.name)
            status = False
          elif pod.status.phase == 'Succeeded':
            captured_pods['succeeded'].append(pod.metadata.name)
            status = False
          elif pod.status.phase == 'ContainerTerminated':
            captured_pods['terminated'].append(pod.metadata.name)
            status = False
          elif pod.status.phase == 'Evicted':
            captured_pods['evicted'].append(pod.metadata.name)
            status = False

      self.logger.info(captured_pods)

      # Return the count of running pods
      return captured_pods, status

    except client.exceptions.ApiException as e:
      self.logger.error(f"An error occurred: {e}")
      return None, False

# def run_kubectl_delete(self, yaml_file):
#   try:
#     process = subprocess.run(["kubectl", "delete", "-f", yaml_file], stdout=subprocess.PIPE,
#                              stderr=subprocess.PIPE, check=True)
#
#     if process.stdout:
#       self.logger.info(process.stdout)
#     if process.stderr:
#       self.logger.error(process.stderr)
#
#     self.logger.info(f"Deleted {yaml_file} with kubectl")
#   except subprocess.CalledProcessError as e:
#     self.logger.error(f"Error deleting {yaml_file} with kubectl: {e}")
#
# def run_kubectl_create_namespace(self, namespace):
#   try:
#     process = subprocess.run(["kubectl", "create", "namespace", namespace], stdout=subprocess.PIPE,
#                              stderr=subprocess.PIPE, check=True)
#
#     if process.stdout:
#       self.logger.info(process.stdout)
#     if process.stderr:
#       self.logger.info(process.stderr)
#
#     self.logger.info(f"Namespace {namespace} created successfully.")
#   except subprocess.CalledProcessError as e:
#     self.logger.error(f"Namespace {namespace} creation failed.")
#     self.logger.error(f'{e}')
