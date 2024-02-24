import subprocess

import kubernetes.client
from kubernetes import config


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
      v1 = kubernetes.client.CoreV1Api()

      # Get a list of all namespaces
      namespaces = v1.list_namespace()

      # Extract the namespace names
      namespace_names = [namespace.metadata.name for namespace in namespaces.items]

      return namespace_names
    except Exception as e:
      self.logger.error(f'{e}')
      return []

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
