import typer
import pytz

from datetime import datetime

from abstrakt.pythonModules.terraformOps.executeTerraform import ExecuteTerraform
from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.kubernetesOps.helmOps import HelmOps
from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf
from abstrakt.pythonModules.customLogging.customLogging import CustomLogger

uk_timezone = pytz.timezone('Europe/London')
uk_time = datetime.now(uk_timezone)
uk_time_str = uk_time.strftime('%d%m%Y')

delete_azure_app = typer.Typer()


# def run_kubectl_delete(yaml_file, logger):
#   try:
#     process = subprocess.run(["kubectl", "delete", "-f", yaml_file], stdout=subprocess.PIPE,
#                              stderr=subprocess.PIPE, check=True)
#
#     if process.stdout:
#       logger.info(process.stdout)
#     if process.stderr:
#       logger.info(process.stderr)
#
#     logger.info(f"Deleted {yaml_file} with kubectl")
#   except subprocess.CalledProcessError as e:
#     logger.info(f"Error deleting {yaml_file} with kubectl: {e}")
#
#
# def run_helm_delete(release_name, namespace, logger):
#   try:
#     process = subprocess.run(["helm", "delete", release_name, "-n", namespace], stdout=subprocess.PIPE,
#                              stderr=subprocess.PIPE, check=True)
#
#     if process.stdout:
#       logger.info(process.stdout)
#     if process.stderr:
#       logger.info(process.stderr)
#
#     logger.info(f"Deleted Helm release {release_name} in namespace {namespace}")
#   except subprocess.CalledProcessError as e:
#     logger.info(f"Error deleting Helm release {release_name} in namespace {namespace}: {e}")


@delete_azure_app.command(help='Delete AKS Cluster', rich_help_panel="Azure Kubernetes Clusters")
def aks():
  aks_log_filename = f'/var/log/crowdstrike/azure/aks-{uk_time_str}.log'
  aks_logger = CustomLogger('aks', aks_log_filename).logger

  printf('Deleting CrowdStrike sensors and agents\n', logger=aks_logger)

  # Delete a YAML file with kubectl
  kube = KubectlOps(logger=aks_logger)
  kube.run_kubectl_command(
    'kubectl delete -f ./abstrakt/conf/crowdstrike/detections-container/detections-container.yaml'
  )
  # kube.run_kubectl_delete("./abstrakt/conf/crowdstrike/detections-container/detections-container.yaml")

  # Delete Helm releases
  helm = HelmOps(logger=aks_logger)
  helm.run_helm_delete("falcon-kac", "falcon-kac")
  helm.run_helm_delete("kpagent", "falcon-kubernetes-protection")
  helm.run_helm_delete("falcon-helm", "falcon-system")
  helm.run_helm_delete("image-analyzer", "falcon-image-analyzer")

  printf('CrowdStrike sensors and agents deleted\n', logger=aks_logger)

  printf('Deleting AKS Cluster\n', logger=aks_logger)

  tf = ExecuteTerraform(logger=aks_logger)

  if tf.execute_terraform_destroy(path='./abstrakt/terraformModules/azure/aks/'):
    printf('AKS cluster successfully deleted\n', logger=aks_logger)
  else:
    printf('The program failed to delete AKS cluster. Exiting the program.\n',
           logger=aks_logger)
    exit()
