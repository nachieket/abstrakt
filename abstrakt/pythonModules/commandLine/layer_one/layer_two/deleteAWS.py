import typer
# import subprocess
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

delete_aws_app = typer.Typer()


# def run_kubectl_delete(yaml_file, logger):
#   try:
#     subprocess.run(["kubectl", "delete", "-f", yaml_file], check=True)
#     logger.info(f"Deleted {yaml_file} with kubectl")
#   except subprocess.CalledProcessError as e:
#     logger.info(f"Error deleting {yaml_file} with kubectl: {e}")
#
#
# def run_helm_delete(release_name, namespace, logger):
#   try:
#     subprocess.run(["helm", "delete", release_name, "-n", namespace], check=True)
#     logger.info(f"Deleted Helm release {release_name} in namespace {namespace}")
#   except subprocess.CalledProcessError as e:
#     logger.info(f"Error deleting Helm release {release_name} in namespace {namespace}: {e}")


@delete_aws_app.command(help='Delete EKS Managed Node Cluster', rich_help_panel="AWS Kubernetes Clusters")
def eks_managed_node():
  eks_managed_node_log_filename = f'/var/logs/crowdstrike/aws/eks/eks-managed-node-{uk_time_str}.log'
  managed_node_logger = CustomLogger('eks_managed_node', eks_managed_node_log_filename).logger

  printf('Deleting CrowdStrike sensors and agents\n', logger=managed_node_logger)

  # Delete a YAML file with kubectl
  kube = KubectlOps(logger=managed_node_logger)
  kube.run_kubectl_command(
    'kubectl delete -f ./abstrakt/conf/crowdstrike/detections-container/detections_container.yaml'
  )
  # kube.run_kubectl_delete("./abstrakt/conf/crowdstrike/detections-container/detections_container.yaml")

  # Delete Helm releases
  helm = HelmOps(logger=managed_node_logger)
  helm.run_helm_delete("falcon-kac", "falcon-kac")
  helm.run_helm_delete("kpagent", "falcon-kubernetes-protection")
  helm.run_helm_delete("falcon-helm", "falcon-system")

  printf('\nCrowdStrike sensors and agents deleted\n', logger=managed_node_logger)

  printf('Deleting EKS Managed Node Cluster\n', logger=managed_node_logger)

  tf = ExecuteTerraform(logger=managed_node_logger)

  if tf.execute_terraform_destroy('./abstrakt/terraformModules/aws/eks/eks_managed_node/'):
    printf('EKS Managed Node cluster successfully deleted\n', logger=managed_node_logger)
  else:
    printf('The program failed to delete EKS Managed Node cluster. Exiting the program.\n',
           logger=managed_node_logger)
    exit()


@delete_aws_app.command(help='Delete EKS Fargate Cluster', rich_help_panel="AWS Kubernetes Clusters")
def eks_fargate():
  eks_fargate_log_filename = f'/var/logs/crowdstrike/aws/eks/eks-fargate-{uk_time_str}.log'
  fargate_logger = CustomLogger('eks_fargate', eks_fargate_log_filename).logger

  printf('Deleting CrowdStrike sensors and agents\n', logger=fargate_logger)

  # Delete a YAML file with kubectl
  kube = KubectlOps(logger=fargate_logger)
  kube.run_kubectl_command(
    'kubectl delete -f ./abstrakt/conf/crowdstrike/detections-container/detections_container.yaml'
  )
  # kube.run_kubectl_delete("./abstrakt/conf/crowdstrike/detections-container/detections_container.yaml")

  # Delete Helm releases
  helm = HelmOps(logger=fargate_logger)
  helm.run_helm_delete("kpagent", "falcon-kubernetes-protection")
  helm.run_helm_delete("falcon-container", "falcon-system")

  printf('\nCrowdStrike sensors and agents deleted\n', logger=fargate_logger)

  printf('Deleting EKS Fargate Cluster\n', logger=fargate_logger)

  tf = ExecuteTerraform(logger=fargate_logger)

  if tf.execute_terraform_destroy('./abstrakt/terraformModules/aws/eks/eks_fargate/'):
    printf('EKS Fargate cluster successfully deleted\n', logger=fargate_logger)
  else:
    printf('The program failed to delete EKS Fargate cluster. Exiting the program.\n',
           logger=fargate_logger)
    exit()
