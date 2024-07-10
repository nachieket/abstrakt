import typer
import pytz

from datetime import datetime

from abstrakt.pythonModules.terraformOps.executeTerraform import ExecuteTerraform
from abstrakt.pythonModules.kubernetesOps.helmOps import HelmOps
from abstrakt.pythonModules.customLogging.customLogging import CustomLogger

uk_timezone = pytz.timezone('Europe/London')
uk_time = datetime.now(uk_timezone)
uk_time_str = uk_time.strftime('%d%m%Y')

delete_aws_app = typer.Typer()


@delete_aws_app.command(help='Delete EKS Managed Node Cluster', rich_help_panel="AWS Kubernetes Clusters")
def eks_managed_node():
  eks_managed_node_log_filename = f'/var/log/crowdstrike/aws/eks-managed-node-{uk_time_str}.log'
  managed_node_logger = CustomLogger('eks-managed-node', eks_managed_node_log_filename).logger

  # Delete Helm releases
  helm = HelmOps(logger=managed_node_logger)

  if helm.is_helm_chart_deployed(release_name='daemonset-falcon-sensor', namespace='falcon-system'):
    print('Deleting Falcon Sensor...')
    helm.run_helm_delete("daemonset-falcon-sensor", "falcon-system")
  elif helm.is_helm_chart_deployed(release_name='falcon-helm', namespace='falcon-system'):
    print('Deleting Falcon Sensor...')
    helm.run_helm_delete("falcon-helm", "falcon-system")

  if helm.is_helm_chart_deployed(release_name='kpagent', namespace='falcon-kubernetes-protection'):
    print('Deleting Kubernetes Protections Agent...')
    helm.run_helm_delete("kpagent", "falcon-kubernetes-protection")

  if helm.is_helm_chart_deployed(release_name='falcon-kac', namespace='falcon-kac'):
    print('Deleting Kubernetes Admission Controller...')
    helm.run_helm_delete("falcon-kac", "falcon-kac")

  if helm.is_helm_chart_deployed(release_name='image-analyzer', namespace='falcon-image-analyzer'):
    print('Deleting Image Assessment at Runtime...')
    helm.run_helm_delete("image-analyzer", "falcon-image-analyzer")

  print('Deleting EKS Managed Node Cluster...')

  tf = ExecuteTerraform(logger=managed_node_logger)

  if tf.execute_terraform_destroy('./abstrakt/terraformModules/aws/eks/eks-managed-node/'):
    print('EKS Managed Node cluster successfully deleted\n')
  else:
    print('The program failed to delete EKS Managed Node cluster. Exiting the program.\n')
    exit()


@delete_aws_app.command(help='Delete EKS Fargate Cluster', rich_help_panel="AWS Kubernetes Clusters")
def eks_fargate():
  eks_fargate_log_filename = f'/var/log/crowdstrike/aws/eks-fargate-{uk_time_str}.log'
  fargate_logger = CustomLogger('eks_fargate', eks_fargate_log_filename).logger

  # Delete Helm releases
  helm = HelmOps(logger=fargate_logger)

  if helm.is_helm_chart_deployed(release_name='sidecar-falcon-sensor', namespace='falcon-system'):
    print('Deleting Falcon Sensor...')
    helm.run_helm_delete("sidecar-falcon-sensor", "falcon-system")
  elif helm.is_helm_chart_deployed(release_name='falcon-container', namespace='falcon-system'):
    print('Deleting Falcon Sensor...')
    helm.run_helm_delete("falcon-container", "falcon-system")

  if helm.is_helm_chart_deployed(release_name='kpagent', namespace='falcon-kubernetes-protection'):
    print('Deleting Kubernetes Protections Agent...')
    helm.run_helm_delete("kpagent", "falcon-kubernetes-protection")

  if helm.is_helm_chart_deployed(release_name='falcon-kac', namespace='falcon-kac'):
    print('Deleting Kubernetes Admission Controller...')
    helm.run_helm_delete("falcon-kac", "falcon-kac")

  if helm.is_helm_chart_deployed(release_name='image-analyzer', namespace='falcon-image-analyzer'):
    print('Deleting Image Assessment at Runtime...')
    helm.run_helm_delete("image-analyzer", "falcon-image-analyzer")

  print('Deleting EKS Fargate Cluster...')

  tf = ExecuteTerraform(logger=fargate_logger)

  if tf.execute_terraform_destroy('./abstrakt/terraformModules/aws/eks/eks-fargate/'):
    print('EKS Fargate cluster successfully deleted\n')
  else:
    print('The program failed to delete EKS Fargate cluster. Exiting the program.\n')
    exit()
