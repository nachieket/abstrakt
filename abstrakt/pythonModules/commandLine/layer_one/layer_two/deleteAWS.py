import os
import typer
import pytz

from datetime import datetime
from typing_extensions import Annotated

from abstrakt.pythonModules.terraformOps.executeTerraform import ExecuteTerraform
from abstrakt.pythonModules.kubernetesOps.helmOps import HelmOps
from abstrakt.pythonModules.customLogging.customLogging import CustomLogger
from abstrakt.pythonModules.vendors.cloudServiceProviders.aws.awsCli.awsOps import AWSOps
from abstrakt.pythonModules.kubernetesOps.updateKubeConfig import UpdateKubeConfig

uk_timezone = pytz.timezone('Europe/London')
uk_time = datetime.now(uk_timezone)
uk_time_str = uk_time.strftime('%d%m%Y')


def delete_string_file(logger):
  string_file = './abstrakt/conf/aws/eks/string.txt'

  if os.path.exists(string_file):
    try:
      os.remove(string_file)
      logger.info(f"The file '{string_file}' has been deleted successfully.")
    except Exception as e:
      logger.error(f"Error occurred while trying to delete the file: {e}")


delete_aws_app = typer.Typer()


@delete_aws_app.command(help='Delete EKS Managed Node Cluster', rich_help_panel="AWS Kubernetes Clusters")
def eks_managed_node(
  cluster: Annotated[str, typer.Option('--cluster', help='Cluster Name', rich_help_panel='AWS Options',
                                       show_default=False)] = None,
  region: Annotated[str, typer.Option('--region', help='Cluster Region or Zone', rich_help_panel='AWS Options',
                                      show_default=False)] = None,
):
  # TODO: Include cluster name and region as runtime parameters and run Kubeconfig update
  eks_managed_node_log_filename = f'/var/log/crowdstrike/aws/eks-managed-node-{uk_time_str}.log'
  managed_node_logger = CustomLogger('eks-managed-node', eks_managed_node_log_filename).logger

  # Check Cloud Service Provider Login
  cli = AWSOps()

  if not cli.check_aws_login():
    print('AWS credentials profile validation failed. No valid default or saml profile found. '
          'Existing the Program.\n')
    exit()

  try:
    kube_config = UpdateKubeConfig(managed_node_logger)
    if not kube_config.update_kubeconfig(cloud='aws', region=region, cluster_name=cluster):
      print('Error updating kubeconfig. Exiting the program.\n')
      exit()
  except Exception as e:
    managed_node_logger.error(e)
    print('Error updating kubeconfig. Exiting the program.\n')
    exit()

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

  print('\nDeleting EKS Managed Node Cluster...')

  tf = ExecuteTerraform(logger=managed_node_logger)

  if tf.execute_terraform_destroy('./abstrakt/terraformModules/aws/eks/eks-managed-node/'):
    print('EKS Managed Node cluster successfully deleted\n')
    delete_string_file(logger=managed_node_logger)
  else:
    print('The program failed to delete EKS Managed Node cluster. Exiting the program.\n')
    exit()


@delete_aws_app.command(help='Delete EKS Fargate Cluster', rich_help_panel="AWS Kubernetes Clusters")
def eks_fargate(
  cluster: Annotated[str, typer.Option('--cluster', help='Cluster Name', rich_help_panel='AWS Options',
                                       show_default=False)] = None,
  region: Annotated[str, typer.Option('--region', help='Cluster Region or Zone', rich_help_panel='AWS Options',
                                      show_default=False)] = None,
):
  eks_fargate_log_filename = f'/var/log/crowdstrike/aws/eks-fargate-{uk_time_str}.log'
  eks_fargate_logger = CustomLogger('eks_fargate', eks_fargate_log_filename).logger

  # Check Cloud Service Provider Login
  cli = AWSOps()

  if not cli.check_aws_login():
    print('AWS credentials profile validation failed. No valid default or saml profile found. '
          'Existing the Program.\n')
    exit()

  try:
    kube_config = UpdateKubeConfig(eks_fargate_logger)
    if not kube_config.update_kubeconfig(cloud='aws', region=region, cluster_name=cluster):
      print('Error updating kubeconfig. Exiting the program.\n')
      exit()
  except Exception as e:
    eks_fargate_logger.error(e)
    print('Error updating kubeconfig. Exiting the program.\n')
    exit()

  # Delete Helm releases
  helm = HelmOps(logger=eks_fargate_logger)

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

  print('\nDeleting EKS Fargate Cluster...')

  tf = ExecuteTerraform(logger=eks_fargate_logger)

  if tf.execute_terraform_destroy('./abstrakt/terraformModules/aws/eks/eks-fargate/'):
    print('EKS Fargate cluster successfully deleted\n')
    delete_string_file(logger=eks_fargate_logger)
  else:
    print('The program failed to delete EKS Fargate cluster. Exiting the program.\n')
    exit()


@delete_aws_app.command(help='Delete ECS Fargate Cluster', rich_help_panel="AWS Kubernetes Clusters")
def ecs_fargate():
  eks_fargate_log_filename = f'/var/log/crowdstrike/aws/ecs-fargate-{uk_time_str}.log'
  ecs_fargate_logger = CustomLogger('ecs_fargate', eks_fargate_log_filename).logger

  # Check Cloud Service Provider Login
  cli = AWSOps()

  if not cli.check_aws_login():
    print('AWS credentials profile validation failed. No valid default or saml profile found. '
          'Existing the Program.\n')
    exit()

  print('\nDeleting ECS Fargate Cluster...')

  tf = ExecuteTerraform(logger=ecs_fargate_logger)

  if tf.execute_terraform_destroy('./abstrakt/terraformModules/aws/ecs/fargate/'):
    print('ECS Fargate cluster successfully deleted\n')
    delete_string_file(logger=ecs_fargate_logger)
  else:
    print('The program failed to delete ECS Fargate cluster. Exiting the program.\n')
    exit()


@delete_aws_app.command(help='Delete ECS EC2 Cluster', rich_help_panel="AWS Kubernetes Clusters")
def ecs_ec2():
  eks_fargate_log_filename = f'/var/log/crowdstrike/aws/ecs-ec2-{uk_time_str}.log'
  ecs_ec2_logger = CustomLogger('ecs_ec2', eks_fargate_log_filename).logger

  # Check Cloud Service Provider Login
  cli = AWSOps()

  if not cli.check_aws_login():
    print('AWS credentials profile validation failed. No valid default or saml profile found. '
          'Existing the Program.\n')
    exit()

  print('\nDeleting ECS EC2 Cluster...')

  tf = ExecuteTerraform(logger=ecs_ec2_logger)

  if tf.execute_terraform_destroy('./abstrakt/terraformModules/aws/ecs/ec2/'):
    print('ECS EC2 cluster successfully deleted\n')
    delete_string_file(logger=ecs_ec2_logger)
  else:
    print('The program failed to delete ECS Fargate cluster. Exiting the program.\n')
    exit()
