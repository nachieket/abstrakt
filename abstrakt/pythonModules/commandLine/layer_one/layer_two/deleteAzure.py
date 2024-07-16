import typer
import pytz

from datetime import datetime
from typing_extensions import Annotated

from abstrakt.pythonModules.terraformOps.executeTerraform import ExecuteTerraform
from abstrakt.pythonModules.kubernetesOps.helmOps import HelmOps
from abstrakt.pythonModules.customLogging.customLogging import CustomLogger
from abstrakt.pythonModules.vendors.cloudServiceProviders.azure.azOps.azOps import AZOps
from abstrakt.pythonModules.kubernetesOps.updateKubeConfig import UpdateKubeConfig

uk_timezone = pytz.timezone('Europe/London')
uk_time = datetime.now(uk_timezone)
uk_time_str = uk_time.strftime('%d%m%Y')

delete_azure_app = typer.Typer()


@delete_azure_app.command(help='Delete AKS Cluster', rich_help_panel="Azure Kubernetes Clusters")
def aks(
  cluster_name: Annotated[str, typer.Option('--cluster-name',
                                            help='Cluster Name',
                                            rich_help_panel='Azure Options',
                                            show_default=False)] = None,
  resource_group_name: Annotated[str, typer.Option('--resource-group-name',
                                                   help='Azure Resource Group Name',
                                                   rich_help_panel='Azure Options',
                                                   show_default=False)] = None,
):
  aks_log_filename = f'/var/log/crowdstrike/azure/aks-{uk_time_str}.log'
  aks_logger = CustomLogger('aks', aks_log_filename).logger

  az = AZOps(logger=aks_logger)

  if not az.check_azure_login():
    print('You are not logged in to Azure. Exiting program.')
    print("Try logging in to GCP using 'az login' and try to run the program again\n")
    exit()

  try:
    kube_config = UpdateKubeConfig(aks_logger)
    if not kube_config.update_kubeconfig(cloud='azure', resource_group=resource_group_name, cluster_name=cluster_name):
      print('Error updating kubeconfig. Exiting the program.\n')
      exit()
  except Exception as e:
    aks_logger.error(e)
    print('Error updating kubeconfig. Exiting the program.\n')
    exit()

  # Delete Helm releases
  helm = HelmOps(logger=aks_logger)

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

  print('\nDeleting AKS Cluster...')

  tf = ExecuteTerraform(logger=aks_logger)

  if tf.execute_terraform_destroy(path='./abstrakt/terraformModules/azure/aks/'):
    print('AKS cluster successfully deleted\n')
  else:
    print('The program failed to delete AKS cluster. Exiting the program.\n')
    exit()
