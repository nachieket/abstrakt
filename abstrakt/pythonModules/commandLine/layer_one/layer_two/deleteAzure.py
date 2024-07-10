import typer
import pytz

from datetime import datetime

from abstrakt.pythonModules.terraformOps.executeTerraform import ExecuteTerraform
from abstrakt.pythonModules.kubernetesOps.helmOps import HelmOps
from abstrakt.pythonModules.customLogging.customLogging import CustomLogger

uk_timezone = pytz.timezone('Europe/London')
uk_time = datetime.now(uk_timezone)
uk_time_str = uk_time.strftime('%d%m%Y')

delete_azure_app = typer.Typer()


@delete_azure_app.command(help='Delete AKS Cluster', rich_help_panel="Azure Kubernetes Clusters")
def aks():
  aks_log_filename = f'/var/log/crowdstrike/azure/aks-{uk_time_str}.log'
  aks_logger = CustomLogger('aks', aks_log_filename).logger

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

  print('Deleting AKS Cluster...')

  tf = ExecuteTerraform(logger=aks_logger)

  if tf.execute_terraform_destroy(path='./abstrakt/terraformModules/azure/aks/'):
    print('AKS cluster successfully deleted\n')
  else:
    print('The program failed to delete AKS cluster. Exiting the program.\n')
    exit()
