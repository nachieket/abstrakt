import typer
import pytz

from datetime import datetime

from abstrakt.pythonModules.terraformOps.executeTerraform import ExecuteTerraform
from abstrakt.pythonModules.kubernetesOps.helmOps import HelmOps
from abstrakt.pythonModules.customLogging.customLogging import CustomLogger

uk_timezone = pytz.timezone('Europe/London')
uk_time = datetime.now(uk_timezone)
uk_time_str = uk_time.strftime('%d%m%Y')

delete_gcp_app = typer.Typer()


@delete_gcp_app.command(help='Delete GKE Standard Cluster', rich_help_panel="GCP Kubernetes Clusters")
def gke_standard():
  gke_standard_log_filename = f'/var/log/crowdstrike/gcp/gke-standard-{uk_time_str}.log'
  gke_standard_logger = CustomLogger('gke-standard', gke_standard_log_filename).logger

  # Delete Helm releases
  helm = HelmOps(logger=gke_standard_logger)

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

  print('Deleting GKE Standard Cluster...')

  tf = ExecuteTerraform(logger=gke_standard_logger)

  if tf.execute_terraform_destroy(path='./abstrakt/terraformModules/gcp/gke/standard/'):
    print('GKE Standard cluster successfully deleted\n')
  else:
    print('The program failed to delete GKE Standard cluster. Exiting the program.\n')
    exit()


@delete_gcp_app.command(help='Delete GKE Autopilot Cluster', rich_help_panel="GCP Kubernetes Clusters")
def gke_autopilot():
  gke_autopilot_log_filename = f'/var/log/crowdstrike/gcp/gke-autopilot-{uk_time_str}.log'
  gke_autopilot_logger = CustomLogger('gke-autopilot', gke_autopilot_log_filename).logger

  # Delete Helm releases
  helm = HelmOps(logger=gke_autopilot_logger)

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

  print('Deleting GKE Autopilot Cluster...')

  tf = ExecuteTerraform(logger=gke_autopilot_logger)

  if tf.execute_terraform_destroy(path='./abstrakt/terraformModules/gcp/gke/autopilot/'):
    print('GKE Autopilot cluster successfully deleted\n')
  else:
    print('The program failed to delete GKE Autopilot cluster. Exiting the program.\n')
    exit()
