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

delete_gcp_app = typer.Typer()


@delete_gcp_app.command(help='Delete GKE COS Cluster', rich_help_panel="GCP Kubernetes Clusters")
def gke_cos():
  gke_cos_log_filename = f'/var/logs/crowdstrike/gcp/gke/cos/gke-cos-{uk_time_str}.log'
  gke_cos_logger = CustomLogger('gke_cos', gke_cos_log_filename).logger

  print('Deleting CrowdStrike sensors and agents\n')

  # Delete a YAML file with kubectl
  kube = KubectlOps(logger=gke_cos_logger)
  kube.run_kubectl_command(
    'kubectl delete -f ./abstrakt/conf/crowdstrike/detections-container/detections-container.yaml'
  )
  # kube.run_kubectl_delete("./abstrakt/conf/crowdstrike/detections-container/detections-container.yaml")

  # Delete Helm releases
  helm = HelmOps(logger=gke_cos_logger)
  helm.run_helm_delete("falcon-kac", "falcon-kac")
  helm.run_helm_delete("kpagent", "falcon-kubernetes-protection")
  helm.run_helm_delete("falcon-helm", "falcon-system")
  helm.run_helm_delete("image-analyzer", "falcon-image-analyzer")

  printf('CrowdStrike sensors and agents deleted\n', logger=gke_cos_logger)

  printf('Deleting GKE COS Cluster\n', logger=gke_cos_logger)

  tf = ExecuteTerraform(logger=gke_cos_logger)

  if tf.execute_terraform_destroy(path='./abstrakt/terraformModules/gcp/gke/cos/'):
    printf('GKE COS cluster successfully deleted\n', logger=gke_cos_logger)
  else:
    printf('The program failed to delete GKE COS cluster. Exiting the program.\n',
           logger=gke_cos_logger)
    exit()


@delete_gcp_app.command(help='Delete GKE Autopilot Cluster', rich_help_panel="GCP Kubernetes Clusters")
def gke_autopilot():
  pass
