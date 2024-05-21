import typer
import pytz

from datetime import datetime
from typing_extensions import Annotated

from abstrakt.pythonModules.opsManager.CrowdStrikeSensorOperationsManager import CrowdStrikeSensorOperationsManager
from abstrakt.pythonModules.customLogging.customLogging import CustomLogger

uk_timezone = pytz.timezone('Europe/London')
uk_time = datetime.now(uk_timezone)
uk_time_str = uk_time.strftime('%d%m%Y')

runtime_sensor_app = typer.Typer()

help_message = """
Install CrowdStrike Sensors\n
_                       _\n\n\n

Example Usages:\n\n
abstrakt install --falcon-sensor --kernel-mode --kpa --kac --iar --detections-container --vulnerable-apps 
--falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n
abstrakt install --falcon-sensor --kernel-mode --proxy-server 10.10.10.11 --proxy-port 8080 --falcon-sensor-tags 
tag1,tag2 --kpa --kac --iar --detections-container --vulnerable-apps --falcon-client-id 3af74117 
--falcon-client-secret vlTpn372s\n\n

Examples with Monitored/Excluded Namespaces for EKS Fargate:\n
abstrakt install --falcon-sensor --monitor-namespaces ns1,ns2,ns4,ns5 --kpa --kac --iar --detections-container 
--vulnerable-apps --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n
abstrakt install --falcon-sensor --monitor-namespaces all --exclude-namespaces ns1,ns2 --proxy-server 10.10.10.11 
--proxy-port 8080 --falcon-sensor-tags tag1,tag2 --kpa --kac --iar --detections-container --vulnerable-apps 
--falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n\n

Examples with Falcon Image Tag:\n
abstrakt install --falcon-sensor --kernel-mode --falcon-image-tag 7.10.0-16303-1.falcon-linux.x86_64.Release.US-1
--kpa --kac --iar --detections-container --vulnerable-apps --falcon-client-id 3af74117 --falcon-client-secret 
vlTpn372s\n
abstrakt install --falcon-sensor --kernel-mode --falcon-image-tag 7.10.0-16303-1.falcon-linux.x86_64.Release.US-1 
--proxy-server 10.10.10.11 --proxy-port 8080 --falcon-sensor-tags tag1,tag2 --kpa --kac --iar --detections-container 
--vulnerable-apps --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n\n

###########\n
### AWS ###\n
###########\n\n

AWS Example - All CrowdStrike Sensors with Detections Container and Vulnerable Apps:\n
abstrakt install crowdstrike --falcon-sensor --kernel-mode --kpa --kac --iar --detections-container 
--vulnerable-apps --cloud-provider aws --cluster-type eks-managed-node --cluster-name random_eks_cluster 
--cloud-region eu-west-2 --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n\n

AWS Example - Falcon Sensor Installation:\n
abstrakt install crowdstrike --falcon-sensor --kernel-mode --cloud-provider aws --cluster-type eks-managed-node 
--cluster-name random_eks_cluster --cloud-region eu-west-2 --falcon-client-id 3af74117 --falcon-client-secret 
vlTpn372s\n\n

AWS Example - Kubernetes Protection Agent Installation:\n
abstrakt install crowdstrike --kpa --cloud-provider aws --cluster-type eks-managed-node --cluster-name 
random_eks_cluster --cloud-region eu-west-2 --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n\n

AWS Example - Kubernetes Admission Controller Installation:\n
abstrakt install crowdstrike --kac --cloud-provider aws --cluster-type eks-managed-node --cluster-name 
random_eks_cluster --cloud-region eu-west-2 --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n\n

AWS Example - Image Assessment at Runtime Installation:\n
abstrakt install crowdstrike --iar --cloud-provider aws --cluster-type eks-managed-node --cluster-name 
random_eks_cluster --cloud-region eu-west-2 --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n\n

AWS Example - Detections Container Installation:\n
abstrakt install crowdstrike --detections-container --cloud-provider aws --cluster-type eks-managed-node 
--cluster-name random_eks_cluster --cloud-region eu-west-2\n\n

AWS Example - Vulnerable Apps Installation:\n
abstrakt install crowdstrike --vulnerable-apps ---cloud-provider aws --cluster-type eks-managed-node --cluster-name 
random_eks_cluster --cloud-region eu-west-2\n\n

#############\n
### Azure ###\n
#############\n\n

Azure Example - All CrowdStrike Sensors with Detections Container and Vulnerable Apps:\n
abstrakt install crowdstrike --falcon-sensor --kernel-mode --kpa --kac --iar --detections-container 
--vulnerable-apps --cloud-provider azure --cluster-type aks --cluster-name random_aks_cluster 
--azure-resource-group-name random_aks_rg --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n\n

Azure Example - Falcon Sensor Installation:\n
abstrakt install crowdstrike --falcon-sensor --kernel-mode --cloud-provider azure --cluster-type aks --cluster-name 
random_aks_cluster --azure-resource-group-name random_aks_rg --falcon-client-id 3af74117 --falcon-client-secret 
vlTpn372s\n\n

Azure Example - Kubernetes Protection Agent Installation:\n
abstrakt install crowdstrike --kpa --cloud-provider azure --cluster-type aks --cluster-name random_aks_cluster 
--azure-resource-group-name random_aks_rg --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n\n

Azure Example - Kubernetes Admission Controller Installation:\n
abstrakt install crowdstrike --kac --cloud-provider azure --cluster-type aks --cluster-name random_aks_cluster 
--azure-resource-group-name random_aks_rg --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n\n

Azure Example - Image Assessment at Runtime Installation:\n
abstrakt install crowdstrike --iar --cloud-provider azure --cluster-type aks --cluster-name random_aks_cluster 
--azure-resource-group-name random_aks_rg --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n\n

Azure Example - Detections Container Installation:\n
abstrakt install crowdstrike --detections-container --cloud-provider azure --cluster-type aks --cluster-name 
random_aks_cluster --azure-resource-group-name random_aks_rg --falcon-client-id 3af74117 --falcon-client-secret 
vlTpn372s\n\n

Azure Example - Vulnerable Apps Installation:\n
abstrakt install crowdstrike --vulnerable-apps --cloud-provider azure --cluster-type aks --cluster-name 
random_aks_cluster --azure-resource-group-name random_aks_rg --falcon-client-id 3af74117 --falcon-client-secret 
vlTpn372s\n\n

###########\n
### GCP ###\n
###########\n\n

GCP Example - All CrowdStrike Sensors with Detections Container and Vulnerable Apps:\n
abstrakt install crowdstrike --falcon-sensor --kpa --kac --iar --detections-container 
--vulnerable-apps --cloud-provider gcp --cluster-type gke-standard --cluster-name random_gke_cluster 
--cloud-region us-central1-c --gcp-project-name xyz --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n\n

GCP Example - Falcon Sensor Installation:\n
abstrakt install crowdstrike --falcon-sensor --cloud-provider gcp --cluster-type gke-standard 
--cluster-name random_gke_cluster --cloud-region us-central1-c --gcp-project-name xyz --falcon-client-id 3af74117 
--falcon-client-secret vlTpn372s\n\n

GCP Example - Kubernetes Protection Agent Installation:\n
abstrakt install crowdstrike --kpa --cloud-provider gcp --cluster-type gke-standard --cluster-name random_gke_cluster 
--cloud-region us-central1-c --gcp-project-name xyz --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n\n

GCP Example - Kubernetes Admission Controller Installation:\n
abstrakt install crowdstrike --kac --cloud-provider gcp --cluster-type gke-standard --cluster-name random_gke_cluster 
--cloud-region us-central1-c --gcp-project-name xyz --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n\n

GCP Example - Image Assessment at Runtime Installation:\n
abstrakt install crowdstrike --iar --cloud-provider gcp --cluster-type gke-standard --cluster-name random_gke_cluster 
--cloud-region us-central1-c --gcp-project-name xyz --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n\n

GCP Example - Detections Container Installation:\n
abstrakt install crowdstrike --detections-container --cloud-provider gcp --cluster-type gke-standard --cluster-name 
random_gke_cluster --cloud-region us-central1-c --gcp-project-name xyz --falcon-client-id 3af74117 
--falcon-client-secret vlTpn372s\n\n

GCP Example - Vulnerable Apps Installation:\n
abstrakt install crowdstrike --vulnerable-apps --cloud-provider gcp --cluster-type gke-standard --cluster-name 
random_gke_cluster --cloud-region us-central1-c --gcp-project-name xyz --falcon-client-id 3af74117 
--falcon-client-secret vlTpn372s\n\n
"""


@runtime_sensor_app.command(help=help_message, rich_help_panel='CrowdStrike Sensors')
def crowdstrike(
  falcon_sensor: Annotated[bool, typer.Option('--falcon-sensor',
                                              help='Install Falcon Sensor',
                                              rich_help_panel='CrowdStrike EDR Sensor',
                                              show_default=False)] = False,
  kernel_mode: Annotated[bool, typer.Option('--kernel-mode', help='Install Falcon Sensor in Kernel mode',
                                            rich_help_panel='CrowdStrike EDR Sensor Options',
                                            show_default=False)] = False,
  ebpf_mode: Annotated[bool, typer.Option('--ebpf-mode', help='Install Falcon Sensor in ebpf mode',
                                          rich_help_panel='CrowdStrike EDR Sensor Options',
                                          show_default=False)] = False,
  monitor_namespaces: Annotated[str, typer.Option('--monitor-namespaces',
                                                  help='Namespaces to monitor to inject falcon sensor '
                                                       '| Example: All or ns1,ns2,ns3',
                                                  rich_help_panel='CrowdStrike EDR Sensor Options')] = 'All',
  exclude_namespaces: Annotated[str, typer.Option('--exclude-namespaces',
                                                  help='Namespaces to exclude from falcon sensor injection '
                                                       '| Example: ns1,ns2,ns3',
                                                  rich_help_panel='CrowdStrike EDR Sensor Options',
                                                  show_default=False)] = None,
  falcon_image_tag: Annotated[str, typer.Option('--falcon-image-tag', help='Falcon Sensor Image Tag | '
                                                                           'Example: 7.10.0-16303-1.falcon-linux'
                                                                           '.x86_64.Release.US-1',
                                                rich_help_panel="CrowdStrike EDR Sensor Options",
                                                show_default=False)] = None,
  proxy_server: Annotated[str, typer.Option('--proxy-server', help='Proxy Server IP or FQDN | '
                                                                   'Example: 10.10.10.10 OR proxy.internal.com',
                                            rich_help_panel="CrowdStrike EDR Sensor Options",
                                            show_default=False)] = None,
  proxy_port: Annotated[str, typer.Option('--proxy-port', help='Proxy Server Port | Example: 8080',
                                          rich_help_panel="CrowdStrike EDR Sensor Options",
                                          show_default=False)] = None,
  falcon_sensor_tags: Annotated[str, typer.Option('--falcon-sensor-tags', help='Falcon Sensor Tags | '
                                                                               'Example: Tag1,Tag2',
                                                  rich_help_panel="CrowdStrike EDR Sensor Options",
                                                  show_default=False)] = None,
  kpa: Annotated[bool, typer.Option('--kpa',
                                    help='Install Kubernetes Protection Agent',
                                    rich_help_panel='CrowdStrike Kubernetes Agents',
                                    show_default=False)] = False,
  kac: Annotated[bool, typer.Option('--kac',
                                    help='Install Kubernetes Admission Controller',
                                    rich_help_panel='CrowdStrike Kubernetes Agents',
                                    show_default=False)] = False,
  iar: Annotated[bool, typer.Option('--iar',
                                    help='Install Image Assessment at Runtime',
                                    rich_help_panel='CrowdStrike Kubernetes Agents',
                                    show_default=False)] = False,
  falcon_client_id: Annotated[str, typer.Option('--falcon-client-id',
                                                help='Client ID to Install Falcon Sensor | Example: QWERT',
                                                rich_help_panel='CrowdStrike API Keys',
                                                show_default=False)] = None,
  falcon_client_secret: Annotated[str, typer.Option('--falcon-client-secret',
                                                    help='Client Secret to Install Falcon Sensor | Example: QWERT',
                                                    rich_help_panel='CrowdStrike API Keys',
                                                    show_default=False)] = None,
  cloud_provider: Annotated[str, typer.Option('--cloud-provider',
                                              help='Cloud Service Provider [aws | azure | gcp]',
                                              rich_help_panel='Cloud Service Provider Options',
                                              show_default=False)] = None,
  cluster_type: Annotated[str, typer.Option('--cluster-type',
                                            help='Cluster Type [eks-managed-node | eks-self-managed-node | '
                                                 'eks-fargate | aks | gke-standard | gke-autopilot]',
                                            rich_help_panel='Cloud Service Provider Options',
                                            show_default=False)] = None,
  cluster_name: Annotated[str, typer.Option('--cluster-name',
                                            help='Cluster Name',
                                            rich_help_panel='Cloud Service Provider Options',
                                            show_default=False)] = None,
  cloud_region: Annotated[str, typer.Option('--cloud-region', help='Cluster Region or Zone',
                                            rich_help_panel='Cloud Service Provider Options',
                                            show_default=False)] = None,
  azure_resource_group_name: Annotated[str, typer.Option('--azure-resource-group-name',
                                                         help='Azure Resource Group Name',
                                                         rich_help_panel='Cloud Service Provider Options',
                                                         show_default=False)] = None,
  gcp_project_name: Annotated[str, typer.Option('--gcp-project-name', help='GCP Project Name',
                                                rich_help_panel='Cloud Service Provider Options',
                                                show_default=False)] = None,
  detections_container: Annotated[bool, typer.Option('--detections-container',
                                                     help='Install CrowdStrike Detections Container',
                                                     rich_help_panel='CrowdStrike Artificial '
                                                                     'Detections Generator',
                                                     show_default=False)] = False,
  vulnerable_apps: Annotated[bool, typer.Option('--vulnerable-apps',
                                                help='Install Vulnerable Apps',
                                                rich_help_panel='CrowdStrike Artificial '
                                                                'Detections Generator',
                                                show_default=False)] = False,
):
  crwd_sensor_log_filename = f'/var/logs/crowdstrike/sensors/sensor-{uk_time_str}.log'
  crwd_sensor_logger = CustomLogger(__name__, crwd_sensor_log_filename).logger

  manager = CrowdStrikeSensorOperationsManager(falcon_sensor=falcon_sensor,
                                               kernel_mode=kernel_mode,
                                               ebpf_mode=ebpf_mode,
                                               monitor_namespaces=monitor_namespaces,
                                               exclude_namespaces=exclude_namespaces,
                                               falcon_image_tag=falcon_image_tag,
                                               proxy_server=proxy_server,
                                               proxy_port=proxy_port,
                                               falcon_sensor_tags=falcon_sensor_tags,
                                               kpa=kpa,
                                               kac=kac,
                                               iar=iar,
                                               falcon_client_id=falcon_client_id,
                                               falcon_client_secret=falcon_client_secret,
                                               cloud_provider=cloud_provider,
                                               cluster_type=cluster_type,
                                               cluster_name=cluster_name,
                                               cloud_region=cloud_region,
                                               azure_resource_group_name=azure_resource_group_name,
                                               gcp_project_name=gcp_project_name,
                                               detections_container=detections_container,
                                               vulnerable_apps=vulnerable_apps,
                                               logger=crwd_sensor_logger)

  manager.start_crowdstrike_sensor_operations()
