import typer
import pytz

from datetime import datetime
from typing_extensions import Annotated

from abstrakt.pythonModules.opsManager.AzureClusterOperationsManager import AzureClusterOperationsManager
from abstrakt.pythonModules.customLogging.customLogging import CustomLogger

uk_timezone = pytz.timezone('Europe/London')
uk_time = datetime.now(uk_timezone)
uk_time_str = uk_time.strftime('%d%m%Y')

create_azure_app = typer.Typer()

help_message = """Azure AKS Cluster"""


@create_azure_app.command(help=help_message, rich_help_panel='Azure Kubernetes Clusters')
def aks(
  config_file: Annotated[str, typer.Option(help='Cluster Configuration File', show_default=True,
                                           rich_help_panel='AKS Configuration File'
                                           )] = './abstrakt/conf/azure/aks.conf',
  cluster_name: Annotated[str, typer.Option('--cluster-name',
                                            help='Cluster Name', show_default=False,
                                            rich_help_panel="AKS Configuration")] = None,
  resource_group: Annotated[str, typer.Option('--resource-group', help='Resource Group Name', show_default=False,
                                              rich_help_panel="AKS Configuration")] = None,
  location: Annotated[str, typer.Option('--location', help='Resource Group Location', show_default=False,
                                        rich_help_panel="AKS Configuration")] = None,
  asset_tags: Annotated[str, typer.Option('--asset-tags', help='Asset Tags | Example - "POV=CRWD,App=Abstrakt"',
                                          show_default=False,
                                          rich_help_panel="AKS Configuration")] = None,
  install_falcon_sensor: Annotated[bool, typer.Option('--install-falcon-sensor',
                                                      help='Install Falcon Sensor', show_default=False,
                                                      rich_help_panel='CrowdStrike EDR Sensor')] = False,
  kernel_mode: Annotated[bool, typer.Option('--kernel-mode', help='Install Falcon Sensor in Kernel mode',
                                            show_default=False,
                                            rich_help_panel='CrowdStrike EDR Sensor Options')] = False,
  ebpf_mode: Annotated[bool, typer.Option('--ebpf-mode', help='Install Falcon Sensor in ebpf mode',
                                          show_default=False,
                                          rich_help_panel='CrowdStrike EDR Sensor Options')] = False,
  registry: Annotated[str, typer.Option('--registry', help='Registry for all Falcon Images | '
                                        'Example: abstrakt.azurecr.io',
                                        show_default=False,
                                        rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  repository: Annotated[str, typer.Option('--repository', help='Registry for all Falcon Images | '
                                          'Example: falcon-sensor',
                                          show_default=False,
                                          rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  sensor_image_tag: Annotated[str, typer.Option('--sensor-image-tag', help='Falcon Sensor Image Tag | '
                                                'Example: 7.10.0-16303-1.falcon-linux.x86_64.Release.US-1',
                                                rich_help_panel="CrowdStrike EDR Sensor Options")] = 'latest',
  proxy_server: Annotated[str, typer.Option('--proxy-server', help='Proxy Server IP or FQDN | '
                                                                   'Example: 10.10.10.10 OR proxy.internal.com',
                                            show_default=False,
                                            rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  proxy_port: Annotated[int, typer.Option('--proxy-port', help='Proxy Server Port | Example: 8080',
                                          show_default=False, rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  sensor_tags: Annotated[str, typer.Option('--sensor-tags', help='Falcon Sensor Tags | '
                                           'Example: Tag1,Tag2',
                                           show_default=True,
                                           rich_help_panel="CrowdStrike EDR Sensor Options")] = 'CRWD,POV,AKS,ABSTRAKT',
  acr_rg: Annotated[str, typer.Option('--acr-resource-group', help='ACR Resource Group Name | '
                                      'Example: resource_group1',
                                      show_default=False,
                                      rich_help_panel="Azure Options")] = None,
  sp_name: Annotated[str, typer.Option('--sp-name',
                                       help='Azure Service Principal Name | Example: administrator',
                                       show_default=False,
                                       rich_help_panel="Azure Options")] = None,
  sp_pass: Annotated[str, typer.Option('--sp-pass',
                                       help='Azure Service Principal Password | Example: password',
                                       show_default=False,
                                       rich_help_panel="Azure Options")] = None,
  install_kac: Annotated[bool, typer.Option('--install-kac',
                                            help='Install Kubernetes Admission Controller',
                                            show_default=False,
                                            rich_help_panel='CrowdStrike Kubernetes Admission Controller')] = False,
  kac_image_tag: Annotated[str, typer.Option('--kac-image-tag', help='KAC Image Tag | '
                                             'Example: 7.18.0-1603.container.x86_64.Release.US-1',
                                             rich_help_panel="CrowdStrike Kubernetes Admission Controller")] = 'latest',
  install_iar: Annotated[bool, typer.Option('--install-iar',
                                            help='Install Image Assessment at Runtime',
                                            show_default=False,
                                            rich_help_panel='CrowdStrike Image Assessment at Runtime')] = False,
  iar_image_tag: Annotated[str, typer.Option('--iar-image-tag', help='IAR Image Tag | '
                                             'Example: 1.0.9',
                                             rich_help_panel="CrowdStrike Image Assessment at Runtime")] = 'latest',
  install_kpa: Annotated[bool, typer.Option('--install-kpa',
                                            help='Install Kubernetes Protection Agent',
                                            show_default=False,
                                            rich_help_panel='CrowdStrike Kubernetes Protection Agent')] = False,
  falcon_client_id: Annotated[str, typer.Option('--falcon-client-id',
                                                help='Client ID to Install Falcon Sensor | Example: QWERT',
                                                show_default=False,
                                                rich_help_panel='CrowdStrike API Keys')] = None,
  falcon_client_secret: Annotated[str, typer.Option('--falcon-client-secret',
                                                    help='Client Secret to Install Falcon Sensor | Example: QWERT',
                                                    show_default=False,
                                                    rich_help_panel='CrowdStrike API Keys')] = None,
  install_detections_container: Annotated[bool, typer.Option('--install-detections-container',
                                                             help='Install CrowdStrike Detections Container',
                                                             show_default=False,
                                                             rich_help_panel='CrowdStrike Artificial '
                                                                             'Detections Generator')] = False,
  install_vulnerable_apps: Annotated[bool, typer.Option('--install-vulnerable-apps',
                                                        help='Install Vulnerable Apps',
                                                        show_default=False,
                                                        rich_help_panel='CrowdStrike Artificial '
                                                                        'Detections Generator')] = False,
  generate_misconfigs: Annotated[bool, typer.Option('--generate-misconfigs',
                                                    help='Generate Misconfigurations',
                                                    show_default=False,
                                                    rich_help_panel='CrowdStrike Artificial '
                                                    'Detections Generator')] = False,
):
  azure_log_filename = f'/var/log/crowdstrike/azure/aks-{uk_time_str}.log'
  aks_logger = CustomLogger(__name__, azure_log_filename).logger

  manager = AzureClusterOperationsManager(config_file=config_file,
                                          cluster_name=cluster_name,
                                          resource_group=resource_group,
                                          location=location,
                                          asset_tags=asset_tags,
                                          install_falcon_sensor=install_falcon_sensor,
                                          registry=registry,
                                          repository=repository,
                                          sensor_image_tag=sensor_image_tag,
                                          proxy_server=proxy_server,
                                          proxy_port=proxy_port,
                                          sensor_tags=sensor_tags,
                                          acr_resource_group=acr_rg,
                                          sp_name=sp_name,
                                          sp_pass=sp_pass,
                                          install_kac=install_kac,
                                          kac_image_tag=kac_image_tag,
                                          install_iar=install_iar,
                                          iar_image_tag=iar_image_tag,
                                          install_kpa=install_kpa,
                                          cloud_type='azure',
                                          cluster_type='aks',
                                          falcon_client_id=falcon_client_id,
                                          falcon_client_secret=falcon_client_secret,
                                          install_detections_container=install_detections_container,
                                          install_vulnerable_apps=install_vulnerable_apps,
                                          generate_misconfigs=generate_misconfigs,
                                          logger=aks_logger,
                                          kernel_mode=kernel_mode,
                                          ebpf_mode=ebpf_mode)

  manager.start_azure_cluster_operations()


azure_aci_help_message = """Azure ACI Cluster"""


# @create_azure_app.command(help=azure_aci_help_message, rich_help_panel='Azure Kubernetes Clusters')
# def aci(
#   config_file: Annotated[str, typer.Option(help='Cluster Configuration File', show_default=True,
#                                            rich_help_panel='ACI Configuration File'
#                                            )] = './abstrakt/conf/azure/aci.conf',
# ):
#   aci_log_filename = f'/var/log/crowdstrike/azure/aci-{uk_time_str}.log'
#   aci_logger = CustomLogger(__name__, aci_log_filename).logger
#
#   manager = AzureClusterOperationsManager(config_file=config_file,
#                                           cloud_type='azure',
#                                           cluster_type='aci',
#                                           logger=aci_logger)
#
#   manager.start_azure_cluster_operations()
