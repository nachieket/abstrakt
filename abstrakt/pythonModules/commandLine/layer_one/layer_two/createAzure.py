import typer
import pytz

from datetime import datetime
from typing_extensions import Annotated

from abstrakt.pythonModules.opsManager.AzureCluserOperationsManager import AzureClusterOperationsManager
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
  install_falcon_sensor: Annotated[bool, typer.Option('--install-falcon-sensor',
                                                      help='Install Falcon Sensor',
                                                      rich_help_panel='CrowdStrike EDR Sensor')] = False,
  kernel_mode: Annotated[bool, typer.Option('--kernel-mode', help='Install Falcon Sensor in Kernel mode',
                                            rich_help_panel='CrowdStrike EDR Sensor Options')] = False,
  ebpf_mode: Annotated[bool, typer.Option('--ebpf-mode', help='Install Falcon Sensor in ebpf mode',
                                          rich_help_panel='CrowdStrike EDR Sensor Options')] = False,
  image_registry: Annotated[str, typer.Option('--image-registry', help='Registry for all Falcon Images | '
                                              'Example: abstrakt.azurecr.io',
                                              rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  sensor_image_tag: Annotated[str, typer.Option('--sensor-image-tag', help='Falcon Sensor Image Tag | '
                                                'Example: 7.10.0-16303-1.falcon-linux.x86_64.Release.US-1',
                                                rich_help_panel="CrowdStrike EDR Sensor Options")] = 'latest',
  proxy_server: Annotated[str, typer.Option('--proxy-server', help='Proxy Server IP or FQDN | '
                                                                   'Example: 10.10.10.10 OR proxy.internal.com',
                                            rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  proxy_port: Annotated[int, typer.Option('--proxy-port', help='Proxy Server Port | Example: 8080',
                                          rich_help_panel="CrowdStrike EDR Sensor Options")] = 3128,
  sensor_tags: Annotated[str, typer.Option('--sensor-tags', help='Falcon Sensor Tags | '
                                           'Example: Tag1,Tag2',
                                           rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  acr_resource_group: Annotated[str, typer.Option('--acr-resource-group', help='ACR Resource Group Name | '
                                                  'Example: resource_group1',
                                                  rich_help_panel="Azure Options")] = None,
  service_principal_name: Annotated[str, typer.Option('--service-principal-name',
                                                      help='Azure Service Principal Name | Example: administrator',
                                                      rich_help_panel="Azure Options")] = 'crowdstrike',
  service_principal_password: Annotated[str, typer.Option('--service-principal-password',
                                                          help='Azure Service Principal Password | Example: password',
                                                          rich_help_panel="Azure Options")] = None,
  acr_subscription_id: Annotated[str, typer.Option('--acr-subscription-id', help='ACR Subscription ID | '
                                                   'Example: 11111111-0000-0000-0000-111111111111',
                                                   rich_help_panel="Azure Options")] = None,
  aks_subscription_id: Annotated[str, typer.Option('--aks-subscription-id', help='AKS Subscription ID | '
                                                   'Example: 11111111-0000-0000-0000-111111111111',
                                                   rich_help_panel="Azure Options")] = None,
  install_kac: Annotated[bool, typer.Option('--install-kac',
                                            help='Install Kubernetes Admission Controller',
                                            rich_help_panel='CrowdStrike Kubernetes Admission Controller')] = False,
  kac_image_tag: Annotated[str, typer.Option('--kac-image-tag', help='KAC Image Tag | '
                                             'Example: 7.18.0-1603.container.x86_64.Release.US-1',
                                             rich_help_panel="CrowdStrike Kubernetes Admission Controller")] = 'latest',
  install_iar: Annotated[bool, typer.Option('--install-iar',
                                            help='Install Image Assessment at Runtime',
                                            rich_help_panel='CrowdStrike Image Assessment at Runtime')] = False,
  iar_image_tag: Annotated[str, typer.Option('--iar-image-tag', help='IAR Image Tag | '
                                             'Example: 1.0.9',
                                             rich_help_panel="CrowdStrike Image Assessment at Runtime")] = 'latest',
  install_kpa: Annotated[bool, typer.Option('--install-kpa',
                                            help='Install Kubernetes Protection Agent',
                                            rich_help_panel='CrowdStrike Kubernetes Protection Agent')] = False,
  falcon_client_id: Annotated[str, typer.Option('--falcon-client-id',
                                                help='Client ID to Install Falcon Sensor | Example: QWERT',
                                                rich_help_panel='CrowdStrike API Keys')] = None,
  falcon_client_secret: Annotated[str, typer.Option('--falcon-client-secret',
                                                    help='Client Secret to Install Falcon Sensor | Example: QWERT',
                                                    rich_help_panel='CrowdStrike API Keys')] = None,
  install_detections_container: Annotated[bool, typer.Option('--install-detections-container',
                                                             help='Install CrowdStrike Detections Container',
                                                             rich_help_panel='CrowdStrike Artificial '
                                                                             'Detections Generator')] = False,
  install_vulnerable_apps: Annotated[bool, typer.Option('--install-vulnerable-apps',
                                                        help='Install Vulnerable Apps',
                                                        rich_help_panel='CrowdStrike Artificial '
                                                                        'Detections Generator')] = False,
  generate_misconfigs: Annotated[bool, typer.Option('--generate-misconfigs',
                                                    help='Generate Misconfigurations',
                                                    rich_help_panel='CrowdStrike Artificial '
                                                    'Detections Generator')] = False,
):
  azure_log_filename = f'/var/log/crowdstrike/azure/aks-{uk_time_str}.log'
  aks_logger = CustomLogger(__name__, azure_log_filename).logger

  manager = AzureClusterOperationsManager(config_file=config_file,
                                          install_falcon_sensor=install_falcon_sensor,
                                          kernel_mode=kernel_mode,
                                          ebpf_mode=ebpf_mode,
                                          image_registry=image_registry,
                                          sensor_image_tag=sensor_image_tag,
                                          proxy_server=proxy_server,
                                          proxy_port=proxy_port,
                                          sensor_tags=sensor_tags,
                                          acr_resource_group=acr_resource_group,
                                          service_principal_name=service_principal_name,
                                          service_principal_password=service_principal_password,
                                          acr_subscription_id=acr_subscription_id,
                                          aks_subscription_id=aks_subscription_id,
                                          falcon_client_id=falcon_client_id,
                                          falcon_client_secret=falcon_client_secret,
                                          install_kpa=install_kpa,
                                          install_kac=install_kac,
                                          kac_image_tag=kac_image_tag,
                                          install_iar=install_iar,
                                          iar_image_tag=iar_image_tag,
                                          install_detections_container=install_detections_container,
                                          install_vulnerable_apps=install_vulnerable_apps,
                                          generate_misconfigs=generate_misconfigs,
                                          cloud_type='azure',
                                          cluster_type='aks',
                                          logger=aks_logger)

  manager.start_azure_cluster_operations()


azure_aci_help_message = """Azure ACI Cluster"""


@create_azure_app.command(help=azure_aci_help_message, rich_help_panel='Azure Kubernetes Clusters')
def aci(
  config_file: Annotated[str, typer.Option(help='Cluster Configuration File', show_default=True,
                                           rich_help_panel='ACI Configuration File'
                                           )] = './abstrakt/conf/azure/aci.conf',
):
  aci_log_filename = f'/var/log/crowdstrike/azure/aci-{uk_time_str}.log'
  aci_logger = CustomLogger(__name__, aci_log_filename).logger

  manager = AzureClusterOperationsManager(config_file=config_file,
                                          cloud_type='azure',
                                          cluster_type='aci',
                                          logger=aci_logger)

  manager.start_azure_cluster_operations()
