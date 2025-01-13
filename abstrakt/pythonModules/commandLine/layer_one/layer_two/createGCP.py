import typer
import pytz

from datetime import datetime
from typing_extensions import Annotated

from abstrakt.pythonModules.customLogging.customLogging import CustomLogger
from abstrakt.pythonModules.opsManager.GCPClusterOperationsManager import GCPClusterOperationsManager

uk_timezone = pytz.timezone('Europe/London')
uk_time = datetime.now(uk_timezone)
uk_time_str = uk_time.strftime('%d%m%Y')

create_gke_app = typer.Typer()

gke_standard_help_message = """GKE Standard Cluster"""


@create_gke_app.command(help=gke_standard_help_message, rich_help_panel='GCP GKE Clusters')
def gke_standard(
  config_file: Annotated[str, typer.Option(help='Cluster Configuration File', show_default=True,
                                           rich_help_panel='GKE Configuration'
                                           )] = './abstrakt/conf/gcp/gke/gke-standard.conf',
  cluster_name: Annotated[str, typer.Option('--cluster-name',
                                            help='Cluster Name', show_default=False,
                                            rich_help_panel="GKE Configuration")] = None,
  vpc_network: Annotated[str, typer.Option('--vpc-network', help='VPC Name', show_default=False,
                                           rich_help_panel="GKE Configuration")] = None,
  location: Annotated[str, typer.Option('--location', help='Cluster Region', show_default=False,
                                        rich_help_panel="GKE Configuration")] = None,
  project_id: Annotated[str, typer.Option('--project-id', help='GCP Project ID', show_default=False,
                                          rich_help_panel='GKE Configuration')] = None,
  asset_tags: Annotated[str, typer.Option('--asset-tags', help='Asset Tags (Alphanumeric and Hyphens only) '
                                                               '| Example - "Falcon,Area5,CRWD"',
                                          show_default=False,
                                          rich_help_panel="GKE Configuration")] = None,
  install_falcon_sensor: Annotated[bool, typer.Option('--install-falcon-sensor',
                                                      help='Install Falcon Sensor',
                                                      rich_help_panel='CrowdStrike EDR Sensor')] = False,
  registry: Annotated[str, typer.Option('--registry', help='Image Registry for all Images | '
                                        'Example: europe-west2-docker.pkg.dev',
                                        show_default=False, rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  repository: Annotated[str, typer.Option('--repository', help='Image Repository for all Images | '
                                          'Example: abstrakt', show_default=False,
                                          rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  sensor_image_tag: Annotated[str, typer.Option('--sensor-image-tag', help='Falcon Sensor Image Tag | '
                                                'Example: 7.10.0-16303-1.falcon-linux.x86_64.Release.US-1',
                                                rich_help_panel="CrowdStrike EDR Sensor Options")] = 'latest',
  proxy_server: Annotated[str, typer.Option('--proxy-server', help='Proxy Server IP or FQDN | '
                                            'Example: 10.10.10.10 OR proxy.internal.com', show_default=False,
                                            rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  proxy_port: Annotated[int, typer.Option('--proxy-port', help='Proxy Server Port | Example: 8080',
                                          show_default=False, rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  sensor_tags: Annotated[str, typer.Option('--sensor-tags', help='Falcon Sensor Tags | '
                                           'Example: Tag1,Tag2', show_default=False,
                                           rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  service_account: Annotated[str, typer.Option('--service-account', help='Service Account Name',
                                               show_default=False,
                                               rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  install_kac: Annotated[bool, typer.Option('--install-kac',
                                            help='Install Kubernetes Admission Controller',
                                            rich_help_panel='CrowdStrike Kubernetes Admission Controller')] = False,
  kac_image_tag: Annotated[str, typer.Option('--kac-image-tag', help='KAC Image Tag | '
                                             'Example: 7.18.0-1603.container.x86_64.Release.US-1',
                                             rich_help_panel="CrowdStrike Kubernetes Admission Controller")] = 'latest',
  install_iar: Annotated[bool, typer.Option('--install-iar',
                                            help='Install Image Assessment at Runtime',
                                            rich_help_panel='CrowdStrike Image Assessment at Runtime')] = False,
  iar_image_tag: Annotated[str, typer.Option('--iar-image-tag', help='IAR Image Tag | Example: 1.0.9',
                                             rich_help_panel="CrowdStrike Image Assessment at Runtime")] = 'latest',
  install_kpa: Annotated[bool, typer.Option('--install-kpa',
                                            help='Install Kubernetes Protection Agent',
                                            rich_help_panel='CrowdStrike Kubernetes Agents')] = False,
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
  gke_standard_log_filename = f'/var/log/crowdstrike/gcp/gke-standard-{uk_time_str}.log'
  gke_standard_logger = CustomLogger(__name__, gke_standard_log_filename).logger

  manager = GCPClusterOperationsManager(config_file=config_file,
                                        cluster_name=cluster_name,
                                        vpc_network=vpc_network,
                                        location=location,
                                        project_id=project_id,
                                        asset_tags=asset_tags,
                                        install_falcon_sensor=install_falcon_sensor,
                                        registry=registry,
                                        repository=repository,
                                        sensor_image_tag=sensor_image_tag,
                                        proxy_server=proxy_server,
                                        proxy_port=proxy_port,
                                        sensor_tags=sensor_tags,
                                        install_kac=install_kac,
                                        kac_image_tag=kac_image_tag,
                                        install_iar=install_iar,
                                        iar_image_tag=iar_image_tag,
                                        install_kpa=install_kpa,
                                        cloud_type='gcp',
                                        cluster_type='gke-standard',
                                        service_account=service_account,
                                        falcon_client_id=falcon_client_id,
                                        falcon_client_secret=falcon_client_secret,
                                        install_detections_container=install_detections_container,
                                        install_vulnerable_apps=install_vulnerable_apps,
                                        generate_misconfigs=generate_misconfigs,
                                        logger=gke_standard_logger)

  manager.start_gcp_cluster_operations()


gke_autopilot_help_message = """GKE Autopilot Cluster"""


@create_gke_app.command(help=gke_autopilot_help_message, rich_help_panel='GCP GKE Clusters')
def gke_autopilot(
  config_file: Annotated[str, typer.Option(help='Cluster Configuration File', show_default=True,
                                           rich_help_panel='GKE Autopilot Configuration File'
                                           )] = './abstrakt/conf/gcp/gke/gke-autopilot.conf',
  cluster_name: Annotated[str, typer.Option('--cluster-name',
                                            help='Cluster Name', show_default=False,
                                            rich_help_panel="GKE Configuration")] = None,
  vpc_network: Annotated[str, typer.Option('--vpc-network', help='VPC Name', show_default=False,
                                           rich_help_panel="GKE Configuration")] = None,
  location: Annotated[str, typer.Option('--location', help='Cluster Region', show_default=False,
                                        rich_help_panel="GKE Configuration")] = None,
  project_id: Annotated[str, typer.Option('--project-id', help='GCP Project ID', show_default=False,
                                          rich_help_panel='GKE Configuration')] = None,
  install_falcon_sensor: Annotated[bool, typer.Option('--install-falcon-sensor',
                                                      help='Install Falcon Sensor',
                                                      rich_help_panel='CrowdStrike EDR Sensor')] = False,
  registry: Annotated[str, typer.Option('--registry', help='Image Registry for all Images | '
                                                           'Example: europe-west2-docker.pkg.dev',
                                        show_default=False,
                                        rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  repository: Annotated[str, typer.Option('--repository', help='Image Repository for all Images | '
                                                               'Example: abstrakt',
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
                                          rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  sensor_tags: Annotated[str, typer.Option('--sensor-tags', help='Falcon Sensor Tags | '
                                           'Example: Tag1,Tag2', show_default=False,
                                           rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  service_account: Annotated[str, typer.Option('--service-account', help='Service Account Name',
                                               rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
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
                                            rich_help_panel='CrowdStrike Kubernetes Agents')] = False,
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
  gke_autopilot_log_filename = f'/var/log/crowdstrike/gcp/gke-autopilot-{uk_time_str}.log'
  gke_autopilot_logger = CustomLogger(__name__, gke_autopilot_log_filename).logger

  manager = GCPClusterOperationsManager(config_file=config_file,
                                        cluster_name=cluster_name,
                                        vpc_network=vpc_network,
                                        location=location,
                                        project_id=project_id,
                                        asset_tags=None,
                                        install_falcon_sensor=install_falcon_sensor,
                                        registry=registry,
                                        repository=repository,
                                        sensor_image_tag=sensor_image_tag,
                                        proxy_server=proxy_server,
                                        proxy_port=proxy_port,
                                        sensor_tags=sensor_tags,
                                        install_kac=install_kac,
                                        kac_image_tag=kac_image_tag,
                                        install_iar=install_iar,
                                        iar_image_tag=iar_image_tag,
                                        install_kpa=install_kpa,
                                        cloud_type='gcp',
                                        cluster_type='gke-autopilot',
                                        service_account=service_account,
                                        falcon_client_id=falcon_client_id,
                                        falcon_client_secret=falcon_client_secret,
                                        install_detections_container=install_detections_container,
                                        install_vulnerable_apps=install_vulnerable_apps,
                                        generate_misconfigs=generate_misconfigs,
                                        logger=gke_autopilot_logger)

  manager.start_gcp_cluster_operations()
