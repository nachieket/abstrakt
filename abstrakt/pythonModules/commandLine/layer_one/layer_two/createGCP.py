import typer
import pytz

from datetime import datetime
from typing_extensions import Annotated

from abstrakt.pythonModules.opsManager.clusterOpsManager import ClusterOperationsManager
from abstrakt.pythonModules.customLogging.customLogging import CustomLogger

uk_timezone = pytz.timezone('Europe/London')
uk_time = datetime.now(uk_timezone)
uk_time_str = uk_time.strftime('%d%m%Y')

create_gke_app = typer.Typer()


@create_gke_app.command(help='Install GKE COS Cluster', rich_help_panel='GCP GKE Clusters')
def gke_cos(
  config_file: Annotated[str, typer.Option(help='Cluster Configuration File', show_default=True,
                                           rich_help_panel='GKE COS Configuration File'
                                           )] = './abstrakt/conf/gcp/gke/gke-cos.conf',
  install_falcon_sensor: Annotated[bool, typer.Option('--install-falcon-sensor',
                                                      help='Install Falcon Sensor -> Requires: '
                                                           '--falcon-client-id, '
                                                           '--falcon-client-secret), '
                                                           '(Optional: --proxy-server, '
                                                           '--proxy-port '
                                                           '--falcon-sensor-tags)',
                                                      rich_help_panel='CrowdStrike EDR Sensor')] = False,
  falcon_client_id: Annotated[str, typer.Option('--falcon-client-id',
                                                help='Client ID to Install Falcon Sensor | Example: QWERT',
                                                rich_help_panel='CrowdStrike EDR Sensor Options')] = None,
  falcon_client_secret: Annotated[str, typer.Option('--falcon-client-secret',
                                                    help='Client Secret to Install Falcon Sensor | Example: QWERT',
                                                    rich_help_panel='CrowdStrike EDR Sensor Options')] = None,
  # falcon_cid: Annotated[str, typer.Option('--falcon-cid',
  #                                         help='Customer ID to install Falcon Sensor |  Example: QWERT-AB',
  #                                         rich_help_panel='CrowdStrike EDR Sensor Options')] = None,
  # falcon_cloud_region: Annotated[str, typer.Option('--falcon-cloud-region',
  #                                                  help='Falcon Cloud Region: us-1, us-2, eu-1',
  #                                                  rich_help_panel='CrowdStrike EDR Sensor Options')] = None,
  # falcon_api: Annotated[str, typer.Option('--falcon-api',
  #                                         help='Possible Values: api.crowdstrike.com (us-1), '
  #                                              'api.us-2.crowdstrike.com (us-2), '
  #                                              'api.eu-1.crowdstrike.com (eu-1)',
  #                                         rich_help_panel='CrowdStrike EDR Sensor Options')] = None,
  proxy_server: Annotated[str, typer.Option('--proxy-server', help='Proxy Server IP or FQDN | '
                                                                   'Example: 10.10.10.10 OR proxy.internal.com',
                                            rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  proxy_port: Annotated[str, typer.Option('--proxy-port', help='Proxy Server Port | Example: 8080',
                                          rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  falcon_sensor_tags: Annotated[str, typer.Option('--falcon-sensor-tags', help='Falcon Sensor Tags | '
                                                                               'Example: Tag1,Tag2',
                                                  rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  install_kpa: Annotated[bool, typer.Option('--install-kpa',
                                            help='Install Kubernetes Protection Agent',
                                            rich_help_panel='CrowdStrike Kubernetes Agents')] = False,
  install_kac: Annotated[bool, typer.Option('--install-kac',
                                            help='Install Kubernetes Admission Controller',
                                            rich_help_panel='CrowdStrike Kubernetes Agents')] = False,
  install_detections_container: Annotated[bool, typer.Option('--install-detections-container',
                                                             help='Install CrowdStrike Detections Container',
                                                             rich_help_panel='CrowdStrike Artificial '
                                                                             'Detections Generator')] = False
):
  gke_cos_log_filename = f'/var/logs/crowdstrike/gcp/gke/gke-cos-{uk_time_str}.log'
  aks_logger = CustomLogger(__name__, gke_cos_log_filename).logger

  manager = ClusterOperationsManager(config_file=config_file,
                                     install_falcon_sensor=install_falcon_sensor,
                                     falcon_client_id=falcon_client_id,
                                     falcon_client_secret=falcon_client_secret,
                                     # falcon_cid=falcon_cid,
                                     # falcon_cloud_region=falcon_cloud_region,
                                     # falcon_api=falcon_api,
                                     proxy_server=proxy_server,
                                     proxy_port=proxy_port,
                                     falcon_sensor_tags=falcon_sensor_tags,
                                     install_kpa=install_kpa,
                                     install_kac=install_kac,
                                     install_detections_container=install_detections_container,
                                     cloud_type='gcp',
                                     cluster_type='gke-cos',
                                     logger=aks_logger)

  manager.start_cluster_operations()


@create_gke_app.command(help='Install GKE Autopilot Cluster', rich_help_panel='GCP GKE Clusters')
def gke_autopilot(
  config_file: Annotated[str, typer.Option(help='Cluster Configuration File', show_default=True,
                                           rich_help_panel='GKE Autopilot Configuration File'
                                           )] = './abstrakt/conf/gcp/gke/gke-autopilot.conf',
  install_falcon_sensor: Annotated[bool, typer.Option('--install-falcon-sensor',
                                                      help='Install Falcon Sensor -> Requires: '
                                                           '--falcon-client-id, '
                                                           '--falcon-client-secret), '
                                                           '(Optional: --proxy-server, '
                                                           '--proxy-port '
                                                           '--falcon-sensor-tags)',
                                                      rich_help_panel='CrowdStrike EDR Sensor')] = False,
  falcon_client_id: Annotated[str, typer.Option('--falcon-client-id',
                                                help='Client ID to Install Falcon Sensor | Example: QWERT',
                                                rich_help_panel='CrowdStrike EDR Sensor Options')] = None,
  falcon_client_secret: Annotated[str, typer.Option('--falcon-client-secret',
                                                    help='Client Secret to Install Falcon Sensor | Example: QWERT',
                                                    rich_help_panel='CrowdStrike EDR Sensor Options')] = None,
  # falcon_cid: Annotated[str, typer.Option('--falcon-cid',
  #                                         help='Customer ID to install Falcon Sensor |  Example: QWERT-AB',
  #                                         rich_help_panel='CrowdStrike EDR Sensor Options')] = None,
  # falcon_cloud_region: Annotated[str, typer.Option('--falcon-cloud-region',
  #                                                  help='Falcon Cloud Region: us-1, us-2, eu-1',
  #                                                  rich_help_panel='CrowdStrike EDR Sensor Options')] = None,
  # falcon_api: Annotated[str, typer.Option('--falcon-api',
  #                                         help='Possible Values: api.crowdstrike.com (us-1), '
  #                                              'api.us-2.crowdstrike.com (us-2), '
  #                                              'api.eu-1.crowdstrike.com (eu-1)',
  #                                         rich_help_panel='CrowdStrike EDR Sensor Options')] = None,
  proxy_server: Annotated[str, typer.Option('--proxy-server', help='Proxy Server IP or FQDN | '
                                                                   'Example: 10.10.10.10 OR proxy.internal.com',
                                            rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  proxy_port: Annotated[str, typer.Option('--proxy-port', help='Proxy Server Port | Example: 8080',
                                          rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  falcon_sensor_tags: Annotated[str, typer.Option('--falcon-sensor-tags', help='Falcon Sensor Tags | '
                                                                               'Example: Tag1,Tag2',
                                                  rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  install_kpa: Annotated[bool, typer.Option('--install-kpa',
                                            help='Install Kubernetes Protection Agent',
                                            rich_help_panel='CrowdStrike Kubernetes Agents')] = False,
  install_kac: Annotated[bool, typer.Option('--install-kac',
                                            help='Install Kubernetes Admission Controller',
                                            rich_help_panel='CrowdStrike Kubernetes Agents')] = False,
  install_detections_container: Annotated[bool, typer.Option('--install-detections-container',
                                                             help='Install CrowdStrike Detections Container',
                                                             rich_help_panel='CrowdStrike Artificial '
                                                                             'Detections Generator')] = False
):
  gke_cos_log_filename = f'/var/logs/crowdstrike/gcp/gke/gke-autopilot-{uk_time_str}.log'
  aks_logger = CustomLogger(__name__, gke_cos_log_filename).logger

  manager = ClusterOperationsManager(config_file=config_file,
                                     install_falcon_sensor=install_falcon_sensor,
                                     falcon_client_id=falcon_client_id,
                                     falcon_client_secret=falcon_client_secret,
                                     # falcon_cid=falcon_cid,
                                     # falcon_cloud_region=falcon_cloud_region,
                                     # falcon_api=falcon_api,
                                     proxy_server=proxy_server,
                                     proxy_port=proxy_port,
                                     falcon_sensor_tags=falcon_sensor_tags,
                                     install_kpa=install_kpa,
                                     install_kac=install_kac,
                                     install_detections_container=install_detections_container,
                                     cloud_type='gcp',
                                     cluster_type='gke-autopilot',
                                     logger=aks_logger)

  manager.start_cluster_operations()
