import typer
import pytz

from datetime import datetime
from typing_extensions import Annotated

from abstrakt.pythonModules.opsManager.CrowdStrikeSensorOperationsManager import CrowdStrikeSensorOperationsManager
from abstrakt.pythonModules.customLogging.customLogging import CustomLogger

uk_timezone = pytz.timezone('Europe/London')
uk_time = datetime.now(uk_timezone)
uk_time_str = uk_time.strftime('%d%m%Y')

uninstall_sensor_app = typer.Typer()


@uninstall_sensor_app.command(rich_help_panel='CrowdStrike Sensors')
def crowdstrike(
  falcon_sensor: Annotated[bool, typer.Option('--falcon-sensor',
                                              help='Uninstall Falcon Sensor',
                                              rich_help_panel='CrowdStrike EDR Sensor',
                                              show_default=False)] = False,
  aws_cluster_name: Annotated[str, typer.Option('--aws-cluster-name',
                                                help='Cluster Name',
                                                rich_help_panel='AWS Options',
                                                show_default=False)] = None,
  aws_region: Annotated[str, typer.Option('--aws-region', help='Cluster Region or Zone',
                                          rich_help_panel='AWS Options',
                                          show_default=False)] = None,
  azure_cluster_name: Annotated[str, typer.Option('--azure-cluster-name',
                                                  help='Cluster Name',
                                                  rich_help_panel='Azure Options',
                                                  show_default=False)] = None,
  azure_resource_group_name: Annotated[str, typer.Option('--azure-resource-group-name',
                                                         help='Azure Resource Group Name',
                                                         rich_help_panel='Azure Options',
                                                         show_default=False)] = None,
  gcp_cluster_name: Annotated[str, typer.Option('--gcp-cluster-name',
                                                help='GCP Cluster Name',
                                                rich_help_panel='GCP Options',
                                                show_default=False)] = None,
  gcp_region: Annotated[str, typer.Option('--gcp-region', help='Cluster Region or Zone',
                                          rich_help_panel='GCP Options',
                                          show_default=False)] = None,
  gcp_project_id: Annotated[str, typer.Option('--gcp-project-name', help='GCP Project Name',
                                              rich_help_panel='GCP Options',
                                              show_default=False)] = None,
  kpa: Annotated[bool, typer.Option('--kpa',
                                    help='Uninstall Kubernetes Protection Agent',
                                    rich_help_panel='CrowdStrike Kubernetes Agents',
                                    show_default=False)] = False,
  kac: Annotated[bool, typer.Option('--kac',
                                    help='Uninstall Kubernetes Admission Controller',
                                    rich_help_panel='CrowdStrike Kubernetes Agents',
                                    show_default=False)] = False,
  iar: Annotated[bool, typer.Option('--iar',
                                    help='Uninstall Image Assessment at Runtime',
                                    rich_help_panel='CrowdStrike Kubernetes Agents',
                                    show_default=False)] = False,
  # detections_container: Annotated[bool, typer.Option('--detections-container',
  #                                                    help='Uninstall CrowdStrike Detections Container',
  #                                                    rich_help_panel='CrowdStrike Artificial '
  #                                                                    'Detections Generator',
  #                                                    show_default=False)] = False,
  # vulnerable_apps: Annotated[bool, typer.Option('--vulnerable-apps',
  #                                               help='Uninstall Vulnerable Apps',
  #                                               rich_help_panel='CrowdStrike Artificial '
  #                                                               'Detections Generator',
  #                                               show_default=False)] = False,
  falcon_client_id: Annotated[str, typer.Option('--falcon-client-id',
                                                help='Client ID to Install Falcon Sensor | Example: QWERT',
                                                rich_help_panel='CrowdStrike API Keys',
                                                show_default=False)] = None,
  falcon_client_secret: Annotated[str, typer.Option('--falcon-client-secret',
                                                    help='Client Secret to Install Falcon Sensor | Example: QWERT',
                                                    rich_help_panel='CrowdStrike API Keys',
                                                    show_default=False)] = None
):
  crwd_sensor_log_filename = f'/var/log/crowdstrike/sensors/sensor-{uk_time_str}.log'
  crwd_sensor_logger = CustomLogger(__name__, crwd_sensor_log_filename).logger

  manager = CrowdStrikeSensorOperationsManager(falcon_sensor=falcon_sensor,
                                               aws_region=aws_region,
                                               aws_cluster_name=aws_cluster_name,
                                               azure_resource_group_name=azure_resource_group_name,
                                               azure_cluster_name=azure_cluster_name,
                                               gcp_region=gcp_region,
                                               gcp_cluster_name=gcp_cluster_name,
                                               gcp_project_id=gcp_project_id,
                                               kpa=kpa,
                                               kac=kac,
                                               iar=iar,
                                               # detections_container=detections_container,
                                               # vulnerable_apps=vulnerable_apps,
                                               falcon_client_id=falcon_client_id,
                                               falcon_client_secret=falcon_client_secret,
                                               logger=crwd_sensor_logger)

  manager.delete_crowdstrike_sensors()
