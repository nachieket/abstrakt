import typer
import pytz

from datetime import datetime
from typing_extensions import Annotated

from abstrakt.pythonModules.customLogging.customLogging import CustomLogger
from abstrakt.pythonModules.opsManager.CrowdStrikeSensorOperationsManager import CrowdStrikeSensorOperationsManager


uk_timezone = pytz.timezone('Europe/London')
uk_time = datetime.now(uk_timezone)
uk_time_str = uk_time.strftime('%d%m%Y')

uninstall_sensor_app = typer.Typer()


@uninstall_sensor_app.command(rich_help_panel='CrowdStrike Sensors')
def crowdstrike(
  aws_cluster: Annotated[str, typer.Option('--aws-cluster',
                                           help='AWS Cluster Name',
                                           rich_help_panel='AWS Options',
                                           show_default=False)] = None,
  aws_region: Annotated[str, typer.Option('--aws-region', help='AWS Cluster Region or Zone',
                                          rich_help_panel='AWS Options',
                                          show_default=False)] = None,
  az_cluster: Annotated[str, typer.Option('--az-cluster',
                                          help='Azure Cluster Name',
                                          rich_help_panel='Azure Options',
                                          show_default=False)] = None,
  az_resource_group: Annotated[str, typer.Option('--az-resource-group',
                                                 help='Azure Resource Group Name',
                                                 rich_help_panel='Azure Options',
                                                 show_default=False)] = None,
  gcp_cluster: Annotated[str, typer.Option('--gcp-cluster',
                                           help='GCP Cluster Name',
                                           rich_help_panel='GCP Options',
                                           show_default=False)] = None,
  gcp_region: Annotated[str, typer.Option('--gcp-region', help='GCP Cluster Region or Zone',
                                          rich_help_panel='GCP Options',
                                          show_default=False)] = None,
  gcp_project_id: Annotated[str, typer.Option('--gcp-project-id', help='GCP Project ID',
                                              rich_help_panel='GCP Options',
                                              show_default=False)] = None,
  falcon_sensor: Annotated[bool, typer.Option('--falcon-sensor',
                                              help='Uninstall Falcon Sensor',
                                              rich_help_panel='CrowdStrike EDR Sensor',
                                              show_default=False)] = False,
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
  detections_containers: Annotated[bool, typer.Option('--detections-containers',
                                                      help='Uninstall Detections Containers',
                                                      rich_help_panel='CrowdStrike Detections',
                                                      show_default=False)] = False,
):
  crwd_sensor_log_filename = f'/var/log/crowdstrike/sensors/sensor-{uk_time_str}.log'
  crwd_sensor_logger = CustomLogger(__name__, crwd_sensor_log_filename).logger

  manager = CrowdStrikeSensorOperationsManager(falcon_sensor=falcon_sensor,
                                               aws_region=aws_region,
                                               aws_cluster=aws_cluster,
                                               az_resource_group=az_resource_group,
                                               az_cluster=az_cluster,
                                               gcp_region=gcp_region,
                                               gcp_cluster=gcp_cluster,
                                               gcp_project_id=gcp_project_id,
                                               kpa=kpa,
                                               kac=kac,
                                               iar=iar,
                                               detections=detections_containers,
                                               logger=crwd_sensor_logger)

  manager.delete_crowdstrike_sensors()
