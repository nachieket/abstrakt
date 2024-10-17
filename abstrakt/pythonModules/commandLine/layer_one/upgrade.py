import typer
import pytz

from datetime import datetime
from typing_extensions import Annotated

from abstrakt.pythonModules.opsManager.CrowdStrikeSensorUpgradeOperationsManager import CrowdStrikeSensorInstallOperationsManager
from abstrakt.pythonModules.customLogging.customLogging import CustomLogger

uk_timezone = pytz.timezone('Europe/London')
uk_time = datetime.now(uk_timezone)
uk_time_str = uk_time.strftime('%d%m%Y')

upgrade_sensor_app = typer.Typer()


@upgrade_sensor_app.command(rich_help_panel='CrowdStrike Sensors')
def crowdstrike(
  falcon_sensor: Annotated[bool, typer.Option('--falcon-sensor',
                                              help='Install Falcon Sensor',
                                              rich_help_panel='CrowdStrike EDR Sensor',
                                              show_default=False)] = False,
  registry: Annotated[str, typer.Option('--registry', help='Image Registry for all Falcon Images | '
                                        'Example: 123456789012.dkr.ecr.eu-west-2.amazonaws.com/ecr',
                                        rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  repository: Annotated[str, typer.Option('--repository', help='Image Repository for all Images | '
                                          'Example: abstrakt', show_default=False,
                                          rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  sensor_image_tag: Annotated[str, typer.Option('--sensor-image-tag', help='Falcon Sensor Image Tag | '
                                                'Example: 7.10.0-16303-1.falcon-linux.x86_64.Release.US-1',
                                                rich_help_panel="CrowdStrike EDR Sensor Options")] = 'latest',
  aws_cluster: Annotated[str, typer.Option('--aws-cluster',
                                           help='AWS Cluster Name',
                                           rich_help_panel='AWS Options',
                                           show_default=False)] = None,
  aws_region: Annotated[str, typer.Option('--aws-region', help='Cluster Region or Zone',
                                          rich_help_panel='AWS Options',
                                          show_default=False)] = None,
  aws_ecr_iam_policy: Annotated[str, typer.Option('--aws-ecr-iam-policy', help='AWS IAM Policy Name [EKS Fargate Only]',
                                                  rich_help_panel='AWS Options')] = 'CrowdStrikeFalconContainerEcrPull',
  aws_sensor_iam_role: Annotated[str, typer.Option('--aws-sensor-iam-role', help='AWS IAM Role Name [EKS Fargate Only]',
                                                   rich_help_panel='AWS Options')] = 'CrowdStrikeFalconContainerIAMRole',
  aws_kac_iam_role: Annotated[str, typer.Option('--aws-kac-iam-role', help='AWS IAM Role Name [EKS Fargate Only]',
                                                rich_help_panel='AWS Options')] = 'CrowdStrikeKACIAMRole',
  aws_iar_iam_role: Annotated[str, typer.Option('--aws-iar-iam-role', help='AWS IAM Role Name [EKS Fargate Only]',
                                                rich_help_panel='AWS Options')] = 'CrowdStrikeIARIAMRole',
  az_cluster: Annotated[str, typer.Option('--az-cluster',
                                          help='Azure Cluster Name',
                                          rich_help_panel='Azure Options',
                                          show_default=False)] = None,
  az_resource_group: Annotated[str, typer.Option('--az-resource-group',
                                                 help='Azure Resource Group Name',
                                                 rich_help_panel='Azure Options',
                                                 show_default=False)] = None,
  az_location: Annotated[str, typer.Option('--az-location', help='Azure Resource Group Location',
                                           show_default=False,
                                           rich_help_panel="Azure Options")] = None,
  az_acr_resource_group: Annotated[str, typer.Option('--az-acr-resource-group',
                                                     help='Azure ACR Resource Group Name',
                                                     rich_help_panel='Azure Options',
                                                     show_default=False)] = None,
  az_acr_sub_id: Annotated[str, typer.Option('--az-acr-sub-id',
                                             help='Azure ACR Subscription ID',
                                             rich_help_panel='Azure Options',
                                             show_default=False)] = None,
  az_sp_name: Annotated[str, typer.Option('--az-sp-name',
                                          help='Azure Service Principal Name',
                                          rich_help_panel='Azure Options',
                                          show_default=False)] = 'abstrakt',
  az_sp_pass: Annotated[str, typer.Option('--az-sp-pass',
                                          help='Azure Service Principal Password',
                                          rich_help_panel='Azure Options',
                                          show_default=False)] = None,
  gcp_cluster: Annotated[str, typer.Option('--gcp-cluster',
                                           help='GCP Cluster Name',
                                           rich_help_panel='GCP Options',
                                           show_default=False)] = None,
  gcp_network: Annotated[str, typer.Option('--gcp-network', help='VPC Network Name', show_default=False,
                                           rich_help_panel="GCP Options")] = None,
  gcp_project_id: Annotated[str, typer.Option('--gcp-project-id', help='GCP Project Name',
                                              rich_help_panel='GCP Options',
                                              show_default=False)] = None,
  gcp_service_account: Annotated[str, typer.Option('--gcp-service-account', help='Service Account Name',
                                                   rich_help_panel="GCP Options")] = 'abstrakt-svc',
  kac: Annotated[bool, typer.Option('--kac',
                                    help='Install Kubernetes Admission Controller',
                                    rich_help_panel='CrowdStrike Kubernetes Admission Controller',
                                    show_default=False)] = False,
  kac_image_tag: Annotated[str, typer.Option('--kac-image-tag', help='KAC Image Tag | '
                                             'Example: 7.18.0-1603.container.x86_64.Release.US-1',
                                             rich_help_panel="CrowdStrike Kubernetes Admission Controller")] = 'latest',
  iar: Annotated[bool, typer.Option('--iar',
                                    help='Install Image Assessment at Runtime',
                                    rich_help_panel='CrowdStrike Image Assessment at Runtime',
                                    show_default=False)] = False,
  iar_image_tag: Annotated[str, typer.Option('--iar-image-tag', help='IAR Image Tag | '
                                                                     'Example: 1.0.9',
                                             rich_help_panel="CrowdStrike Image Assessment at Runtime")] = 'latest',
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

  manager = CrowdStrikeSensorInstallOperationsManager(falcon_sensor=falcon_sensor,
                                                      registry=registry,
                                                      repository=repository,
                                                      sensor_image_tag=sensor_image_tag,
                                                      aws_cluster=aws_cluster,
                                                      aws_region=aws_region,
                                                      aws_ecr_iam_policy=aws_ecr_iam_policy,
                                                      aws_sensor_iam_role=aws_sensor_iam_role,
                                                      aws_kac_iam_role=aws_kac_iam_role,
                                                      aws_iar_iam_role=aws_iar_iam_role,
                                                      az_cluster=az_cluster,
                                                      az_resource_group=az_resource_group,
                                                      az_location=az_location,
                                                      az_acr_resource_group=az_acr_resource_group,
                                                      az_sp_name=az_sp_name,
                                                      az_sp_pass=az_sp_pass,
                                                      az_acr_sub_id=az_acr_sub_id,
                                                      gcp_cluster=gcp_cluster,
                                                      gcp_network=gcp_network,
                                                      gcp_project_id=gcp_project_id,
                                                      gcp_service_account=gcp_service_account,
                                                      kac=kac,
                                                      kac_image_tag=kac_image_tag,
                                                      iar=iar,
                                                      iar_image_tag=iar_image_tag,
                                                      falcon_client_id=falcon_client_id,
                                                      falcon_client_secret=falcon_client_secret,
                                                      logger=crwd_sensor_logger)

  manager.start_crowdstrike_upgrade_operations()
