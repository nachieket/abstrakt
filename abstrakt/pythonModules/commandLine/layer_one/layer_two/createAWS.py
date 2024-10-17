import typer
import pytz

from datetime import datetime
from typing_extensions import Annotated

from abstrakt.pythonModules.customLogging.customLogging import CustomLogger
from abstrakt.pythonModules.opsManager._AWSClusterOperationsManager import (_AWSDaemonsetOperationsManager,
                                                                            _AWSSidecarOperationsManager)

uk_timezone = pytz.timezone('Europe/London')
uk_time = datetime.now(uk_timezone)
uk_time_str = uk_time.strftime('%d%m%Y')

create_aws_app = typer.Typer()


@create_aws_app.command(help='EKS Managed Node Cluster', rich_help_panel="AWS Kubernetes Clusters")
def eks_managed_node(
  config_file: Annotated[str, typer.Option(help='Cluster Configuration File', show_default=True,
                                           rich_help_panel='EKS Configuration'
                                           )] = './abstrakt/conf/aws/eks/eks-managed-node.conf',
  cluster_name: Annotated[str, typer.Option('--cluster-name',
                                            help='Cluster Name', show_default=False,
                                            rich_help_panel="EKS Configuration")] = None,
  vpc_name: Annotated[str, typer.Option('--vpc-name', help='VPC Name', show_default=False,
                                        rich_help_panel="EKS Configuration")] = None,
  region: Annotated[str, typer.Option('--region', help='Cluster Region', show_default=False,
                                      rich_help_panel="EKS Configuration")] = None,
  asset_tags: Annotated[str, typer.Option('--asset-tags', help='Asset Tags | Example - "POV=CRWD,App=Abstrakt"',
                                          show_default=False, rich_help_panel="EKS Configuration")] = None,
  install_falcon_sensor: Annotated[bool, typer.Option('--install-falcon-sensor',
                                                      help='Install Falcon Sensor', show_default=False,
                                                      rich_help_panel='CrowdStrike EDR Sensor')] = False,
  kernel_mode: Annotated[bool, typer.Option('--kernel-mode', help='Install Falcon Sensor in Kernel mode',
                                            show_default=False,
                                            rich_help_panel='CrowdStrike EDR Sensor Options')] = False,
  ebpf_mode: Annotated[bool, typer.Option('--ebpf-mode', help='Install Falcon Sensor in ebpf mode',
                                          show_default=False,
                                          rich_help_panel='CrowdStrike EDR Sensor Options')] = True,
  registry: Annotated[str, typer.Option('--registry', help='Image Registry for all Images | '
                                        'Example: 123456789012.dkr.ecr.eu-west-2.amazonaws.com',
                                        show_default=False,
                                        rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  repository: Annotated[str, typer.Option('--repository', help='Image Repository for all Images | '
                                          'Example: abstrakt', show_default=False,
                                          rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  sensor_image_tag: Annotated[str, typer.Option('--sensor-image-tag', help='Falcon Sensor Image Tag | '
                                                'Example: 7.10.0-16303-1.falcon-linux.x86_64.Release.US-1',
                                                rich_help_panel="CrowdStrike EDR Sensor Options")] = 'latest',
  proxy_server: Annotated[str, typer.Option('--proxy-server', help='Proxy Server IP or FQDN | '
                                            'Example: 10.10.10.10 OR proxy.internal.com',
                                            show_default=False,
                                            rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  proxy_port: Annotated[int, typer.Option('--proxy-port', help='Proxy Server Port | Example: 8080',
                                          rich_help_panel="CrowdStrike EDR Sensor Options")] = 3128,
  sensor_tags: Annotated[str, typer.Option('--sensor-tags', help='Falcon Sensor Tags | Example: Tag1,Tag2',
                                           show_default=True,
                                           rich_help_panel="CrowdStrike EDR Sensor Options")] = 'CRWD,POV,'
                                                                                                'EKS-MANAGED-NODE,'
                                                                                                'ABSTRAKT',
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
                                                show_default=False, rich_help_panel='CrowdStrike API Keys')] = None,
  falcon_client_secret: Annotated[str, typer.Option('--falcon-client-secret',
                                                    help='Client Secret to Install Falcon Sensor | Example: QWERT',
                                                    show_default=False, rich_help_panel='CrowdStrike API Keys')] = None,
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
  generate_misconfigurations: Annotated[bool, typer.Option('--generate-misconfigs',
                                                           help='Generate Misconfigurations',
                                                           show_default=False,
                                                           rich_help_panel='CrowdStrike Artificial '
                                                           'Detections Generator')] = False,
):
  eks_managed_node_log_filename = f'/var/log/crowdstrike/aws/eks-managed-node-{uk_time_str}.log'
  eks_managed_node_logger = CustomLogger('eks_managed_node', eks_managed_node_log_filename).logger

  manager = _AWSDaemonsetOperationsManager(config_file=config_file,
                                           cluster_name=cluster_name,
                                           vpc_name=vpc_name,
                                           asset_tags=asset_tags,
                                           region=region,
                                           install_falcon_sensor=install_falcon_sensor,
                                           registry=registry,
                                           repository=repository,
                                           sensor_image_tag=sensor_image_tag,
                                           kernel_mode=kernel_mode,
                                           ebpf_mode=ebpf_mode,
                                           falcon_client_id=falcon_client_id,
                                           falcon_client_secret=falcon_client_secret,
                                           proxy_server=proxy_server,
                                           proxy_port=proxy_port,
                                           sensor_tags=sensor_tags,
                                           install_kpa=install_kpa,
                                           install_kac=install_kac,
                                           kac_image_tag=kac_image_tag,
                                           install_iar=install_iar,
                                           iar_image_tag=iar_image_tag,
                                           install_detections_container=install_detections_container,
                                           install_vulnerable_apps=install_vulnerable_apps,
                                           generate_misconfigs=generate_misconfigurations,
                                           cloud_type='aws',
                                           cluster_type='eks-managed-node',
                                           logger=eks_managed_node_logger
                                           )

  manager.start_cluster_operations()


@create_aws_app.command(help='EKS Fargate Cluster', rich_help_panel="AWS Kubernetes Clusters")
def eks_fargate(
  config_file: Annotated[str, typer.Option(help='Cluster Configuration File', show_default=True,
                                           rich_help_panel="EKS Configuration"
                                           )] = './abstrakt/conf/aws/eks/eks-fargate.conf',
  cluster_name: Annotated[str, typer.Option('--cluster-name',
                                            help='Cluster Name', show_default=False,
                                            rich_help_panel="EKS Configuration")] = None,
  vpc_name: Annotated[str, typer.Option('--vpc-name', help='VPC Name', show_default=False,
                                        rich_help_panel="EKS Configuration")] = None,
  region: Annotated[str, typer.Option('--region', help='Cluster Region', show_default=False,
                                      rich_help_panel="EKS Configuration")] = None,
  assets_tags: Annotated[str, typer.Option('--asset-tags', help='Asset Tags', show_default=False,
                                           rich_help_panel="EKS Configuration")] = None,
  install_falcon_sensor: Annotated[bool, typer.Option('--install-falcon-sensor',
                                                      help='Install Falcon Sensor',
                                                      show_default=False,
                                                      rich_help_panel='CrowdStrike EDR Sensor')] = False,
  registry: Annotated[str, typer.Option('--registry', help='Image Repository for all Images | '
                                        'Example: 123456789012.dkr.ecr.eu-west-2.amazonaws.com',
                                        show_default=False,
                                        rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  repository: Annotated[str, typer.Option('--repository', help='Image Repository for all Images | '
                                          'Example: abstrakt',
                                          show_default=False,
                                          rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  sensor_image_tag: Annotated[str, typer.Option('--sensor-image-tag', help='Falcon Sensor Image Tag | '
                                                'Example: 7.10.0-16303-1.falcon-linux.x86_64.Release.US-1',
                                                rich_help_panel="CrowdStrike EDR Sensor Options")] = 'latest',
  monitor_namespaces: Annotated[str, typer.Option('--monitor-namespaces',
                                                  help='Namespaces to monitor to inject falcon sensor '
                                                       '| Example: All or ns1,ns2,ns3',
                                                  show_default=False,
                                                  rich_help_panel='CrowdStrike EDR Sensor Options')] = 'All',
  exclude_namespaces: Annotated[str, typer.Option('--exclude-namespaces',
                                                  help='Namespaces to exclude from falcon sensor injection '
                                                       '| Example: ns1,ns2,ns3',
                                                  show_default=False,
                                                  rich_help_panel='CrowdStrike EDR Sensor Options')] = None,
  proxy_server: Annotated[str, typer.Option('--proxy-server', help='Proxy Server IP or FQDN | '
                                                                   'Example: 10.10.10.10 OR proxy.internal.com',
                                            show_default=False,
                                            rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  proxy_port: Annotated[int, typer.Option('--proxy-port', help='Proxy Server Port | Example: 8080',
                                          rich_help_panel="CrowdStrike EDR Sensor Options")] = 3128,
  sensor_tags: Annotated[str, typer.Option('--sensor-tags',
                                           help='Falcon Sensor Tags | Example: Tag1,Tag2', show_default=False,
                                           rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  install_kac: Annotated[bool, typer.Option('--install-kac',
                                            help='Install Kubernetes Admission Controller', show_default=False,
                                            rich_help_panel="CrowdStrike Kubernetes Admission Controller")] = False,
  kac_image_tag: Annotated[str, typer.Option('--kac-image-tag', help='KAC Image Tag | '
                                             'Example: 7.18.0-1603.container.x86_64.Release.US-1',
                                             rich_help_panel="CrowdStrike Kubernetes Admission Controller")] = 'latest',
  install_iar: Annotated[bool, typer.Option('--install-iar',
                                            help='Install Image Assessment at Runtime', show_default=False,
                                            rich_help_panel='CrowdStrike Image Assessment at Runtime')] = False,
  iar_image_tag: Annotated[str, typer.Option('--iar-image-tag', help='IAR Image Tag | Example: 1.0.9',
                                             rich_help_panel="CrowdStrike Image Assessment at Runtime")] = 'latest',
  install_kpa: Annotated[bool, typer.Option('--install-kpa',
                                            help='Install Kubernetes Protection Agent',
                                            show_default=False,
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
                                                             show_default=False,
                                                             rich_help_panel='CrowdStrike Artificial '
                                                                             'Detections Generator')] = False,
  install_vulnerable_apps: Annotated[bool, typer.Option('--install-vulnerable-apps',
                                                        help='Install Vulnerable Apps', show_default=False,
                                                        rich_help_panel='CrowdStrike Artificial '
                                                                        'Detections Generator')] = False,
  generate_misconfigs: Annotated[bool, typer.Option('--generate-misconfigs',
                                                    help='Generate Misconfigurations', show_default=False,
                                                    rich_help_panel='CrowdStrike Artificial '
                                                    'Detections Generator')] = False,
  iam_policy: Annotated[str, typer.Option('--iam-policy', help='AWS IAM Policy Name',
                                          show_default=True,
                                          rich_help_panel='AWS Options')] = 'CrowdStrikeFalconContainerEcrPull',
  sensor_iam_role: Annotated[str, typer.Option('--sensor-iam-role', help='AWS IAM Role Name for Falcon Sensor',
                                               show_default=True,
                                               rich_help_panel='AWS Options')] = 'CrowdStrikeFalconContainerIAMRole',
  kac_iam_role: Annotated[str, typer.Option('--kac-iam-role', help='AWS IAM Role Name for KAC',
                                            show_default=True,
                                            rich_help_panel='AWS Options')] = 'CrowdStrikeKACIAMRole',
  iar_iam_role: Annotated[str, typer.Option('--ecr-iar-iam-role', help='AWS IAM Role Name for IAR',
                                            show_default=True, rich_help_panel='AWS Options')] = 'CrowdStrikeIARIAMRole'
):
  eks_fargate_log_filename = f'/var/log/crowdstrike/aws/eks-fargate-{uk_time_str}.log'
  eks_fargate_logger = CustomLogger('eks_fargate', eks_fargate_log_filename).logger

  manager = _AWSSidecarOperationsManager(config_file=config_file,
                                         cluster_name=cluster_name,
                                         region=region,
                                         vpc_name=vpc_name,
                                         asset_tags=assets_tags,
                                         install_falcon_sensor=install_falcon_sensor,
                                         registry=registry,
                                         repository=repository,
                                         sensor_image_tag=sensor_image_tag,
                                         falcon_client_id=falcon_client_id,
                                         falcon_client_secret=falcon_client_secret,
                                         monitor_namespaces=monitor_namespaces,
                                         exclude_namespaces=exclude_namespaces,
                                         proxy_server=proxy_server,
                                         proxy_port=proxy_port,
                                         sensor_tags=sensor_tags,
                                         install_kpa=install_kpa,
                                         install_kac=install_kac,
                                         kac_image_tag=kac_image_tag,
                                         install_iar=install_iar,
                                         iar_image_tag=iar_image_tag,
                                         install_detections_container=install_detections_container,
                                         install_vulnerable_apps=install_vulnerable_apps,
                                         generate_misconfigs=generate_misconfigs,
                                         cloud_type='aws',
                                         cluster_type='eks-fargate',
                                         logger=eks_fargate_logger,
                                         iam_policy=iam_policy,
                                         sensor_iam_role=sensor_iam_role,
                                         kac_iam_role=kac_iam_role,
                                         iar_iam_role=iar_iam_role)

  manager.start_cluster_operations()


# @create_aws_app.command(help='ECS Fargate Cluster', rich_help_panel="AWS Kubernetes Clusters")
# def ecs_fargate(
#   config_file: Annotated[str, typer.Option(help='(Cluster Configuration File', show_default=True,
#                                            rich_help_panel="ECS Fargate Configuration File"
#                                            )] = './abstrakt/conf/aws/ecs/ecs-fargate.conf',
# ):
#   ecs_fargate_log_filename = f'/var/log/crowdstrike/aws/ecs-fargate-{uk_time_str}.log'
#   ecs_fargate_logger = CustomLogger('ecs_fargate', ecs_fargate_log_filename).logger
#
#   manager = AWSClusterOperationsManager(config_file=config_file,
#                                         cloud_type='aws',
#                                         cluster_type='ecs-fargate',
#                                         logger=ecs_fargate_logger)
#
#   manager.start_cluster_operations()
#
#
# @create_aws_app.command(help='ECS EC2 Cluster', rich_help_panel="AWS Kubernetes Clusters")
# def ecs_ec2(
#   config_file: Annotated[str, typer.Option(help='(Cluster Configuration File', show_default=True,
#                                            rich_help_panel="ECS with EC2 Configuration File"
#                                            )] = './abstrakt/conf/aws/ecs/ecs-ec2.conf',
# ):
#   ecs_ec2_log_filename = f'/var/log/crowdstrike/aws/ecs-ec2-{uk_time_str}.log'
#   ecs_ec2_logger = CustomLogger('ecs_ec2', ecs_ec2_log_filename).logger
#
#   manager = AWSClusterOperationsManager(config_file=config_file,
#                                         cloud_type='aws',
#                                         cluster_type='ecs-ec2',
#                                         logger=ecs_ec2_logger)
#
#   manager.start_cluster_operations()
