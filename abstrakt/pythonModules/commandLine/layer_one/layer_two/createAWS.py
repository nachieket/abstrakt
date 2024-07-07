import typer
import pytz

from datetime import datetime
from typing_extensions import Annotated

from abstrakt.pythonModules.opsManager.clusterOpsManager import ClusterOperationsManager
from abstrakt.pythonModules.customLogging.customLogging import CustomLogger

uk_timezone = pytz.timezone('Europe/London')
uk_time = datetime.now(uk_timezone)
uk_time_str = uk_time.strftime('%d%m%Y')

create_aws_app = typer.Typer()

eks_managed_node_help_message = """
Install EKS Managed Node Cluster\n
_                              _\n\n\n

Example Usages:\n\n
abstrakt create aws eks-managed-node --install-falcon-sensor --kernel-mode --install-kpa --install-kac --install-iar
--install-detections-container --install-vulnerable-apps --falcon-client-id 3af74117
--falcon-client-secret vlTpn372s\n
abstrakt create aws eks-managed-node --install-falcon-sensor --kernel-mode --proxy-server 10.10.10.11 --proxy-port 
8080 --falcon-sensor-tags tag1,tag2  --install-kpa --install-kac --install-iar --install-detections-container 
--install-vulnerable-apps --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n\n

Examples with Falcon Image Tag:\n
abstrakt create aws eks-managed-node --install-falcon-sensor --falcon-image-tag 
7.10.0-16303-1.falcon-linux.x86_64.Release.US-1 --kernel-mode --install-kpa --install-kac --install-iar
--install-detections-container --install-vulnerable-apps --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n
abstrakt create aws eks-managed-node --install-falcon-sensor --falcon-image-tag 
7.10.0-16303-1.falcon-linux.x86_64.Release.US-1 --kernel-mode --proxy-server 10.10.10.11 --proxy-port  8080 
--falcon-sensor-tags tag1,tag2 --install-kpa --install-kac --install-iar --install-detections-container 
--install-vulnerable-apps --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n\n

Other Examples:\n
abstrakt create aws eks-managed-node --install-falcon-sensor --kernel-mode --falcon-client-id 3af74117
--falcon-client-secret vlTpn372s\n
abstrakt create aws eks-managed-node --install-kpa --falcon-client-id 3af74117
--falcon-client-secret vlTpn372s\n
abstrakt create aws eks-managed-node --install-kac --falcon-client-id 3af74117
--falcon-client-secret vlTpn372s\n
abstrakt create aws eks-managed-node --install-iar --falcon-client-id 3af74117
--falcon-client-secret vlTpn372s\n
abstrakt create aws eks-managed-node --install-detections-container\n
abstrakt create aws eks-managed-node --install-vulnerable-apps\n"""


@create_aws_app.command(help=eks_managed_node_help_message, rich_help_panel="AWS Kubernetes Clusters")
def eks_managed_node(
  config_file: Annotated[str, typer.Option(help='Cluster Configuration File', show_default=True,
                                           rich_help_panel='AKS Configuration File'
                                           )] = './abstrakt/conf/aws/eks/eks-managed-node.conf',
  install_falcon_sensor: Annotated[bool, typer.Option('--install-falcon-sensor',
                                                      help='Install Falcon Sensor',
                                                      rich_help_panel='CrowdStrike EDR Sensor')] = False,
  falcon_image_repo: Annotated[str, typer.Option('--falcon-image-repo', help='Falcon Sensor Image Repository | '
                                                 'Example: 123456789012.dkr.ecr.eu-west-2.amazonaws.com/ecr',
                                                 rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  falcon_image_tag: Annotated[str, typer.Option('--falcon-image-tag', help='Falcon Sensor Image Tag | '
                                                'Example: 7.10.0-16303-1.falcon-linux.x86_64.Release.US-1',
                                                rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  kernel_mode: Annotated[bool, typer.Option('--kernel-mode', help='Install Falcon Sensor in Kernel mode',
                                            rich_help_panel='CrowdStrike EDR Sensor Options')] = False,
  ebpf_mode: Annotated[bool, typer.Option('--ebpf-mode', help='Install Falcon Sensor in ebpf mode',
                                          rich_help_panel='CrowdStrike EDR Sensor Options')] = False,
  proxy_server: Annotated[str, typer.Option('--proxy-server', help='Proxy Server IP or FQDN | '
                                                                   'Example: 10.10.10.10 OR proxy.internal.com',
                                            rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  proxy_port: Annotated[str, typer.Option('--proxy-port', help='Proxy Server Port | Example: 8080',
                                          rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  falcon_sensor_tags: Annotated[str, typer.Option('--falcon-sensor-tags', help='Falcon Sensor Tags | '
                                                                               'Example: Tag1,Tag2',
                                                  rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  falcon_client_id: Annotated[str, typer.Option('--falcon-client-id',
                                                help='Client ID to Install Falcon Sensor | Example: QWERT',
                                                rich_help_panel='CrowdStrike API Keys')] = None,
  falcon_client_secret: Annotated[str, typer.Option('--falcon-client-secret',
                                                    help='Client Secret to Install Falcon Sensor | Example: QWERT',
                                                    rich_help_panel='CrowdStrike API Keys')] = None,
  install_kpa: Annotated[bool, typer.Option('--install-kpa',
                                            help='Install Kubernetes Protection Agent',
                                            rich_help_panel='CrowdStrike Kubernetes Agents')] = False,
  install_kac: Annotated[bool, typer.Option('--install-kac',
                                            help='Install Kubernetes Admission Controller',
                                            rich_help_panel='CrowdStrike Kubernetes Agents')] = False,
  install_iar: Annotated[bool, typer.Option('--install-iar',
                                            help='Install Image Assessment at Runtime',
                                            rich_help_panel='CrowdStrike Kubernetes Agents')] = False,
  install_detections_container: Annotated[bool, typer.Option('--install-detections-container',
                                                             help='Install CrowdStrike Detections Container',
                                                             rich_help_panel='CrowdStrike Artificial '
                                                                             'Detections Generator')] = False,
  install_vulnerable_apps: Annotated[bool, typer.Option('--install-vulnerable-apps',
                                                        help='Install Vulnerable Apps',
                                                        rich_help_panel='CrowdStrike Artificial '
                                                                        'Detections Generator')] = False,
):
  eks_managed_node_log_filename = f'/var/log/crowdstrike/aws/eks-managed-node-{uk_time_str}.log'
  eks_managed_node_logger = CustomLogger('eks_managed_node', eks_managed_node_log_filename).logger

  manager = ClusterOperationsManager(config_file=config_file,
                                     install_falcon_sensor=install_falcon_sensor,
                                     falcon_image_repo=falcon_image_repo,
                                     falcon_image_tag=falcon_image_tag,
                                     kernel_mode=kernel_mode,
                                     ebpf_mode=ebpf_mode,
                                     falcon_client_id=falcon_client_id,
                                     falcon_client_secret=falcon_client_secret,
                                     proxy_server=proxy_server,
                                     proxy_port=proxy_port,
                                     falcon_sensor_tags=falcon_sensor_tags,
                                     install_kpa=install_kpa,
                                     install_kac=install_kac,
                                     install_iar=install_iar,
                                     install_detections_container=install_detections_container,
                                     install_vulnerable_apps=install_vulnerable_apps,
                                     cloud_type='aws',
                                     cluster_type='eks-managed-node',
                                     logger=eks_managed_node_logger)

  manager.start_cluster_operations()


eks_fargate_help_message = """
Install EKS Fargate Cluster\n
_                         _\n\n

Example Usages:\n\n
abstrakt create aws eks-fargate --install-falcon-sensor --install-kpa --install-kac --install-iar
--install-detections-container --install-vulnerable-apps --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n
abstrakt create aws eks-fargate --install-falcon-sensor --proxy-server 10.10.10.11 --proxy-port 8080 
--falcon-sensor-tags tag1,tag2  --install-kpa --install-kac --install-iar --install-detections-container 
--install-vulnerable-apps --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n\n

Examples with Monitored/Excluded Namespaces:\n
abstrakt create aws eks-fargate --install-falcon-sensor --monitor-namespaces ns1,ns2,ns4,ns5 --falcon-sensor-tags 
tag1,tag2 --install-kpa --install-kac  --install-iar --install-detections-container --install-vulnerable-apps 
--falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n
abstrakt create aws eks-fargate --install-falcon-sensor --monitor-namespaces all --exclude-namespaces ns1,
ns2 --falcon-sensor-tags tag1,tag2  --install-kpa --install-kac  --install-iar --install-detections-container 
--install-vulnerable-apps --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s\n\n

Examples with Falcon Image Tag:\n
abstrakt create aws eks-fargate --install-falcon-sensor --monitor-namespaces ns1,ns2,ns4,ns5 --falcon-image-tag 
7.10.0-16303-1.falcon-linux.x86_64.Release.US-1 --falcon-sensor-tags tag1,tag2 --install-kpa --install-kac 
--install-iar --install-detections-container --install-vulnerable-apps --falcon-client-id 3af74117 
--falcon-client-secret vlTpn372s\n
abstrakt create aws eks-fargate --install-falcon-sensor --monitor-namespaces all --exclude-namespaces ns1,
ns2 --falcon-image-tag  7.10.0-16303-1.falcon-linux.x86_64.Release.US-1 --falcon-sensor-tags tag1,tag2 --install-kpa 
--install-kac --install-iar --install-detections-container --install-vulnerable-apps --falcon-client-id 3af74117 
--falcon-client-secret vlTpn372s\n\n

Other Examples:\n
abstrakt create aws eks-fargate --install-falcon-sensor --kernel-mode --falcon-client-id 3af74117
--falcon-client-secret vlTpn372s\n
abstrakt create aws eks-fargate --install-kpa --falcon-client-id 3af74117
--falcon-client-secret vlTpn372s\n
abstrakt create aws eks-fargate --install-kac --falcon-client-id 3af74117
--falcon-client-secret vlTpn372s\n
abstrakt create aws eks-fargate --install-iar --falcon-client-id 3af74117
--falcon-client-secret vlTpn372s\n
abstrakt create aws eks-fargate --install-detections-container\n
abstrakt create aws eks-fargate --install-vulnerable-apps\n"""


@create_aws_app.command(help=eks_fargate_help_message, rich_help_panel="AWS Kubernetes Clusters")
def eks_fargate(
  config_file: Annotated[str, typer.Option(help='Cluster Configuration File', show_default=True,
                                           rich_help_panel="EKS Fargate Configuration File"
                                           )] = './abstrakt/conf/aws/eks/eks-fargate.conf',
  install_falcon_sensor: Annotated[bool, typer.Option('--install-falcon-sensor',
                                                      help='Install Falcon Sensor',
                                                      rich_help_panel='CrowdStrike EDR Sensor')] = False,
  falcon_image_repo: Annotated[str, typer.Option('--falcon-image-repo', help='Falcon Sensor Image Repository | '
                                                 'Example: 123456789012.dkr.ecr.eu-west-2.amazonaws.com/ecr',
                                                 rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  falcon_image_tag: Annotated[str, typer.Option('--falcon-image-tag', help='Falcon Sensor Image Tag | '
                                                'Example: 7.10.0-16303-1.falcon-linux.x86_64.Release.US-1',
                                                rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  monitor_namespaces: Annotated[str, typer.Option('--monitor-namespaces',
                                                  help='Namespaces to monitor to inject falcon sensor '
                                                       '| Example: All or ns1,ns2,ns3',
                                                  rich_help_panel='CrowdStrike EDR Sensor Options')] = 'All',
  exclude_namespaces: Annotated[str, typer.Option('--exclude-namespaces',
                                                  help='Namespaces to exclude from falcon sensor injection '
                                                       '| Example: ns1,ns2,ns3',
                                                  rich_help_panel='CrowdStrike EDR Sensor Options')] = None,
  proxy_server: Annotated[str, typer.Option('--proxy-server', help='Proxy Server IP or FQDN | '
                                                                   'Example: 10.10.10.10 OR proxy.internal.com',
                                            rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  proxy_port: Annotated[str, typer.Option('--proxy-port', help='Proxy Server Port | Example: 8080',
                                          rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  falcon_sensor_tags: Annotated[str, typer.Option('--falcon-sensor-tags',
                                                  help='Falcon Sensor Tags | Example: Tag1,Tag2',
                                                  rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  falcon_client_id: Annotated[str, typer.Option('--falcon-client-id',
                                                help='Client ID to Install Falcon Sensor | Example: QWERT',
                                                rich_help_panel='CrowdStrike API Keys')] = None,
  falcon_client_secret: Annotated[str, typer.Option('--falcon-client-secret',
                                                    help='Client Secret to Install Falcon Sensor | Example: QWERT',
                                                    rich_help_panel='CrowdStrike API Keys')] = None,
  install_kpa: Annotated[bool, typer.Option('--install-kpa',
                                            help='Install Kubernetes Protection Agent',
                                            rich_help_panel='CrowdStrike Kubernetes Agents')] = False,
  install_kac: Annotated[bool, typer.Option('--install-kac',
                                            help='Install Kubernetes Admission Controller',
                                            rich_help_panel="CrowdStrike Kubernetes Agents")] = False,
  install_iar: Annotated[bool, typer.Option('--install-iar',
                                            help='Install Image Assessment at Runtime',
                                            rich_help_panel='CrowdStrike Kubernetes Agents')] = False,
  install_detections_container: Annotated[bool, typer.Option('--install-detections-container',
                                                             help='Install CrowdStrike Detections Container',
                                                             rich_help_panel='CrowdStrike Artificial '
                                                                             'Detections Generator')] = False,
  install_vulnerable_apps: Annotated[bool, typer.Option('--install-vulnerable-apps',
                                                        help='Install Vulnerable Apps',
                                                        rich_help_panel='CrowdStrike Artificial '
                                                                        'Detections Generator')] = False,
  ecr_iam_policy_name: Annotated[str, typer.Option('--ecr-iam-policy-name', help='AWS IAM Policy Name',
                                                   rich_help_panel='AWS Options')] = 'CrowdStrikeFalconContainerEcrPull',
  ecr_iam_role_name: Annotated[str, typer.Option('--ecr-iam-role-name', help='AWS IAM Role Name',
                                                 rich_help_panel='AWS Options')] = 'CrowdStrikeFalconContainerIAMRole'
):
  eks_fargate_log_filename = f'/var/log/crowdstrike/aws/eks-fargate-{uk_time_str}.log'
  eks_fargate_logger = CustomLogger('eks_fargate', eks_fargate_log_filename).logger

  manager = ClusterOperationsManager(config_file=config_file,
                                     install_falcon_sensor=install_falcon_sensor,
                                     falcon_image_repo=falcon_image_repo,
                                     falcon_image_tag=falcon_image_tag,
                                     falcon_client_id=falcon_client_id,
                                     falcon_client_secret=falcon_client_secret,
                                     monitor_namespaces=monitor_namespaces,
                                     exclude_namespaces=exclude_namespaces,
                                     proxy_server=proxy_server,
                                     proxy_port=proxy_port,
                                     falcon_sensor_tags=falcon_sensor_tags,
                                     install_kpa=install_kpa,
                                     install_kac=install_kac,
                                     install_iar=install_iar,
                                     install_detections_container=install_detections_container,
                                     install_vulnerable_apps=install_vulnerable_apps,
                                     cloud_type='aws',
                                     cluster_type='eks-fargate',
                                     logger=eks_fargate_logger,
                                     ecr_iam_policy_name=ecr_iam_policy_name,
                                     ecr_iam_role_name=ecr_iam_role_name)

  manager.start_cluster_operations()


ecs_fargate_help_message = """
Install ECS Fargate Cluster\n
_                              _\n\n\n

Example Usages:\n\n
abstrakt create aws ecs-fargate"""


@create_aws_app.command(help=ecs_fargate_help_message, rich_help_panel="AWS Kubernetes Clusters")
def ecs_fargate(
  config_file: Annotated[str, typer.Option(help='(Cluster Configuration File', show_default=True,
                                           rich_help_panel="ECS Fargate Configuration File"
                                           )] = './abstrakt/conf/aws/ecs/ecs-fargate.conf',
):
  ecs_fargate_log_filename = f'/var/log/crowdstrike/aws/ecs-fargate-{uk_time_str}.log'
  ecs_fargate_logger = CustomLogger('ecs_fargate', ecs_fargate_log_filename).logger

  manager = ClusterOperationsManager(config_file=config_file,
                                     cloud_type='aws',
                                     cluster_type='ecs-fargate',
                                     logger=ecs_fargate_logger)

  manager.start_cluster_operations()


ecs_ec2_help_message = """
Install ECS with EC2 Cluster\n
_                              _\n\n\n

Example Usages:\n\n
abstrakt create aws ecs-with-ec2"""


@create_aws_app.command(help=ecs_ec2_help_message, rich_help_panel="AWS Kubernetes Clusters")
def ecs_with_ec2(
  config_file: Annotated[str, typer.Option(help='(Cluster Configuration File', show_default=True,
                                           rich_help_panel="ECS with EC2 Configuration File"
                                           )] = './abstrakt/conf/aws/ecs/ecs-ec2.conf',
):
  ecs_ec2_log_filename = f'/var/log/crowdstrike/aws/ecs-ec2-{uk_time_str}.log'
  ecs_ec2_logger = CustomLogger('ecs_ec2', ecs_ec2_log_filename).logger

  manager = ClusterOperationsManager(config_file=config_file,
                                     cloud_type='aws',
                                     cluster_type='ecs-ec2',
                                     logger=ecs_ec2_logger)

  manager.start_cluster_operations()
