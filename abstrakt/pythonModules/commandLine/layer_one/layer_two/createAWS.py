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


@create_aws_app.command(help='Install EKS Managed Node Cluster', rich_help_panel="AWS Kubernetes Clusters")
def eks_managed_node(
  config_file: Annotated[str, typer.Option(help='Cluster Configuration File', show_default=True,
                                           rich_help_panel="EKS Managed Node Configuration File"
                                           )] = './abstrakt/conf/aws/eks/eks-managed-node.conf',
  install_falcon_sensor: Annotated[bool, typer.Option('--install-falcon-sensor',
                                                      help='Install Falcon Sensor -> Requires: '
                                                           '--kernel-mode OR --ebpf-mode, '
                                                           '--falcon-client-id, '
                                                           '--falcon-client-secret, '
                                                           '--falcon-cid, '
                                                           '--falcon-cloud-region, '
                                                           '--falcon-api), '
                                                           '(Optional: --proxy-server, '
                                                           '--proxy-port '
                                                           '--falcon-sensor-tags',
                                                      rich_help_panel="CrowdStrike EDR Sensor")] = False,
  kernel_mode: Annotated[bool, typer.Option('--kernel-mode', help='Install Falcon Sensor in Kernel mode',
                                            rich_help_panel="CrowdStrike EDR Sensor Options")] = False,
  ebpf_mode: Annotated[bool, typer.Option('--ebpf-mode', help='Install Falcon Sensor in ebpf mode',
                                          rich_help_panel="CrowdStrike EDR Sensor Options")] = False,
  falcon_client_id: Annotated[str, typer.Option('--falcon-client-id',
                                                help='Client ID to Install Falcon Sensor | Example: QWERT',
                                                rich_help_panel='CrowdStrike EDR Sensor Options')] = None,
  falcon_client_secret: Annotated[str, typer.Option('--falcon-client-secret',
                                                    help='Client Secret to Install Falcon Sensor | Example: QWERT',
                                                    rich_help_panel='CrowdStrike EDR Sensor Options')] = None,
  falcon_cid: Annotated[str, typer.Option('--falcon-cid',
                                          help='Customer ID to install Falcon Sensor |  Example: QWERT-AB',
                                          rich_help_panel='CrowdStrike EDR Sensor Options')] = None,
  falcon_cloud_region: Annotated[str, typer.Option('--falcon-cloud-region',
                                                   help='Falcon Cloud Region: us-1, us-2, eu-1',
                                                   rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
  falcon_api: Annotated[str, typer.Option('--falcon-api',
                                          help='Possible Values: api.crowdstrike.com (us-1), '
                                               'api.us-2.crowdstrike.com (us-2), '
                                               'api.eu-1.crowdstrike.com (eu-1)',
                                          rich_help_panel="CrowdStrike EDR Sensor Options")] = None,
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
                                            rich_help_panel="CrowdStrike Kubernetes Agents")] = False,
  install_kac: Annotated[bool, typer.Option('--install-kac',
                                            help='Install Kubernetes Admission Controller',
                                            rich_help_panel="CrowdStrike Kubernetes Agents")] = False,
  install_detections_container: Annotated[bool, typer.Option('--install-detections-container',
                                                             help='Install CrowdStrike Detections Container',
                                                             rich_help_panel="CrowdStrike Artificial "
                                                                             "Detections Generator")] = False,
  # install_vulnerable_apps: Annotated[bool, typer.Option('--install-vulnerable-apps',
  #                                                       help='Install Vulnerable Applications')] = False,
  # install_load_test_apps: Annotated[bool, typer.Option('--install-load-test-apps',
  #                                                      help='Install Load Test Applications',
  #                                                      rich_help_panel="Generic Load Test Apps")] = False
):
  eks_managed_node_log_filename = f'/var/logs/crowdstrike/aws/eks/eks-managed-node-{uk_time_str}.log'
  managed_node_logger = CustomLogger('eks_managed_node', eks_managed_node_log_filename).logger

  manager = ClusterOperationsManager(config_file=config_file,
                                     install_falcon_sensor=install_falcon_sensor,
                                     kernel_mode=kernel_mode,
                                     ebpf_mode=ebpf_mode,
                                     falcon_client_id=falcon_client_id,
                                     falcon_client_secret=falcon_client_secret,
                                     falcon_cid=falcon_cid,
                                     falcon_cloud_region=falcon_cloud_region,
                                     falcon_api=falcon_api,
                                     proxy_server=proxy_server,
                                     proxy_port=proxy_port,
                                     falcon_sensor_tags=falcon_sensor_tags,
                                     install_kpa=install_kpa,
                                     install_kac=install_kac,
                                     install_detections_container=install_detections_container,
                                     cloud_type='aws',
                                     cluster_type='eks-managed-node',
                                     logger=managed_node_logger)

  manager.start_cluster_operations()


@create_aws_app.command(help='Install EKS Fargate Cluster', rich_help_panel="AWS Kubernetes Clusters")
def eks_fargate(
  config_file: Annotated[str, typer.Option(help='(Cluster Configuration File', show_default=True,
                                           rich_help_panel="EKS Fargate Configuration File"
                                           )] = './abstrakt/conf/aws/eks/eks-fargate.conf',
  install_falcon_sensor: Annotated[bool, typer.Option('--install-falcon-sensor',
                                                      help='Install Falcon Sensor -> (Requires: '
                                                           '--falcon-client-id, '
                                                           '--falcon-client-secret, '
                                                           '--falcon-cid, '
                                                           '--falcon-cloud-region, '
                                                           '--falcon-api), '
                                                           '(Optional: --proxy-server, '
                                                           '--proxy-port '
                                                           '--falcon-sensor-tags',
                                                      rich_help_panel='CrowdStrike EDR Sensor')] = False,
  falcon_client_id: Annotated[str, typer.Option('--falcon-client-id',
                                                help='Client ID to Install Falcon Sensor | Example: QWERT',
                                                rich_help_panel='CrowdStrike EDR Sensor Options')] = None,
  falcon_client_secret: Annotated[str, typer.Option('--falcon-client-secret',
                                                    help='Client Secret to Install Falcon Sensor | Example: QWERT',
                                                    rich_help_panel='CrowdStrike EDR Sensor Options')] = None,
  falcon_cid: Annotated[str, typer.Option('--falcon-cid',
                                          help='Customer ID to install Falcon Sensor |  Example: QWERT-AB',
                                          rich_help_panel='CrowdStrike EDR Sensor Options')] = None,
  falcon_cloud_region: Annotated[str, typer.Option('--falcon-cloud-region',
                                                   help='Falcon Cloud Region: us-1, us-2, eu-1',
                                                   rich_help_panel='CrowdStrike EDR Sensor Options')] = None,
  falcon_api: Annotated[str, typer.Option('--falcon-api',
                                          help='Possible Values: api.crowdstrike.com (us-1), '
                                               'api.us-2.crowdstrike.com (us-2), '
                                               'api.eu-1.crowdstrike.com (eu-1)',
                                          rich_help_panel='CrowdStrike EDR Sensor Options')] = None,
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
  install_kpa: Annotated[bool, typer.Option('--install-kpa',
                                            help='Install Kubernetes Protection Agent',
                                            rich_help_panel='CrowdStrike Kubernetes Agents')] = False,
  install_kac: Annotated[bool, typer.Option('--install-kac',
                                            help='Install Kubernetes Admission Controller',
                                            rich_help_panel="CrowdStrike Kubernetes Agents")] = False,
  install_detections_container: Annotated[bool, typer.Option('--install-detections-container',
                                                             help='Install CrowdStrike Detections Container',
                                                             rich_help_panel='CrowdStrike Kubernetes Agents')] = False
):
  # TODO: Automate KPA via API
  # TODO: Check KAC on EKS Fargate

  eks_fargate_log_filename = f'/var/logs/crowdstrike/aws/eks/eks-fargate-{uk_time_str}.log'
  eks_fargate_logger = CustomLogger('eks_fargate', eks_fargate_log_filename).logger

  manager = ClusterOperationsManager(config_file=config_file,
                                     install_falcon_sensor=install_falcon_sensor,
                                     falcon_client_id=falcon_client_id,
                                     falcon_client_secret=falcon_client_secret,
                                     falcon_cid=falcon_cid,
                                     falcon_cloud_region=falcon_cloud_region,
                                     falcon_api=falcon_api,
                                     monitor_namespaces=monitor_namespaces,
                                     exclude_namespaces=exclude_namespaces,
                                     proxy_server=proxy_server,
                                     proxy_port=proxy_port,
                                     falcon_sensor_tags=falcon_sensor_tags,
                                     install_kpa=install_kpa,
                                     install_kac=install_kac,
                                     install_detections_container=install_detections_container,
                                     cloud_type='aws',
                                     cluster_type='eks-fargate',
                                     logger=eks_fargate_logger)

  manager.start_cluster_operations()


@create_aws_app.command(help='Install ECS Fargate Cluster', rich_help_panel="AWS Kubernetes Clusters")
def ecs_fargate(
  config_file: Annotated[str, typer.Option(help='(Cluster Configuration File', show_default=True,
                                           rich_help_panel="ECS Fargate Configuration File"
                                           )] = './abstrakt/conf/aws/ecs/ecs-fargate.conf',
):
  ecs_fargate_log_filename = f'/var/logs/crowdstrike/aws/ecs/ecs-fargate-{uk_time_str}.log'
  ecs_fargate_logger = CustomLogger('ecs_fargate', ecs_fargate_log_filename).logger

  manager = ClusterOperationsManager(config_file=config_file,
                                     cloud_type='aws',
                                     cluster_type='ecs-fargate',
                                     logger=ecs_fargate_logger)

  manager.start_cluster_operations()


@create_aws_app.command(help='Install ECS with EC2 Cluster', rich_help_panel="AWS Kubernetes Clusters")
def ecs_with_ec2(
  config_file: Annotated[str, typer.Option(help='(Cluster Configuration File', show_default=True,
                                           rich_help_panel="ECS with EC2 Configuration File"
                                           )] = './abstrakt/conf/aws/ecs/ecs-ec2.conf',
):
  ecs_ec2_log_filename = f'/var/logs/crowdstrike/aws/ecs/ecs-ec2-{uk_time_str}.log'
  ecs_ec2_logger = CustomLogger('ecs_ec2', ecs_ec2_log_filename).logger

  manager = ClusterOperationsManager(config_file=config_file,
                                     cloud_type='aws',
                                     cluster_type='ecs-ec2',
                                     logger=ecs_ec2_logger)

  manager.start_cluster_operations()
