import time

from abstrakt.pythonModules.vendors.cloudServiceProviders.aws.eksManagedNode.eksManagedNode import EKSManagedNode
from abstrakt.pythonModules.vendors.cloudServiceProviders.aws.eksFargate.eksFargate import EKSFargate
from abstrakt.pythonModules.vendors.cloudServiceProviders.aws.ecsFargate.ecsFargate import ECSFargate
from abstrakt.pythonModules.vendors.cloudServiceProviders.aws.ecsEC2.ecsEC2 import ECSec2
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.aws.awsDaemonset.AWSFalconSensorDaemonset \
  import AWSFalconSensorDaemonset, AWSDaemonsetKAC, AWSDaemonsetIAR
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.aws.awsSidecar.AWSFalconSensorSidecar \
  import AWSFalconSensorSidecar, AWSSidecarKAC, AWSSidecarIAR
from abstrakt.pythonModules.opsManager.opsManager import ClusterOperationsManager


class AWSClusterOperationsManager(ClusterOperationsManager):
  def __init__(self, config_file: str = None,
               install_falcon_sensor: bool = None,
               image_registry: str = None,
               kernel_mode: bool = None,
               ebpf_mode: bool = None,
               sensor_image_tag: str = None,
               monitor_namespaces: str = None,
               exclude_namespaces: str = None,
               proxy_server: str = None,
               proxy_port: int = None,
               sensor_tags: str = None,
               install_kac: bool = None,
               kac_image_tag: str = None,
               install_iar: bool = None,
               iar_image_tag: str = None,
               install_kpa: bool = None,
               falcon_client_id: str = None,
               falcon_client_secret: str = None,
               install_detections_container: bool = None,
               install_vulnerable_apps: bool = None,
               generate_misconfigs: bool = None,
               cloud_type: str = None,
               cluster_type: str = None,
               logger=None,
               ecr_iam_policy: str = None,
               sensor_iam_role: str = None,
               kac_iam_role: str = None,
               iar_iam_role: str = None):
    super().__init__(config_file, install_falcon_sensor, image_registry, sensor_image_tag, proxy_server,
                     proxy_port, sensor_tags, install_kac, kac_image_tag, install_iar, iar_image_tag,
                     install_kpa, cloud_type, cluster_type, falcon_client_id, falcon_client_secret,
                     install_detections_container, install_vulnerable_apps, generate_misconfigs, logger)
    self.config_file: str = config_file
    self.install_falcon_sensor: bool = install_falcon_sensor
    self.image_registry: str = image_registry
    self.kernel_mode: bool = kernel_mode
    self.ebpf_mode: bool = ebpf_mode
    self.sensor_image_tag: str = sensor_image_tag
    self.monitor_namespaces: str = monitor_namespaces
    self.exclude_namespaces: str = exclude_namespaces
    self.proxy_server: str = proxy_server
    self.proxy_port: int = proxy_port
    self.sensor_tags: str = sensor_tags
    self.install_kac: bool = install_kac
    self.kac_image_tag: str = kac_image_tag
    self.install_iar: bool = install_iar
    self.iar_image_tag: str = iar_image_tag
    self.install_kpa: bool = install_kpa
    self.falcon_client_id: str = falcon_client_id
    self.falcon_client_secret: str = falcon_client_secret
    self.install_detections_container: bool = install_detections_container
    self.install_vulnerable_apps: bool = install_vulnerable_apps
    self.generate_misconfigs: bool = generate_misconfigs
    self.cloud_type: str = cloud_type
    self.cluster_type: str = cluster_type
    self.logger = logger
    self.ecr_iam_policy: str = ecr_iam_policy
    self.sensor_iam_role: str = sensor_iam_role
    self.kac_iam_role: str = kac_iam_role
    self.iar_iam_role: str = iar_iam_role

  def deploy_cluster(self) -> str:
    random_string = self.get_random_string()

    if self.cluster_type == 'eks-managed-node':
      managed_node = EKSManagedNode(logger=self.logger)
      eks_managed_node_cluster_name = managed_node.deploy_eks_managed_node_cluster(random_string=random_string,
                                                                                   config_file=self.config_file)

      return eks_managed_node_cluster_name
    elif self.cluster_type == 'eks-fargate':
      eks_fargate = EKSFargate(logger=self.logger)
      eks_fargate_cluster_name = eks_fargate.deploy_eks_fargate_cluster(random_string=random_string,
                                                                        config_file=self.config_file)

      return eks_fargate_cluster_name
    elif self.cluster_type == 'ecs-fargate':
      ecs_fargate = ECSFargate(logger=self.logger)
      ecs_fargate_cluster_name = ecs_fargate.deploy_ecs_fargate_cluster(random_string=random_string,
                                                                        config_file=self.config_file)

      return ecs_fargate_cluster_name
    elif self.cluster_type == 'ecs-ec2':
      ecs_ec2 = ECSec2(logger=self.logger)
      ecs_ec2_cluster_name = ecs_ec2.deploy_ecs_ec2_cluster(random_string=random_string, config_file=self.config_file)

      return ecs_ec2_cluster_name

  def start_falcon_sensor_deployment(self, cluster_name):
    if self.kernel_mode:
      sensor_mode = 'kernel'
    else:
      sensor_mode = 'bpf'

    if self.cluster_type == 'eks-managed-node':
      daemonset = AWSFalconSensorDaemonset(falcon_client_id=self.falcon_client_id,
                                           falcon_client_secret=self.falcon_client_secret,
                                           image_registry=self.image_registry,
                                           sensor_image_tag=self.sensor_image_tag,
                                           proxy_server=self.proxy_server,
                                           proxy_port=self.proxy_port,
                                           sensor_tags=self.sensor_tags,
                                           sensor_mode=sensor_mode,
                                           cluster_name=cluster_name,
                                           logger=self.logger)
      daemonset.deploy_falcon_sensor_daemonset()
    elif self.cluster_type == 'eks-fargate':
      sidecar = AWSFalconSensorSidecar(falcon_client_id=self.falcon_client_id,
                                       falcon_client_secret=self.falcon_client_secret,
                                       monitor_namespaces=self.monitor_namespaces,
                                       exclude_namespaces=self.exclude_namespaces,
                                       image_registry=self.image_registry,
                                       sensor_image_tag=self.sensor_image_tag,
                                       proxy_server=self.proxy_server,
                                       proxy_port=self.proxy_port,
                                       sensor_tags=self.sensor_tags,
                                       cluster_name=cluster_name,
                                       logger=self.logger,
                                       ecr_iam_policy=self.ecr_iam_policy,
                                       sensor_iam_role=self.sensor_iam_role)

      sidecar.deploy_falcon_sensor_sidecar()
    else:
      print('The cluster type you mentioned is not yet supported. Existing falcon sensor deployment.\n')
      return

  def start_kac_deployment(self, cluster_name):
    if self.cluster_type == 'eks-managed-node':
      kac = AWSDaemonsetKAC(falcon_client_id=self.falcon_client_id,
                            falcon_client_secret=self.falcon_client_secret,
                            image_registry=self.image_registry,
                            kac_image_tag=self.kac_image_tag,
                            cluster_name=cluster_name,
                            cluster_type=self.cluster_type,
                            logger=self.logger)
      kac.deploy_falcon_kac()
    elif self.cluster_type == 'eks-fargate':
      kac = AWSSidecarKAC(falcon_client_id=self.falcon_client_id,
                          falcon_client_secret=self.falcon_client_secret,
                          image_registry=self.image_registry,
                          kac_image_tag=self.kac_image_tag,
                          cluster_name=cluster_name,
                          cluster_type=self.cluster_type,
                          logger=self.logger,
                          ecr_iam_policy=self.ecr_iam_policy,
                          kac_iam_role=self.kac_iam_role)
      kac.deploy_falcon_kac()

  def start_iar_deployment(self, cluster_name):
    if self.cluster_type == 'eks-managed-node':
      iar = AWSDaemonsetIAR(falcon_client_id=self.falcon_client_id,
                            falcon_client_secret=self.falcon_client_secret,
                            image_registry=self.image_registry,
                            iar_image_tag=self.iar_image_tag,
                            cluster_name=cluster_name,
                            cluster_type=self.cluster_type,
                            logger=self.logger)

      iar.deploy_falcon_iar()
    elif self.cluster_type == 'eks-fargate':
      iar = AWSSidecarIAR(falcon_client_id=self.falcon_client_id,
                          falcon_client_secret=self.falcon_client_secret,
                          image_registry=self.image_registry,
                          iar_image_tag=self.iar_image_tag,
                          cluster_name=cluster_name,
                          cluster_type=self.cluster_type,
                          ecr_iam_policy=self.ecr_iam_policy,
                          iar_iam_role=self.iar_iam_role,
                          logger=self.logger)

      iar.deploy_falcon_iar()

  def start_cluster_operations(self):
    start_time = time.time()
    print("\nStart Time:", time.strftime("%Y-%m-%d %H:%M:%S\n", time.localtime(start_time)))

    # Check Cloud Service Provider Login
    if not self.check_csp_login():
      print(f'Session is not logged into {self.cloud_type}. Try running Abstrakt after attempting manual login.\n')
      exit()

    # Deploy the cluster using Terraform
    cluster_name = self.deploy_cluster()

    # install falcon sensor in daemonset mode
    if self.install_falcon_sensor:
      self.start_falcon_sensor_deployment(cluster_name=cluster_name)

    # install kubernetes protection agent
    if self.install_kpa:
      self.start_kpa_deployment()

    # install kubernetes admission controller
    if self.install_kac:
      self.start_kac_deployment(cluster_name=cluster_name)

    # install image assessment at runtime
    if self.install_iar:
      self.start_iar_deployment(cluster_name=cluster_name)

    # install detections container and generate artificial detections + misconfigurations
    if self.install_detections_container:
      self.start_detections_container_deployment()

    # install vulnerable apps
    if self.install_vulnerable_apps:
      self.start_vulnerable_app_deployment()

    # generate misconfigurations
    if self.generate_misconfigs:
      self.generate_misconfigurations()

    end_time = time.time()
    time_difference = end_time - start_time

    print(f'{"+" * 39}\n')
    print("End Time:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time)))

    print(f'Total deployment time: {int(int(time_difference) / 60)} minute/s and {int(time_difference) % 60} seconds\n')
