import time

from abstrakt.pythonModules.opsManager.generalOpsManager import ClusterOperationsManager
from abstrakt.pythonModules.vendors.cloudServiceProviders.aws.eksFargate.eksFargate import EKSFargate
from abstrakt.pythonModules.vendors.cloudServiceProviders.aws.eksManagedNode.eksManagedNode import EKSManagedNode
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.kac.AWSKAC import AWSDaemonsetKAC, AWSSidecarKAC
from abstrakt.pythonModules.commandLine.layer_one.layer_two.runtimeParameterVerification import \
  AWSRuntimeParameterVerification
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.iar.AWSIAR import AWSDaemonsetIAR, AWSSidecarIAR
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.falconsensor.sidecar.AWSSidecar \
  import AWSSidecar
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.falconsensor.daemonset.AWSDaemonset \
  import AWSDaemonsetInstall


class AWSDaemonsetOperationsManager(ClusterOperationsManager):
  def __init__(self, config_file: str,
               cluster_name: str,
               vpc_name: str,
               region: str,
               asset_tags: str,
               install_falcon_sensor: bool,
               registry: str,
               repository: str,
               kernel_mode: bool,
               ebpf_mode: bool,
               sensor_image_tag: str,
               proxy_server: str,
               proxy_port: int,
               sensor_tags: str,
               install_kac: bool,
               kac_image_tag: str,
               install_iar: bool,
               iar_image_tag: str,
               install_kpa: bool,
               falcon_client_id: str,
               falcon_client_secret: str,
               install_detections_container: bool,
               install_vulnerable_apps: bool,
               generate_misconfigs: bool,
               cloud_type: str,
               cluster_type: str,
               logger):
    self.config_file: str = config_file
    self.cluster_name: str = cluster_name
    self.vpc_name: str = vpc_name
    self.region: str = region
    self.asset_tags: str = asset_tags
    self.install_falcon_sensor: bool = install_falcon_sensor
    self.registry: str = registry
    self.repository: str = repository
    self.kernel_mode: bool = kernel_mode
    self.ebpf_mode: bool = ebpf_mode
    self.sensor_image_tag: str = sensor_image_tag
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

  def verify_parameters(self):
    runtime = AWSRuntimeParameterVerification(config_file=self.config_file,
                                              cluster_name=self.cluster_name,
                                              vpc_name=self.vpc_name,
                                              region=self.region,
                                              asset_tags=self.asset_tags,
                                              install_falcon_sensor=self.install_falcon_sensor,
                                              kernel_mode=self.kernel_mode,
                                              ebpf_mode=self.ebpf_mode,
                                              registry=self.registry,
                                              repository=self.repository,
                                              proxy_server=self.proxy_server,
                                              proxy_port=self.proxy_port,
                                              install_kac=self.install_kac,
                                              install_iar=self.install_iar,
                                              install_kpa=self.install_kpa,
                                              falcon_client_id=self.falcon_client_id,
                                              falcon_client_secret=self.falcon_client_secret,
                                              install_detections_container=self.install_detections_container,
                                              install_vulnerable_apps=self.install_vulnerable_apps,
                                              generate_misconfigs=self.generate_misconfigs,
                                              logger=self.logger)
    runtime.verify_eks_managed_node_runtime_parameters()

  def deploy_cluster(self) -> str:
    random_string = self.get_random_string(logger=self.logger)

    managed_node = EKSManagedNode(logger=self.logger)
    eks_managed_node_cluster_name = managed_node.deploy_eks_managed_node_cluster(cluster_name=self.cluster_name,
                                                                                 vpc_name=self.vpc_name,
                                                                                 region=self.region,
                                                                                 asset_tags=self.asset_tags,
                                                                                 random_string=random_string,
                                                                                 config_file=self.config_file)

    return eks_managed_node_cluster_name

  def start_falcon_sensor_deployment(self):
    if self.kernel_mode:
      sensor_mode = 'kernel'
    else:
      sensor_mode = 'bpf'

    daemonset = AWSDaemonsetInstall(falcon_client_id=self.falcon_client_id,
                                    falcon_client_secret=self.falcon_client_secret,
                                    registry=self.registry,
                                    repository=self.repository,
                                    sensor_image_tag=self.sensor_image_tag,
                                    proxy_server=self.proxy_server,
                                    proxy_port=self.proxy_port,
                                    sensor_tags=self.sensor_tags,
                                    sensor_mode=sensor_mode,
                                    logger=self.logger)
    daemonset.deploy_falcon_sensor_daemonset(logger=self.logger)

  def start_kac_deployment(self, cluster_name):
    kac = AWSDaemonsetKAC(falcon_client_id=self.falcon_client_id,
                          falcon_client_secret=self.falcon_client_secret,
                          registry=self.registry,
                          repository=self.repository,
                          kac_image_tag=self.kac_image_tag,
                          cluster_name=cluster_name,
                          cluster_type=self.cluster_type,
                          sensor_tags=self.sensor_tags,
                          logger=self.logger)
    kac.deploy_falcon_kac(logger=self.logger)

  def start_iar_deployment(self, cluster_name):
    iar = AWSDaemonsetIAR(falcon_client_id=self.falcon_client_id,
                          falcon_client_secret=self.falcon_client_secret,
                          logger=self.logger,
                          registry=self.registry,
                          repository=self.repository,
                          iar_image_tag=self.iar_image_tag,
                          cluster_name=cluster_name,
                          cluster_type=self.cluster_type)

    iar.deploy_falcon_iar(logger=self.logger)

  def start_cluster_operations(self):
    self.logger.info("Starting cluster operations")
    try:
      start_time = time.time()
      print("\nStart Time:", time.strftime("%Y-%m-%d %H:%M:%S\n", time.localtime(start_time)))

      self.verify_parameters()

      # Check Cloud Service Provider Login
      if not self.check_csp_login(csp='aws', logger=self.logger):
        print(f'Session is not logged into {self.cloud_type}. Try running Abstrakt after attempting manual login.\n')
        exit()

      # Deploy the cluster using Terraform
      cluster_name = self.deploy_cluster()

      # install falcon sensor in _daemonset mode
      if self.install_falcon_sensor:
        self.start_falcon_sensor_deployment()

      # install kubernetes protection agent
      if self.install_kpa:
        self.start_kpa_deployment(falcon_client_id=self.falcon_client_id,
                                  falcon_client_secret=self.falcon_client_secret,
                                  logger=self.logger)

      # install kubernetes admission controller
      if self.install_kac:
        self.start_kac_deployment(cluster_name=cluster_name)

      # install image assessment at runtime
      if self.install_iar:
        self.start_iar_deployment(cluster_name=cluster_name)

      # install detections container and generate artificial detections + misconfigurations
      if self.install_detections_container:
        self.start_detections_container_deployment(cluster_type=self.cluster_type, logger=self.logger)

      # install vulnerable apps
      if self.install_vulnerable_apps:
        self.start_vulnerable_app_deployment(logger=self.logger)

      # generate misconfigurations
      if self.generate_misconfigs:
        self.generate_misconfigurations(cluster_type=self.cluster_type, logger=self.logger)

      end_time = time.time()
      time_difference = end_time - start_time

      print(f'{"+" * 39}\n')
      print("End Time:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time)))

      print(f'Total deployment time: {int(int(time_difference) / 60)} '
            f'minute/s and {int(time_difference) % 60} seconds\n')
    finally:
      self.logger.info("Finished cluster operations")


class AWSSidecarOperationsManager(ClusterOperationsManager):
  def __init__(self, config_file: str,
               cluster_name: str,
               region: str,
               vpc_name: str,
               asset_tags: str,
               cluster_type: str,
               install_falcon_sensor: bool,
               registry: str,
               repository: str,
               sensor_image_tag: str,
               monitor_namespaces: str,
               exclude_namespaces: str,
               proxy_server: str,
               proxy_port: int,
               sensor_tags: str,
               install_kac: bool,
               kac_image_tag: str,
               install_iar: bool,
               iar_image_tag: str,
               install_kpa: bool,
               falcon_client_id: str,
               falcon_client_secret: str,
               install_detections_container: bool,
               install_vulnerable_apps: bool,
               generate_misconfigs: bool,
               ecr_iam_policy: str,
               ecr_sensor_iam_role: str,
               ecr_kac_iam_role: str,
               ecr_iar_iam_role: str,
               cloud_type: str,
               logger):
    self.config_file: str = config_file
    self.cluster_name: str = cluster_name
    self.region: str = region
    self.vpc_name: str = vpc_name
    self.asset_tags: str = asset_tags
    self.cluster_type: str = cluster_type
    self.install_falcon_sensor: bool = install_falcon_sensor
    self.registry: str = registry
    self.repository: str = repository
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
    self.ecr_iam_policy: str = ecr_iam_policy
    self.ecr_sensor_iam_role: str = ecr_sensor_iam_role
    self.ecr_kac_iam_role: str = ecr_kac_iam_role
    self.ecr_iar_iam_role: str = ecr_iar_iam_role
    self.cloud_type: str = cloud_type
    self.logger = logger

  def verify_parameters(self):
    runtime = AWSRuntimeParameterVerification(config_file=self.config_file,
                                              cluster_name=self.cluster_name,
                                              vpc_name=self.vpc_name,
                                              region=self.region,
                                              asset_tags=self.asset_tags,
                                              install_falcon_sensor=self.install_falcon_sensor,
                                              registry=self.registry,
                                              repository=self.repository,
                                              proxy_server=self.proxy_server,
                                              proxy_port=self.proxy_port,
                                              install_kac=self.install_kac,
                                              install_iar=self.install_iar,
                                              install_kpa=self.install_kpa,
                                              falcon_client_id=self.falcon_client_id,
                                              falcon_client_secret=self.falcon_client_secret,
                                              install_detections_container=self.install_detections_container,
                                              install_vulnerable_apps=self.install_vulnerable_apps,
                                              generate_misconfigs=self.generate_misconfigs,
                                              logger=self.logger)
    runtime.verify_eks_fargate_runtime_parameters()

  def deploy_cluster(self) -> str:
    random_string = self.get_random_string(logger=self.logger)

    eks_fargate = EKSFargate(logger=self.logger)
    eks_fargate_cluster_name = eks_fargate.deploy_eks_fargate_cluster(cluster_name=self.cluster_name,
                                                                      vpc_name=self.vpc_name,
                                                                      region=self.region,
                                                                      asset_tags=self.asset_tags,
                                                                      random_string=random_string,
                                                                      config_file=self.config_file)

    return eks_fargate_cluster_name

  def start_falcon_sensor_deployment(self, cluster_name: str):
    sidecar = AWSSidecar(falcon_client_id=self.falcon_client_id,
                         falcon_client_secret=self.falcon_client_secret,
                         logger=self.logger,
                         registry=self.registry,
                         repository=self.repository,
                         proxy_server=self.proxy_server,
                         proxy_port=self.proxy_port,
                         sensor_image_tag=self.sensor_image_tag,
                         sensor_tags=self.sensor_tags,
                         sensor_mode='bpf',
                         monitor_namespaces=self.monitor_namespaces,
                         exclude_namespaces=self.exclude_namespaces,
                         ecr_iam_policy=self.ecr_iam_policy,
                         ecr_sensor_iam_role=self.ecr_sensor_iam_role,
                         ecr_kac_iam_role=self.ecr_kac_iam_role,
                         ecr_iar_iam_role=self.ecr_iar_iam_role,
                         cluster_name=cluster_name
                         )

    sidecar.deploy_sidecar_falcon_sensor(logger=self.logger)

  def start_kac_deployment(self):
    kac = AWSSidecarKAC(falcon_client_id=self.falcon_client_id,
                        falcon_client_secret=self.falcon_client_secret,
                        logger=self.logger,
                        registry=self.registry,
                        repository=self.repository,
                        ecr_iam_policy=self.ecr_iam_policy,
                        cluster_name=self.cluster_name,
                        cluster_type=self.cluster_type,
                        kac_image_tag=self.kac_image_tag,
                        kac_iam_role=self.ecr_kac_iam_role
                        )
    kac.deploy_falcon_kac(logger=self.logger)

  def start_iar_deployment(self, cluster_name: str):
    iar = AWSSidecarIAR(falcon_client_id=self.falcon_client_id,
                        falcon_client_secret=self.falcon_client_secret,
                        logger=self.logger,
                        registry=self.registry,
                        repository=self.repository,
                        iar_image_tag=self.iar_image_tag,
                        cluster_name=cluster_name,
                        cluster_type=self.cluster_type,
                        ecr_iam_policy=self.ecr_iam_policy,
                        iar_iam_role=self.ecr_iar_iam_role)

    iar.deploy_falcon_iar(logger=self.logger)

  def start_cluster_operations(self):
    start_time = time.time()
    print("\nStart Time:", time.strftime("%Y-%m-%d %H:%M:%S\n", time.localtime(start_time)))

    self.verify_parameters()

    # Check Cloud Service Provider Login
    if not self.check_csp_login(csp='aws', logger=self.logger):
      print(f'Session is not logged into {self.cloud_type}. Try running Abstrakt after attempting manual login.\n')
      exit()

    # Deploy the cluster using Terraform
    cluster_name: str = self.deploy_cluster()

    # install falcon sensor in _daemonset mode
    if self.install_falcon_sensor:
      self.start_falcon_sensor_deployment(cluster_name=cluster_name)

    # install kubernetes protection agent
    if self.install_kpa:
      self.start_kpa_deployment(falcon_client_id=self.falcon_client_id,
                                falcon_client_secret=self.falcon_client_secret,
                                logger=self.logger)

    # install kubernetes admission controller
    if self.install_kac:
      self.start_kac_deployment()

    # install image assessment at runtime
    if self.install_iar:
      self.start_iar_deployment(cluster_name=cluster_name)

    # install detections container and generate artificial detections + misconfigurations
    if self.install_detections_container:
      self.start_detections_container_deployment(cluster_type=self.cluster_type, logger=self.logger)

    # install vulnerable apps
    if self.install_vulnerable_apps:
      self.start_vulnerable_app_deployment(logger=self.logger)

    # generate misconfigurations
    if self.generate_misconfigs:
      self.generate_misconfigurations(cluster_type=self.cluster_type, logger=self.logger)

    end_time = time.time()
    time_difference = end_time - start_time

    print(f'{"+" * 39}\n')
    print("End Time:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time)))

    print(f'Total deployment time: {int(int(time_difference) / 60)} minute/s and {int(time_difference) % 60} seconds\n')
