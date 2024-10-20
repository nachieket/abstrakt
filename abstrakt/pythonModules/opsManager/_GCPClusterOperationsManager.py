import time

from abstrakt.pythonModules.vendors.cloudServiceProviders.gcp.gke import GKE
from abstrakt.pythonModules.opsManager.opsManager import _ClusterOperationsManager
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors._kac._GCPKAC import _GCPKAC
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors._iar._GCPIAR import _GCPIAR
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors._falconsensor._daemonset._GCPDaemonset import \
  _GCPDaemonset


class _GCPClusterOperationsManager(_ClusterOperationsManager):
  def __init__(self, config_file: str,
               cluster_name: str,
               vpc_network: str,
               region: str,
               project_id: str,
               asset_tags: str | None,
               install_falcon_sensor: bool,
               registry: str,
               repository: str,
               sensor_image_tag: str,
               proxy_server: str,
               proxy_port: int,
               sensor_tags: str,
               install_kac: bool,
               kac_image_tag: str,
               install_iar: bool,
               iar_image_tag: str,
               install_kpa: bool,
               cloud_type: str,
               cluster_type: str,
               service_account: str,
               falcon_client_id: str,
               falcon_client_secret: str,
               install_detections_container: bool,
               install_vulnerable_apps: bool,
               generate_misconfigs: bool,
               logger):

    self.config_file: str = config_file
    self.cluster_name: str = cluster_name
    self.vpc_network: str = vpc_network
    self.region: str = region
    self.project_id: str = project_id
    self.asset_tags: str = asset_tags
    self.install_falcon_sensor: bool = install_falcon_sensor
    self.registry: str = registry
    self.repository: str = repository
    self.sensor_image_tag: str = sensor_image_tag
    self.proxy_server: str = proxy_server
    self.proxy_port: int = proxy_port
    self.sensor_tags: str = sensor_tags
    self.install_kac: bool = install_kac
    self.kac_image_tag: str = kac_image_tag
    self.install_iar: bool = install_iar
    self.iar_image_tag: str = iar_image_tag
    self.install_kpa: bool = install_kpa
    self.cloud_type: str = cloud_type
    self.cluster_type: str = cluster_type
    self.service_account: str = service_account
    self.falcon_client_id: str = falcon_client_id
    self.falcon_client_secret: str = falcon_client_secret
    self.install_detections_container: bool = install_detections_container
    self.install_vulnerable_apps: bool = install_vulnerable_apps
    self.generate_misconfigs: bool = generate_misconfigs
    self.logger = logger

  def deploy_gke_cluster(self) -> str:
    if self.cluster_type == 'gke-standard':
      gke_standard_cluster = GKE(self.logger)
      return gke_standard_cluster.deploy_gke_standard_cluster(cluster_name=self.cluster_name,
                                                              vpc_network=self.vpc_network,
                                                              region=self.region,
                                                              asset_tags=self.asset_tags,
                                                              config_file=self.config_file,
                                                              project_id=self.project_id)

    elif self.cluster_type == 'gke-autopilot':
      gke_autopilot_cluster = GKE(self.logger)
      return gke_autopilot_cluster.deploy_gke_autopilot_cluster(cluster_name=self.cluster_name,
                                                                vpc_network=self.vpc_network,
                                                                region=self.region,
                                                                config_file=self.config_file,
                                                                project_id=self.project_id)

  def start_falcon_sensor_deployment(self):
    daemonset = _GCPDaemonset(falcon_client_id=self.falcon_client_id,
                              falcon_client_secret=self.falcon_client_secret,
                              logger=self.logger,
                              registry=self.registry,
                              repository=self.repository,
                              project_id=self.project_id,
                              sensor_image_tag=self.sensor_image_tag,
                              sensor_tags=self.sensor_tags,
                              proxy_server=self.proxy_server,
                              proxy_port=self.proxy_port,
                              cluster_type=self.cluster_type,
                              service_account=self.service_account,
                              location=self.region)

    daemonset.deploy_falcon_sensor_daemonset(cluster_type=self.cluster_type)

  def start_kac_deployment(self):
    kac = _GCPKAC(falcon_client_id=self.falcon_client_id,
                  falcon_client_secret=self.falcon_client_secret,
                  logger=self.logger,
                  registry=self.registry,
                  repository=self.repository,
                  project_id=self.project_id,
                  service_account=self.service_account,
                  kac_image_tag=self.kac_image_tag,
                  location=self.region)

    kac.deploy_falcon_kac()

  def start_iar_deployment(self):
    iar = _GCPIAR(falcon_client_id=self.falcon_client_id,
                  falcon_client_secret=self.falcon_client_secret,
                  logger=self.logger,
                  registry=self.registry,
                  repository=self.repository,
                  project_id=self.project_id,
                  service_account=self.service_account,
                  iar_image_tag=self.iar_image_tag,
                  location=self.region)

    iar.deploy_falcon_iar()

  def start_gcp_cluster_operations(self):
    start_time = time.time()
    print("\nStart Time:", time.strftime("%Y-%m-%d %H:%M:%S\n", time.localtime(start_time)))

    # Check Cloud Service Provider Login
    if not self.check_csp_login(csp='gcp', logger=self.logger):
      print(f'Session is not logged into {self.cloud_type}. Try running Abstrakt after attempting manual login.\n')
      exit()

    # Deploy the cluster using Terraform
    # self.deploy_gke_cluster()

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
      self.start_kac_deployment()

    # install image assessment at runtime
    if self.install_iar:
      self.start_iar_deployment()

    # install detections container and generate artificial detections + misconfigurations
    if self.install_detections_container:
      self.start_detections_container_deployment(cluster_type=self.cluster_type, logger=self.logger)

    if self.generate_misconfigs:
      self.generate_misconfigurations(cluster_type=self.cluster_type, logger=self.logger)

    # install vulnerable apps
    if self.install_vulnerable_apps:
      self.start_vulnerable_app_deployment(logger=self.logger)

    end_time = time.time()
    time_difference = end_time - start_time

    print(f'{"+" * 39}\n')
    print("End Time:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time)))

    print(f'Total deployment time: {int(int(time_difference) / 60)} minute/s and {int(time_difference) % 60} seconds\n')
