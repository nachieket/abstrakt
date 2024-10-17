import time

from abstrakt.pythonModules.vendors.cloudServiceProviders.gcp.gke import GKE
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.gcp.gcpDaemonset.GCPFalconSensorDaemonset \
  import GCPFalconSensorDaemonset, GCPDaemonsetKAC, GCPDaemonsetIAR
from abstrakt.pythonModules.opsManager.opsManager import ClusterOperationsManager


class GCPClusterOperationsManager(ClusterOperationsManager):
  def __init__(self, config_file: str = None,
               install_falcon_sensor: bool = None,
               image_registry: str = None,
               sensor_image_tag: str = None,
               proxy_server: str = None,
               proxy_port: int = None,
               sensor_tags: str = None,
               install_kac: bool = None,
               kac_image_tag: str = 'latest',
               install_iar: bool = None,
               iar_image_tag: str = 'latest',
               install_kpa: bool = None,
               cloud_type: str = None,
               cluster_type: str = None,
               falcon_client_id: str = None,
               falcon_client_secret: str = None,
               install_detections_container: bool = None,
               install_vulnerable_apps: bool = None,
               generate_misconfigs: bool = None,
               logger=None,
               gcp_project_id: str = None):
    super().__init__(config_file, install_falcon_sensor, image_registry, sensor_image_tag, proxy_server,
                     proxy_port, sensor_tags, install_kac, kac_image_tag, install_iar, iar_image_tag,
                     install_kpa, cloud_type, cluster_type, falcon_client_id, falcon_client_secret,
                     install_detections_container, install_vulnerable_apps, generate_misconfigs, logger)

    self.gcp_project_id: str = gcp_project_id

  def deploy_gcp_cluster(self) -> str:
    if self.cluster_type == 'gke-standard':
      gke_cluster = GKE(self.logger)
      gke_standard_cluster_name = gke_cluster.deploy_gke_standard_cluster(self.config_file, self.gcp_project_id)

      return gke_standard_cluster_name
    elif self.cluster_type == 'gke-autopilot':
      gke_cluster = GKE(self.logger)
      gke_autopilot_cluster_name = gke_cluster.deploy_gke_autopilot_cluster(self.config_file, self.gcp_project_id)

      return gke_autopilot_cluster_name

  def start_falcon_sensor_deployment(self):
    if self.cluster_type == 'gke-standard':
      daemonset = GCPFalconSensorDaemonset(falcon_client_id=self.falcon_client_id,
                                           falcon_client_secret=self.falcon_client_secret,
                                           sensor_image_tag=self.sensor_image_tag,
                                           proxy_server=self.proxy_server,
                                           proxy_port=self.proxy_port,
                                           sensor_tags=self.sensor_tags,
                                           logger=self.logger)

      daemonset.deploy_falcon_sensor_daemonset()
    elif self.cluster_type == 'gke-autopilot':
      daemonset = GCPFalconSensorDaemonset(falcon_client_id=self.falcon_client_id,
                                           falcon_client_secret=self.falcon_client_secret,
                                           sensor_image_tag=self.sensor_image_tag,
                                           proxy_server=self.proxy_server,
                                           proxy_port=self.proxy_port,
                                           sensor_tags=self.sensor_tags,
                                           logger=self.logger,
                                           cluster_type='gke-autopilot')

      daemonset.deploy_falcon_sensor_daemonset()
    else:
      print('The cluster type you mentioned is not yet supported. Existing falcon sensor deployment.\n')
      return

  def start_kac_deployment(self, cluster_name):
    kac = GCPDaemonsetKAC(falcon_client_id=self.falcon_client_id,
                          falcon_client_secret=self.falcon_client_secret,
                          logger=self.logger,
                          image_registry=self.image_registry,
                          cluster_name=cluster_name,
                          cluster_type=self.cluster_type,
                          kac_image_tag=self.kac_image_tag)

    kac.deploy_falcon_kac()

  def start_iar_deployment(self, cluster_name):
    iar = GCPDaemonsetIAR(falcon_client_id=self.falcon_client_id,
                          falcon_client_secret=self.falcon_client_secret,
                          logger=self.logger,
                          image_registry=self.image_registry,
                          cluster_name=cluster_name,
                          cluster_type=self.cluster_type,
                          iar_image_tag=self.iar_image_tag)

    iar.deploy_falcon_iar()

  def start_gcp_cluster_operations(self):
    start_time = time.time()
    print("\nStart Time:", time.strftime("%Y-%m-%d %H:%M:%S\n", time.localtime(start_time)))

    # Check Cloud Service Provider Login
    if not self.check_csp_login():
      print(f'Session is not logged into {self.cloud_type}. Try running Abstrakt after attempting manual login.\n')
      exit()

    # Deploy the cluster using Terraform
    cluster_name = self.deploy_gcp_cluster()

    # install falcon sensor in _daemonset mode
    if self.install_falcon_sensor:
      self.start_falcon_sensor_deployment()

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

    if self.generate_misconfigs:
      self.generate_misconfigurations()

    # install vulnerable apps
    if self.install_vulnerable_apps:
      self.start_vulnerable_app_deployment()

    end_time = time.time()
    time_difference = end_time - start_time

    print(f'{"+" * 39}\n')
    print("End Time:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time)))

    print(f'Total deployment time: {int(int(time_difference) / 60)} minute/s and {int(time_difference) % 60} seconds\n')
