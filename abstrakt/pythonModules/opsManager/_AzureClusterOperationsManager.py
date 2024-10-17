import time

from abstrakt.pythonModules.opsManager.opsManager import _ClusterOperationsManager
from abstrakt.pythonModules.vendors.cloudServiceProviders.azure.aks.aks import AKS
from abstrakt.pythonModules.vendors.cloudServiceProviders.azure.aci.aci import ACI
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors._kac._AzureKAC import _AzureKAC
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors._iar._AzureIAR import _AzureIAR
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors._falconsensor._daemonset._AzureDaemonset \
  import _AzureDaemonset


class _AzureClusterOperationsManager(_ClusterOperationsManager):
  def __init__(self, config_file: str,
               cluster_name: str,
               rg_name: str,
               rg_location: str,
               asset_tags: str,
               install_falcon_sensor: bool,
               registry: str,
               repository: str,
               sensor_image_tag: str,
               proxy_server: str,
               proxy_port: int,
               sensor_tags: str,
               acr_rg: str,
               sp_name: str,
               sp_pass: str,
               install_kac: bool,
               kac_image_tag: str,
               install_iar: bool,
               iar_image_tag: str,
               install_kpa: bool,
               cloud_type: str,
               cluster_type: str,
               falcon_client_id: str,
               falcon_client_secret: str,
               install_detections_container: bool,
               install_vulnerable_apps: bool,
               generate_misconfigs: bool,
               logger,
               kernel_mode: bool,
               ebpf_mode: bool,
               acr_sub_id: str,
               aks_sub_id: str):

    self.config_file: str = config_file
    self.cluster_name: str = cluster_name
    self.rg_name: str = rg_name
    self.rg_location: str = rg_location
    self.asset_tags: str = asset_tags
    self.install_falcon_sensor: bool = install_falcon_sensor
    self.registry: str = registry
    self.repository: str = repository
    self.sensor_image_tag: str = sensor_image_tag
    self.proxy_server: str = proxy_server
    self.proxy_port: int = proxy_port
    self.sensor_tags: str = sensor_tags
    self.acr_rg: str = acr_rg
    self.sp_name: str = sp_name
    self.sp_pass: str = sp_pass
    self.install_kac: bool = install_kac
    self.kac_image_tag: str = kac_image_tag
    self.install_iar: bool = install_iar
    self.iar_image_tag: str = iar_image_tag
    self.install_kpa: bool = install_kpa
    self.cloud_type: str = cloud_type
    self.cluster_type: str = cluster_type
    self.falcon_client_id: str = falcon_client_id
    self.falcon_client_secret: str = falcon_client_secret
    self.install_detections_container: bool = install_detections_container
    self.install_vulnerable_apps: bool = install_vulnerable_apps
    self.generate_misconfigs: bool = generate_misconfigs
    self.logger = logger
    self.kernel_mode: bool = kernel_mode
    self.ebpf_mode: bool = ebpf_mode
    self.acr_sub_id: str = acr_sub_id
    self.aks_sub_id: str = aks_sub_id

  def deploy_azure_cluster(self) -> str:
    if self.cluster_type == 'aks':
      aks_cluster = AKS(self.logger)
      aks_cluster_name = aks_cluster.deploy_aks_cluster(cluster_name=self.cluster_name,
                                                        rg_name=self.rg_name,
                                                        rg_location=self.rg_location,
                                                        asset_tags=self.asset_tags,
                                                        config_file=self.config_file)

      return aks_cluster_name
    elif self.cluster_type == 'aci':
      aci_cluster = ACI(self.logger)
      aci_cluster_name = aci_cluster.deploy_aci_cluster(self.config_file)

      return aci_cluster_name

  def start_falcon_sensor_deployment(self):
    if self.kernel_mode:
      sensor_mode = 'kernel'
    else:
      sensor_mode = 'bpf'

    if self.cluster_type == 'aks':
      daemonset = _AzureDaemonset(falcon_client_id=self.falcon_client_id,
                                  falcon_client_secret=self.falcon_client_secret,
                                  logger=self.logger,
                                  registry=self.registry,
                                  repository=self.repository,
                                  rg_name=self.rg_name,
                                  rg_location=self.rg_location,
                                  sensor_image_tag=self.sensor_image_tag,
                                  acr_rg=self.acr_rg,
                                  acr_sub_id=self.acr_sub_id,
                                  proxy_server=self.proxy_server,
                                  proxy_port=self.proxy_port,
                                  sensor_tags=self.sensor_tags,
                                  sensor_mode=sensor_mode,
                                  aks_sub_id=self.aks_sub_id,
                                  sp_name=self.sp_name,
                                  sp_pass=self.sp_pass)

      daemonset.deploy_azure_daemonset_falcon_sensor()
    else:
      print('The cluster type you mentioned is not yet supported. Existing falcon sensor deployment.\n')
      return

  def start_kac_deployment(self):
    if self.cluster_type == 'aks':
      kac = _AzureKAC(falcon_client_id=self.falcon_client_id,
                      falcon_client_secret=self.falcon_client_secret,
                      logger=self.logger,
                      registry=self.registry,
                      repository=self.repository,
                      rg_name=self.rg_name,
                      rg_location=self.rg_location,
                      acr_rg=self.acr_rg,
                      acr_sub_id=self.acr_sub_id,
                      kac_image_tag=self.kac_image_tag,
                      sp_name=self.sp_name,
                      sp_pass=self.sp_pass)

      kac.deploy_falcon_kac()

  def start_iar_deployment(self):
    if self.cluster_type == 'aks':
      iar = _AzureIAR(falcon_client_id=self.falcon_client_id,
                      falcon_client_secret=self.falcon_client_secret,
                      logger=self.logger,
                      registry=self.registry,
                      repository=self.repository,
                      rg_name=self.rg_name,
                      rg_location=self.rg_location,
                      acr_rg=self.acr_rg,
                      acr_sub_id=self.acr_sub_id,
                      iar_image_tag=self.iar_image_tag,
                      sp_name=self.sp_name,
                      sp_pass=self.sp_pass)

      iar.deploy_falcon_iar()

  def start_azure_cluster_operations(self):
    start_time = time.time()
    print("\nStart Time:", time.strftime("%Y-%m-%d %H:%M:%S\n", time.localtime(start_time)))

    # Check Cloud Service Provider Login
    if not self.check_csp_login(csp='azure', logger=self.logger):
      print(f'Session is not logged into {self.cloud_type}. Try running Abstrakt after attempting manual login.\n')
      exit()

    # Deploy the cluster using Terraform
    self.deploy_azure_cluster()

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
