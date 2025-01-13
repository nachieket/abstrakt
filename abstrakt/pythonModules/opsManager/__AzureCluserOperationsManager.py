import time

from abstrakt.pythonModules.vendors.cloudServiceProviders.azure.aks.aks import AKS
from abstrakt.pythonModules.vendors.cloudServiceProviders.azure.aci.aci import ACI
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.__azure.azureDaemonset.AzureFalconSensorDaemonset \
  import AzureFalconSensorDaemonset, AzureDaemonsetKAC, AzureDaemonsetIAR
from abstrakt.pythonModules.opsManager.generalOpsManager import __ClusterOperationsManager


class AzureClusterOperationsManager(__ClusterOperationsManager):
  def __init__(self, config_file: str = None,
               install_falcon_sensor: bool = None,
               image_registry: str = None,
               sensor_image_tag: str = None,
               proxy_server: str = None,
               proxy_port: int = None,
               sensor_tags: str = None,
               acr_resource_group: str = None,
               service_principal_name: str = None,
               service_principal_password: str = None,
               install_kac: bool = None,
               kac_image_tag: str = None,
               install_iar: bool = None,
               iar_image_tag: str = None,
               install_kpa: bool = None,
               cloud_type: str = None,
               cluster_type: str = None,
               falcon_client_id: str = None,
               falcon_client_secret: str = None,
               install_detections_container: bool = None,
               install_vulnerable_apps: bool = None,
               generate_misconfigs: bool = None,
               logger=None,
               kernel_mode: bool = None,
               ebpf_mode: bool = None,
               acr_subscription_id: str = None,
               aks_subscription_id: str = None):
    super().__init__(config_file, install_falcon_sensor, image_registry, sensor_image_tag, proxy_server,
                     proxy_port, sensor_tags, install_kac, kac_image_tag, install_iar, iar_image_tag,
                     install_kpa, cloud_type, cluster_type, falcon_client_id, falcon_client_secret,
                     install_detections_container, install_vulnerable_apps, generate_misconfigs, logger)

    self.kernel_mode: bool = kernel_mode
    self.ebpf_mode: bool = ebpf_mode
    self.acr_resource_group = acr_resource_group
    self.service_principal_name = service_principal_name
    self.service_principal_password = service_principal_password
    self.acr_subscription_id: str = acr_subscription_id
    self.aks_subscription_id: str = aks_subscription_id

  def deploy_azure_cluster(self) -> str:
    if self.cluster_type == 'aks':
      aks_cluster = AKS(self.logger)
      aks_cluster_name = aks_cluster.deploy_aks_cluster(self.config_file)

      return aks_cluster_name
    elif self.cluster_type == 'aci':
      aci_cluster = ACI(self.logger)
      aci_cluster_name = aci_cluster.deploy_aci_cluster(self.config_file)

      return aci_cluster_name

  def start_falcon_sensor_deployment(self, cluster_name):
    if self.kernel_mode:
      sensor_mode = 'kernel'
    else:
      sensor_mode = 'bpf'

    if self.cluster_type == 'aks':
      daemonset = AzureFalconSensorDaemonset(falcon_client_id=self.falcon_client_id,
                                             falcon_client_secret=self.falcon_client_secret,
                                             logger=self.logger,
                                             image_registry=self.image_registry,
                                             sensor_image_tag=self.sensor_image_tag,
                                             proxy_server=self.proxy_server,
                                             proxy_port=self.proxy_port,
                                             sensor_tags=self.sensor_tags,
                                             cluster_name=cluster_name,
                                             cluster_type=self.cluster_type,
                                             acr_resource_group=self.acr_resource_group,
                                             acr_subscription_id=self.acr_subscription_id,
                                             sensor_mode=sensor_mode,
                                             aks_subscription_id=self.aks_subscription_id,
                                             service_principal_name=self.service_principal_name,
                                             service_principal_password=self.service_principal_password)

      daemonset.deploy_azure_daemonset_falcon_sensor()
    else:
      print('The cluster type you mentioned is not yet supported. Existing falcon sensor deployment.\n')
      return

  def start_kac_deployment(self, cluster_name):
    if self.cluster_type == 'aks':
      kac = AzureDaemonsetKAC(falcon_client_id=self.falcon_client_id,
                              falcon_client_secret=self.falcon_client_secret,
                              logger=self.logger,
                              image_registry=self.image_registry,
                              cluster_name=cluster_name,
                              cluster_type=self.cluster_type,
                              acr_resource_group=self.acr_resource_group,
                              acr_subscription_id=self.acr_subscription_id,
                              kac_image_tag=self.kac_image_tag,
                              service_principal_name=self.service_principal_name,
                              service_principal_password=self.service_principal_password)
      kac.deploy_falcon_kac()

  def start_iar_deployment(self, cluster_name):
    if self.cluster_type == 'aks':
      iar = AzureDaemonsetIAR(falcon_client_id=self.falcon_client_id,
                              falcon_client_secret=self.falcon_client_secret,
                              logger=self.logger,
                              image_registry=self.image_registry,
                              cluster_name=cluster_name,
                              cluster_type=self.cluster_type,
                              acr_resource_group=self.acr_resource_group,
                              acr_subscription_id=self.acr_subscription_id,
                              iar_image_tag=self.iar_image_tag,
                              service_principal_name=self.service_principal_name,
                              service_principal_password=self.service_principal_password)

      iar.deploy_falcon_iar()

  def start_azure_cluster_operations(self):
    start_time = time.time()
    print("\nStart Time:", time.strftime("%Y-%m-%d %H:%M:%S\n", time.localtime(start_time)))

    # Check Cloud Service Provider Login
    if not self.check_csp_login():
      print(f'Session is not logged into {self.cloud_type}. Try running Abstrakt after attempting manual login.\n')
      exit()

    # Deploy the cluster using Terraform
    cluster_name = self.deploy_azure_cluster()

    # install falcon sensor in _daemonset mode
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
