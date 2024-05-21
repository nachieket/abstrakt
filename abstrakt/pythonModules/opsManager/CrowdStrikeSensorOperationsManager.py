import time
import subprocess

from abstrakt.pythonModules.commandLine.layer_one.layer_two.runtimeParameterVerification import \
  RuntimeParameterVerification
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.daemonset.fsDaemonset import FalconSensorDaemonset
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.sidecar.fsSidecar import FalconSensorSidecar
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.kpa.fKPA import FalconKPA
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.kac.fsKAC import FalconKAC
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.iar.fIAR import IAR
from abstrakt.pythonModules.vendors.generic.VulnerableApps.vulnerableApps import VulnerableApps
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.detectionsContainer.detectionsContainer import \
  DetectionsContainer
from abstrakt.pythonModules.vendors.cloudServiceProviders.aws.awsCli.awsOps import AWSOps
from abstrakt.pythonModules.vendors.cloudServiceProviders.azure.azOps.azOps import AZOps
from abstrakt.pythonModules.vendors.cloudServiceProviders.gcp.gcpOps import GCPOps
from abstrakt.pythonModules.kubernetesOps.kubectlApplyYAMLs import KubectlApplyYAMLs
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading


class CrowdStrikeSensorOperationsManager:
  def __init__(self, falcon_sensor: bool, kernel_mode: bool, ebpf_mode: bool, kpa: bool, kac: bool, iar: bool,
               detections_container: bool, vulnerable_apps: bool, cloud_provider: str, cluster_type: str,
               cluster_name: str, cloud_region: str, falcon_client_id: str, falcon_client_secret: str, logger,
               monitor_namespaces=None, exclude_namespaces=None, falcon_image_tag=None,
               proxy_server=None, proxy_port=None, falcon_sensor_tags=None,
               azure_resource_group_name=None, gcp_project_name=None):
    self.falcon_sensor = falcon_sensor
    self.kernel_mode = kernel_mode
    self.ebpf_mode = ebpf_mode
    self.monitor_namespaces = monitor_namespaces
    self.exclude_namespaces = exclude_namespaces
    self.falcon_image_tag = falcon_image_tag
    self.proxy_server = proxy_server
    self.proxy_port = proxy_port
    self.falcon_sensor_tags = falcon_sensor_tags
    self.kpa = kpa
    self.kac = kac
    self.iar = iar
    self.cloud_provider = cloud_provider
    self.cluster_type = cluster_type
    self.cluster_name = cluster_name
    self.cloud_region = cloud_region
    self.azure_resource_group_name = azure_resource_group_name
    self.gcp_project_name = gcp_project_name
    self.falcon_client_id = falcon_client_id
    self.falcon_client_secret = falcon_client_secret
    self.detections_container = detections_container
    self.vulnerable_apps = vulnerable_apps
    self.logger = logger

  def verify_parameters(self):
    # ensure required parameters are passed with falcon sensor
    runtime = RuntimeParameterVerification(logger=self.logger)
    runtime.verify_crowdstrike_sensor_parameters(falcon_sensor=self.falcon_sensor,
                                                 kernel_mode=self.kernel_mode,
                                                 ebpf_mode=self.ebpf_mode,
                                                 monitor_namespaces=self.monitor_namespaces,
                                                 exclude_namespaces=self.exclude_namespaces,
                                                 falcon_image_tag=self.falcon_image_tag,
                                                 proxy_server=self.proxy_server,
                                                 proxy_port=self.proxy_port,
                                                 falcon_sensor_tags=self.falcon_sensor_tags,
                                                 kpa=self.kpa,
                                                 kac=self.kac,
                                                 iar=self.iar,
                                                 cloud_provider=self.cloud_provider,
                                                 cluster_type=self.cluster_type,
                                                 cluster_name=self.cluster_name,
                                                 cloud_region=self.cloud_region,
                                                 azure_resource_group_name=self.azure_resource_group_name,
                                                 gcp_project_name=self.gcp_project_name,
                                                 falcon_client_id=self.falcon_client_id,
                                                 falcon_client_secret=self.falcon_client_secret,
                                                 detections_container=self.detections_container,
                                                 vulnerable_apps=self.vulnerable_apps
                                                 )

  def get_cluster_credentials(self, cloud_provider, cluster_type, cluster_name, cluster_region=None,
                              azure_resource_group_name=None, gcp_project_name=None):
    if cloud_provider == 'aws':
      if cluster_type == 'eks-managed-node' or cluster_type == 'eks-self-managed-node' or cluster_type == 'eks-fargate':
        command = f'aws eks update-kubeconfig --region {cluster_region} --name {cluster_name}'
      elif cluster_type == 'ecs-fargate' or cluster_type == 'ecs-with-ec2':
        print('This cluster type is currently not supported. Exiting the program.')
        exit()
      else:
        print('This cluster type is currently not supported. Exiting the program.')
        exit()
    elif cloud_provider == 'azure':
      if cluster_type == 'aks':
        command = f'az aks get-credentials --resource-group {azure_resource_group_name} --name {cluster_name}'
      elif cluster_type == 'aci':
        print('This cluster type is currently not supported. Exiting the program.')
        exit()
      else:
        print('This cluster type is currently not supported. Exiting the program.')
        exit()
    elif cloud_provider == 'gcp':
      if cluster_type == 'gke-standard' or cluster_type == 'gke-autopilot':
        command = (f'gcloud container clusters get-credentials {cluster_name} --zone {cluster_region} --project'
                   f' {gcp_project_name}')
      else:
        print('This cluster type is currently not supported. Exiting the program.')
        exit()
    else:
      print('This cloud provider is currently not supported. Exiting the program.')
      exit()

    try:
      process = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)

      if process.stdout:
        self.logger.info(process.stdout)
      if process.stderr:
        self.logger.info(process.stderr)
    except subprocess.SubprocessError as e:
      self.logger.error(f'Error: {e}')
      print(f"Couldn't get the cluster {self.cluster_name} credentials. Existing the program.")
      exit()

  def start_falcon_sensor_deployment(self):
    # install falcon sensor in daemonset mode
    if self.cluster_type == 'eks-managed-node' or self.cluster_type == 'aks':
      sensor_mode = 'kernel' if self.kernel_mode else 'bpf' if self.ebpf_mode else 'bpf'
      daemonset = FalconSensorDaemonset(falcon_client_id=self.falcon_client_id,
                                        falcon_client_secret=self.falcon_client_secret,
                                        proxy_server=self.proxy_server,
                                        proxy_port=self.proxy_port,
                                        tags=self.falcon_sensor_tags,
                                        logger=self.logger,
                                        sensor_mode=sensor_mode)

      daemonset.deploy_falcon_sensor_daemonset(cloud_type=self.cloud_provider)
    elif self.cluster_type == 'gke-standard':
      daemonset = FalconSensorDaemonset(falcon_client_id=self.falcon_client_id,
                                        falcon_client_secret=self.falcon_client_secret,
                                        falcon_image_tag=self.falcon_image_tag,
                                        proxy_server=self.proxy_server,
                                        proxy_port=self.proxy_port,
                                        tags=self.falcon_sensor_tags,
                                        logger=self.logger,
                                        sensor_mode='bpf')

      daemonset.deploy_falcon_sensor_daemonset(cloud_type=self.cloud_provider)
    elif self.cluster_type == 'gke-autopilot':
      daemonset = FalconSensorDaemonset(falcon_client_id=self.falcon_client_id,
                                        falcon_client_secret=self.falcon_client_secret,
                                        falcon_image_tag=self.falcon_image_tag,
                                        proxy_server=self.proxy_server,
                                        proxy_port=self.proxy_port,
                                        tags=self.falcon_sensor_tags,
                                        logger=self.logger,
                                        sensor_mode='bpf')

      daemonset.deploy_falcon_sensor_daemonset(cloud_type=self.cloud_provider, cluster_type='gke-autopilot')
    elif self.cluster_type == 'eks-fargate':
      sidecar = FalconSensorSidecar(falcon_client_id=self.falcon_client_id,
                                    falcon_client_secret=self.falcon_client_secret,
                                    monitor_namespaces=self.monitor_namespaces,
                                    exclude_namespaces=self.exclude_namespaces,
                                    sensor_mode='sidecar',
                                    logger=self.logger)

      sidecar.deploy_falcon_sensor_sidecar(cloud=self.cloud_provider)
    else:
      print('The cluster type you mentioned is not yet supported. Existing falcon sensor deployment.\n')
      return

  def start_kpa_deployment(self):
    # install kubernetes protection agent
    kpa = FalconKPA(falcon_client_id=self.falcon_client_id, falcon_client_secret=self.falcon_client_secret,
                    logger=self.logger)
    kpa.deploy_falcon_kpa()

  def start_kac_deployment(self):
    # install kubernetes admission controller
    kac = FalconKAC(falcon_client_id=self.falcon_client_id, falcon_client_secret=self.falcon_client_secret,
                    logger=self.logger)
    kac.deploy_falcon_kac()

  def start_iar_deployment(self):
    # install image assessment at runtime
    iar = IAR(falcon_client_id=self.falcon_client_id, falcon_client_secret=self.falcon_client_secret,
              logger=self.logger)
    iar.deploy_falcon_iar()

  def start_vulnerable_app_deployment(self):
    # install vulnerable apps
    apps = VulnerableApps(logger=self.logger)
    apps.deploy_vulnerable_apps()

  def start_detections_container_deployment(self):
    # install detections container and generate artificial detections + misconfigurations
    detection_container = DetectionsContainer(logger=self.logger)
    if self.cluster_type == 'eks-fargate':
      detection_container.deploy_detections_containers(cluster_type=self.cluster_type, mode='sidecar')
    else:
      detection_container.deploy_detections_containers(cluster_type=self.cluster_type, mode='daemonset')

    print('Generating kubernetes misconfigurations...')

    try:
      if self.cluster_type == 'eks-fargate':
        yaml_applier = KubectlApplyYAMLs("./abstrakt/conf/crowdstrike/kubernetes/fargate-misconfigs/",
                                         logger=self.logger)
      else:
        yaml_applier = KubectlApplyYAMLs("./abstrakt/conf/crowdstrike/kubernetes/misconfigurations/",
                                         logger=self.logger)

      with MultiThreading() as mt:
        mt.run_with_progress_indicator(yaml_applier.apply_yaml_files, 1)

      print('Kubernetes misconfigurations generated successfully. They should appear in console in a few minutes.\n')
    except Exception as e:
      print(f'Error: {e}', 'Not all misconfigurations may have been generated. Check log file for details.')

  def start_crowdstrike_sensor_operations(self):
    # ensure required parameters are passed with falcon sensor
    self.verify_parameters()

    start_time = time.time()
    print("\nStart Time:", time.strftime("%Y-%m-%d %H:%M:%S\n", time.localtime(start_time)))

    if self.cloud_provider == 'aws':
      aws = AWSOps()
      aws.check_aws_login()
    elif self.cloud_provider == 'azure':
      azure = AZOps(logger=self.logger)
      azure.check_azure_login()
    elif self.cloud_provider == 'gcp':
      gcp = GCPOps(logger=self.logger)
      gcp.check_gcloud_login()
    else:
      print(f'Cloud provide "{self.cloud_provider}" is not supported. Existing the program.\n')
      exit()

    # Get cluster credentials
    self.get_cluster_credentials(cloud_provider=self.cloud_provider, cluster_type=self.cluster_type,
                                 cluster_name=self.cluster_name, cluster_region=self.cloud_region,
                                 azure_resource_group_name=self.azure_resource_group_name,
                                 gcp_project_name=self.gcp_project_name)

    # install falcon sensor in daemonset mode
    if self.falcon_sensor:
      self.start_falcon_sensor_deployment()

    # install kubernetes protection agent
    if self.kpa:
      self.start_kpa_deployment()

    # install kubernetes admission controller
    if self.kac:
      self.start_kac_deployment()

    # install image assessment at runtime
    if self.iar:
      self.start_iar_deployment()

    # install detections container and generate artificial detections + misconfigurations
    if self.detections_container:
      self.start_detections_container_deployment()

    # install vulnerable apps
    if self.vulnerable_apps:
      self.start_vulnerable_app_deployment()

    end_time = time.time()
    time_difference = end_time - start_time

    print(f'{"+" * 39}\n')
    print("End Time:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time)))

    print("Total deployment time (minutes):", int(time_difference) / 60, '\n')
