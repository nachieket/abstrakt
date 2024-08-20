import os
import random
import string

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


class ClusterOperationsManager:
  def __init__(self, config_file: str, install_falcon_sensor: bool, image_registry: str,
               sensor_image_tag: str, proxy_server: str, proxy_port: int, sensor_tags: str,
               install_kac: bool, kac_image_tag: str, install_iar: bool, iar_image_tag: str, install_kpa: bool,
               cloud_type: str, cluster_type: str, falcon_client_id: str, falcon_client_secret: str,
               install_detections_container: bool, install_vulnerable_apps: bool, generate_misconfigs: bool, logger):
    self.config_file: str = config_file
    self.install_falcon_sensor: bool = install_falcon_sensor
    self.image_registry: str = image_registry
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
    self.falcon_client_id: str = falcon_client_id
    self.falcon_client_secret: str = falcon_client_secret
    self.install_detections_container: bool = install_detections_container
    self.install_vulnerable_apps: bool = install_vulnerable_apps
    self.generate_misconfigs: bool = generate_misconfigs
    self.logger = logger

  def check_csp_login(self):
    cli = AWSOps()

    if self.cloud_type == 'aws':
      if cli.check_aws_login():
        return True
      else:
        print('AWS credentials profile validation failed. No valid default or saml profile found. '
              'Existing the Program.\n')
        exit()
    elif self.cloud_type == 'azure':
      az = AZOps(logger=self.logger)

      if az.check_azure_login():
        return True
    elif self.cloud_type == 'gcp':
      gcp = GCPOps(logger=self.logger)

      if not gcp.check_gcloud_login():
        print('You are not logged in to gcloud. Exiting program.')
        print("Try logging in to GCP using 'gcloud auth login' and try to run the program again\n")
        exit()
      else:
        return True
    else:
      return False

  def get_random_string(self, length=5):
    string_file = './abstrakt/conf/aws/eks/string.txt'

    try:
      if os.path.exists(string_file):
        with open(string_file, 'r') as file:
          append_string = file.readline()
          return append_string
      else:
        # Use ascii letters and digits for the string pool
        characters = string.ascii_letters + string.digits
        # Generate a random string
        random_string = ''.join(random.choices(characters, k=length))

        with open(string_file, 'w') as file:
          file.write(f'-{random_string}')

        return f'-{random_string}'
    except Exception as e:
      self.logger.error(e)
      return '-qwert'

  def start_kpa_deployment(self):
    # install kubernetes protection agent
    kpa = FalconKPA(falcon_client_id=self.falcon_client_id,
                    falcon_client_secret=self.falcon_client_secret,
                    logger=self.logger)
    kpa.deploy_falcon_kpa()

  def start_kac_deployment(self, cluster_name):
    # install kubernetes admission controller
    kac = FalconKAC(falcon_client_id=self.falcon_client_id,
                    falcon_client_secret=self.falcon_client_secret,
                    image_registry=self.image_registry,
                    kac_image_tag=self.kac_image_tag,
                    cluster_name=cluster_name,
                    cluster_type=self.cluster_type,
                    logger=self.logger)
    kac.deploy_falcon_kac()

  def start_iar_deployment(self, cluster_name):
    # install image assessment at runtime
    iar = IAR(falcon_client_id=self.falcon_client_id,
              falcon_client_secret=self.falcon_client_secret,
              image_registry=self.image_registry,
              iar_image_tag=self.iar_image_tag,
              cluster_name=cluster_name,
              cluster_type=self.cluster_type,
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

  def generate_misconfigurations(self):
    print(f"{'+' * 18}\nMisconfigurations\n{'+' * 18}\n")

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
