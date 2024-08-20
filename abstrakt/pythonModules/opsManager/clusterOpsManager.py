import os
import time
import random
import string

from abstrakt.pythonModules.commandLine.layer_one.layer_two.runtimeParameterVerification import \
  RuntimeParameterVerification
from abstrakt.pythonModules.vendors.cloudServiceProviders.aws.eksManagedNode.eksManagedNode import EKSManagedNode
from abstrakt.pythonModules.vendors.cloudServiceProviders.aws.eksFargate.eksFargate import EKSFargate
from abstrakt.pythonModules.vendors.cloudServiceProviders.aws.ecsFargate.ecsFargate import ECSFargate
from abstrakt.pythonModules.vendors.cloudServiceProviders.aws.ecsEC2.ecsEC2 import ECSec2
from abstrakt.pythonModules.vendors.cloudServiceProviders.azure.aks.aks import AKS
from abstrakt.pythonModules.vendors.cloudServiceProviders.azure.aci.aci import ACI
from abstrakt.pythonModules.vendors.cloudServiceProviders.gcp.gke import GKE
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
from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf


class ClusterOperationsManager:
  def __init__(self, config_file=None,
               install_falcon_sensor=None,
               falcon_image_repo=None,
               kernel_mode=None,
               ebpf_mode=None,
               falcon_sensor_image_tag=None,
               monitor_namespaces='all',
               exclude_namespaces=None,
               proxy_server=None,
               proxy_port=None,
               falcon_sensor_tags=None,
               install_kac=None,
               kac_image_tag=None,
               install_iar=None,
               iar_image_tag=None,
               install_kpa=None,
               falcon_client_id=None,
               falcon_client_secret=None,
               install_detections_container=None,
               install_vulnerable_apps=None,
               generate_misconfigs=None,
               gcp_project_id=None,
               cloud_type=None,
               cluster_type=None,
               logger=None,
               ecr_iam_policy_name=None,
               ecr_sensor_iam_role=None,
               ecr_kac_iam_role=None,
               ecr_iar_iam_role=None):
    self.config_file = config_file
    self.install_falcon_sensor = install_falcon_sensor
    self.falcon_image_repo = falcon_image_repo
    self.kernel_mode = kernel_mode
    self.ebpf_mode = ebpf_mode
    self.falcon_sensor_image_tag = falcon_sensor_image_tag
    self.monitor_namespaces = monitor_namespaces
    self.exclude_namespaces = exclude_namespaces
    self.proxy_server = proxy_server
    self.proxy_port = proxy_port
    self.falcon_sensor_tags = falcon_sensor_tags
    self.install_kac = install_kac
    self.kac_image_tag = kac_image_tag
    self.install_iar = install_iar
    self.iar_image_tag = iar_image_tag
    self.install_kpa = install_kpa
    self.falcon_client_id = falcon_client_id
    self.falcon_client_secret = falcon_client_secret
    self.install_detections_container = install_detections_container
    self.install_vulnerable_apps = install_vulnerable_apps
    self.generate_misconfigs = generate_misconfigs
    self.gcp_project_id = gcp_project_id
    self.cloud_type = cloud_type
    self.cluster_type = cluster_type
    self.logger = logger
    self.ecr_iam_policy_name = ecr_iam_policy_name
    self.ecr_iam_role_name = ecr_sensor_iam_role
    self.ecr_kac_iam_role = ecr_kac_iam_role
    self.ecr_iar_iam_role = ecr_iar_iam_role

  def verify_parameters(self):
    # ensure required parameters are passed with falcon sensor
    runtime = RuntimeParameterVerification(logger=self.logger)
    runtime.verify_csp_runtime_parameters(config_file=self.config_file,
                                          install_falcon_sensor=self.install_falcon_sensor,
                                          kernel_mode=self.kernel_mode,
                                          ebpf_mode=self.ebpf_mode,
                                          falcon_client_id=self.falcon_client_id,
                                          falcon_client_secret=self.falcon_client_secret,
                                          proxy_server=self.proxy_server,
                                          proxy_port=self.proxy_port,
                                          falcon_sensor_tags=self.falcon_sensor_tags,
                                          install_kpa=self.install_kpa,
                                          install_kac=self.install_kac,
                                          install_detections_container=self.install_detections_container,
                                          cloud_type=self.cloud_type,
                                          cluster_type=self.cluster_type,
                                          gcp_project_id=self.gcp_project_id
                                          )

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
    elif self.cluster_type == 'aks':
      aks_cluster = AKS(self.logger)
      aks_cluster_name = aks_cluster.deploy_aks_cluster(self.config_file)

      return aks_cluster_name
    elif self.cluster_type == 'aci':
      aci_cluster = ACI(self.logger)
      aci_cluster_name = aci_cluster.deploy_aci_cluster(self.config_file)

      return aci_cluster_name
    elif self.cluster_type == 'gke-standard':
      gke_cluster = GKE(self.logger)
      gke_standard_cluster_name = gke_cluster.deploy_gke_standard_cluster(self.config_file, self.gcp_project_id)

      return gke_standard_cluster_name
    elif self.cluster_type == 'gke-autopilot':
      gke_cluster = GKE(self.logger)
      gke_autopilot_cluster_name = gke_cluster.deploy_gke_autopilot_cluster(self.config_file, self.gcp_project_id)

      return gke_autopilot_cluster_name

  def start_falcon_sensor_deployment(self, cluster_name):
    # install falcon sensor in daemonset mode
    if self.cluster_type == 'eks-managed-node' or self.cluster_type == 'aks':
      if self.kernel_mode:
        sensor_mode = 'kernel'
      else:
        sensor_mode = 'bpf'

      if self.cluster_type == 'eks-managed-node':
        daemonset = FalconSensorDaemonset(falcon_client_id=self.falcon_client_id,
                                          falcon_client_secret=self.falcon_client_secret,
                                          image_registry=self.falcon_image_repo,
                                          sensor_image_tag=self.falcon_sensor_image_tag,
                                          proxy_server=self.proxy_server,
                                          proxy_port=self.proxy_port,
                                          sensor_tags=self.falcon_sensor_tags,
                                          sensor_mode=sensor_mode,
                                          cluster_name=cluster_name,
                                          logger=self.logger)
      else:
        daemonset = FalconSensorDaemonset(falcon_client_id=self.falcon_client_id,
                                          falcon_client_secret=self.falcon_client_secret,
                                          image_registry=self.falcon_image_repo,
                                          sensor_image_tag=self.falcon_sensor_image_tag,
                                          proxy_server=self.proxy_server,
                                          proxy_port=self.proxy_port,
                                          sensor_tags=self.falcon_sensor_tags,
                                          sensor_mode=sensor_mode,
                                          logger=self.logger)

      daemonset.deploy_falcon_sensor_daemonset()
    elif self.cluster_type == 'gke-standard':
      daemonset = FalconSensorDaemonset(falcon_client_id=self.falcon_client_id,
                                        falcon_client_secret=self.falcon_client_secret,
                                        image_registry=self.falcon_image_repo,
                                        sensor_image_tag=self.falcon_sensor_image_tag,
                                        proxy_server=self.proxy_server,
                                        proxy_port=self.proxy_port,
                                        sensor_tags=self.falcon_sensor_tags,
                                        sensor_mode='bpf',
                                        logger=self.logger)

      daemonset.deploy_falcon_sensor_daemonset()
    elif self.cluster_type == 'gke-autopilot':
      daemonset = FalconSensorDaemonset(falcon_client_id=self.falcon_client_id,
                                        falcon_client_secret=self.falcon_client_secret,
                                        image_registry=self.falcon_image_repo,
                                        sensor_image_tag=self.falcon_sensor_image_tag,
                                        proxy_server=self.proxy_server,
                                        proxy_port=self.proxy_port,
                                        sensor_tags=self.falcon_sensor_tags,
                                        sensor_mode='bpf',
                                        logger=self.logger,
                                        cluster_type='gke-autopilot')

      daemonset.deploy_falcon_sensor_daemonset()
    elif self.cluster_type == 'eks-fargate':
      sidecar = FalconSensorSidecar(falcon_client_id=self.falcon_client_id,
                                    falcon_client_secret=self.falcon_client_secret,
                                    monitor_namespaces=self.monitor_namespaces,
                                    exclude_namespaces=self.exclude_namespaces,
                                    image_registry=self.falcon_image_repo,
                                    falcon_sensor_image_tag=self.falcon_sensor_image_tag,
                                    proxy_server=self.proxy_server,
                                    proxy_port=self.proxy_port,
                                    sensor_tags=self.falcon_sensor_tags,
                                    sensor_mode='sidecar',
                                    cluster_name=cluster_name,
                                    logger=self.logger,
                                    iam_policy=self.ecr_iam_policy_name,
                                    sensor_iam_role=self.ecr_iam_role_name)

      sidecar.deploy_falcon_sensor_sidecar()
    else:
      print('The cluster type you mentioned is not yet supported. Existing falcon sensor deployment.\n')
      return

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
                    image_registry=self.falcon_image_repo,
                    kac_image_tag=self.kac_image_tag,
                    cluster_name=cluster_name,
                    cluster_type=self.cluster_type,
                    logger=self.logger)
    kac.deploy_falcon_kac()

  def start_iar_deployment(self, cluster_name):
    # install image assessment at runtime
    iar = IAR(falcon_client_id=self.falcon_client_id,
              falcon_client_secret=self.falcon_client_secret,
              image_registry=self.falcon_image_repo,
              iar_image_tag=self.iar_image_tag,
              cluster_name=cluster_name,
              cluster_type=self.cluster_type,
              iam_policy=self.ecr_iam_policy_name,
              iar_iam_role=self.ecr_iar_iam_role,
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

      printf('Kubernetes misconfigurations generated successfully. They should appear in console in a few minutes.\n',
             logger=self.logger)
    except Exception as e:
      printf(f'Error: {e}', 'Not all misconfigurations may have been generated. Check log file for details.',
             logger=self.logger)

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

  def start_cluster_operations(self):
    # ensure required parameters are passed with falcon sensor
    self.verify_parameters()

    start_time = time.time()
    printf("\nStart Time:", time.strftime("%Y-%m-%d %H:%M:%S\n", time.localtime(start_time)),
           logger=self.logger)

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

    end_time = time.time()
    time_difference = end_time - start_time

    print(f'{"+" * 39}\n')
    printf("End Time:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time)), logger=self.logger)

    print(f'Total deployment time: {int(int(time_difference) / 60)} minute/s and {int(time_difference) % 60} seconds\n')
