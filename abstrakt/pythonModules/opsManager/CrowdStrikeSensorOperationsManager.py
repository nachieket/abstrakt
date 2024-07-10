import os
import time
import json
import subprocess
from kubernetes import client, config

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
from abstrakt.pythonModules.kubernetesOps.helmOps import HelmOps
from abstrakt.pythonModules.vendors.cloudServiceProviders.aws.awsCli.awsOps import AWSOps
from abstrakt.pythonModules.vendors.cloudServiceProviders.azure.azOps.azOps import AZOps
from abstrakt.pythonModules.vendors.cloudServiceProviders.gcp.gcpOps import GCPOps
from abstrakt.pythonModules.kubernetesOps.kubectlApplyYAMLs import KubectlApplyYAMLs
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading


class CrowdStrikeSensorOperationsManager:
  def __init__(self, falcon_sensor=None,
               kernel_mode=None,
               ebpf_mode=None,
               monitor_namespaces=None,
               exclude_namespaces=None,
               falcon_image_repo=None,
               falcon_image_tag=None,
               proxy_server=None,
               proxy_port=None,
               falcon_sensor_tags=None,
               aws_region=None,
               aws_cluster_name=None,
               azure_resource_group_name=None,
               azure_cluster_name=None,
               gcp_region=None,
               gcp_cluster_name=None,
               gcp_project_id=None,
               kpa=None,
               kac=None,
               iar=None,
               detections_container=None,
               vulnerable_apps=None,
               falcon_client_id=None,
               falcon_client_secret=None,
               ecr_iam_policy_name=None,
               ecr_iam_role_name=None,
               logger=None):
    self.falcon_sensor = falcon_sensor
    self.kernel_mode = kernel_mode
    self.ebpf_mode = ebpf_mode
    self.monitor_namespaces = monitor_namespaces
    self.exclude_namespaces = exclude_namespaces
    self.falcon_image_repo = falcon_image_repo
    self.falcon_image_tag = falcon_image_tag
    self.proxy_server = proxy_server
    self.proxy_port = proxy_port
    self.falcon_sensor_tags = falcon_sensor_tags
    self.aws_region = aws_region
    self.aws_cluster_name = aws_cluster_name
    self.azure_resource_group_name = azure_resource_group_name
    self.azure_cluster_name = azure_cluster_name
    self.gcp_region = gcp_region
    self.gcp_cluster_name = gcp_cluster_name
    self.gcp_project_id = gcp_project_id
    self.kpa = kpa
    self.kac = kac
    self.iar = iar
    self.detections_container = detections_container
    self.vulnerable_apps = vulnerable_apps
    self.falcon_client_id = falcon_client_id
    self.falcon_client_secret = falcon_client_secret
    self.ecr_iam_policy_name = ecr_iam_policy_name
    self.ecr_iam_role_name = ecr_iam_role_name
    self.logger = logger

  def run_command(self, command, output=False):
    try:
      result = subprocess.run(command, shell=True, check=True, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)

      if result.returncode == 0:
        if output is True:
          if result.stdout and result.stderr:
            self.logger.info(result.stdout)
            self.logger.error(result.stderr)
            return result.stdout, result.stderr
          elif result.stdout and not result.stderr:
            self.logger.info(result.stdout)
            return result.stdout, None
          elif result.stderr and not result.stdout:
            self.logger.info(result.stderr)
            return None, result.stderr
        else:
          if result.stdout:
            self.logger.info(result.stdout)
          if result.stderr:
            self.logger.error(result.stderr)
          return True
      else:
        return False
    except subprocess.CalledProcessError as e:
      self.logger.error(f"Command failed with error: {e.stderr}")
      return False

  def verify_parameters(self, cluster_type=None):
    pass
    # ensure required parameters are passed with falcon sensor
    runtime = RuntimeParameterVerification(logger=self.logger)

    runtime.verify_crowdstrike_sensor_parameters(falcon_sensor=self.falcon_sensor,
                                                 kernel_mode=self.kernel_mode,
                                                 ebpf_mode=self.ebpf_mode,
                                                 monitor_namespaces=self.monitor_namespaces,
                                                 exclude_namespaces=self.exclude_namespaces,
                                                 falcon_image_repo=self.falcon_image_repo,
                                                 falcon_image_tag=self.falcon_image_tag,
                                                 proxy_server=self.proxy_server,
                                                 proxy_port=self.proxy_port,
                                                 falcon_sensor_tags=self.falcon_sensor_tags,
                                                 aws_region=self.aws_region,
                                                 aws_cluster_name=self.aws_cluster_name,
                                                 azure_resource_group_name=self.azure_resource_group_name,
                                                 azure_cluster_name=self.azure_cluster_name,
                                                 gcp_region=self.gcp_region,
                                                 gcp_cluster_name=self.gcp_cluster_name,
                                                 gcp_project_id=self.gcp_project_id,
                                                 kpa=self.kpa,
                                                 kac=self.kac,
                                                 iar=self.iar,
                                                 detections_container=self.detections_container,
                                                 vulnerable_apps=self.vulnerable_apps,
                                                 falcon_client_id=self.falcon_client_id,
                                                 falcon_client_secret=self.falcon_client_secret,
                                                 ecr_iam_policy_name=self.ecr_iam_policy_name,
                                                 ecr_iam_role_name=self.ecr_iam_role_name,
                                                 logger=self.logger,
                                                 cluster_type=cluster_type
                                                 )

  def get_cluster_credentials(self):
    if self.aws_cluster_name and self.aws_region:
      command = f'aws eks update-kubeconfig --region {self.aws_region} --name {self.aws_cluster_name}'
    elif self.azure_cluster_name and self.azure_resource_group_name:
      command = (f'az aks get-credentials --resource-group {self.azure_resource_group_name} --name'
                 f' {self.azure_cluster_name} --overwrite-existing')
    elif self.gcp_cluster_name and self.gcp_region and self.gcp_project_id:
      command = (f'gcloud container clusters get-credentials {self.gcp_cluster_name} --zone {self.gcp_region} --project'
                 f' {self.gcp_project_id}')
    else:
      print(f"Couldn't get the cluster credentials. One of the required runtime parameters may be missing Existing the "
            f"program.")
      exit()

    try:
      process = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)

      # Load the kubeconfig file
      config.load_kube_config()

      if process.stdout:
        self.logger.info(process.stdout)
      if process.stderr:
        self.logger.info(process.stderr)
    except subprocess.SubprocessError as e:
      self.logger.error(f'Error: {e}')
      print(f"Couldn't get the cluster credentials. Existing the program.")
      exit()

  def get_eks_cluster_type(self, cluster_name, region):
    eks_managed_node = None
    eks_self_managed_node = None
    eks_fargate = None

    # cluster_name = nodes.items[0].metadata.labels['alpha.eksctl.io/cluster-name']

    try:
      eks_update_command = f'aws eks update-kubeconfig --region {region} --name {cluster_name}'
      result = subprocess.run(eks_update_command, shell=True, check=True, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)

      # Load the kubeconfig file
      config.load_kube_config()

      if result.returncode == 0:
        # Create API clients for different API groups
        v1 = client.CoreV1Api()

        nodes = v1.list_node()

        for node in nodes.items:
          if node.metadata.labels.get('eks.amazonaws.com/nodegroup') is not None:
            eks_managed_node = True
          elif node.metadata.labels.get('eks.amazonaws.com/compute-type') is not None:
            eks_fargate = True
          else:
            eks_self_managed_node = True

        return eks_managed_node, eks_self_managed_node, eks_fargate
      else:
        return None, None, None
    except Exception as e:
      self.logger.error({e})
      return None, None, None

  def get_all_gcp_projects(self):
    """
    Executes a gcloud command to list all project IDs and returns them as a list.
    """
    projects = []

    try:
      command = 'gcloud projects list --format="json(projectId)"'
      process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
      output, err = process.communicate()

      if err:
        raise RuntimeError(f"Error running gcloud command: {err.decode()}")
      raw_data = json.loads(output.decode())

      for data in raw_data:
        projects.append(data['projectId'])

      return projects
    except Exception as e:
      self.logger.error(e)
      return None

  def get_gke_clusters(self, gcp_project_id):
    try:
      standard_gke_clusters = {}
      autopilot_gke_clusters = {}

      try:
        command = f'gcloud container clusters list --project {gcp_project_id} --format="json()"'
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
        output, err = process.communicate()

        output = json.loads(output)

        if len(output) < 1:
          return None, None

        for x in output:
          if 'autopilot' in x and 'enabled' in x['autopilot']:
            autopilot_gke_clusters[x['name']] = {}

            if 'currentNodeCount' in x:
              autopilot_gke_clusters[x['name']] = int(x['currentNodeCount'])
            else:
              autopilot_gke_clusters[x['name']] = 0
          else:
            standard_gke_clusters[x['name']] = {}

            if 'currentNodeCount' in x:
              standard_gke_clusters[x['name']] = int(x['currentNodeCount'])
            else:
              standard_gke_clusters[x['name']] = 0

        return standard_gke_clusters, autopilot_gke_clusters

      except subprocess.CalledProcessError as err:
        self.logger.error(f"Error processing cluster information for project {gcp_project_id}: {err.output}\n")
        return None, None
      except json.decoder.JSONDecodeError as err:
        self.logger.error(f'Error: {err}')
        self.logger.error(f'Kubernetes Engine API has not been used in project {gcp_project_id}\n')
        return None, None
      except Exception as err:
        self.logger.error(f'Generic error: {err}\n')
        return None, None

    except RuntimeError as err:
      print(f"An error occurred: {err}")
      return None, None

  def get_gke_cluster_type(self, cluster_name, gcp_project_id):
    gke_standard_clusters, gke_autopilot_clusters = self.get_gke_clusters(gcp_project_id=gcp_project_id)

    if cluster_name in gke_standard_clusters:
      return 'gke-standard'
    elif cluster_name in gke_autopilot_clusters:
      return 'gke-autopilot'
    else:
      return None

    # gke_standard = None
    # gke_autopilot = None
    #
    # try:
    #   gcloud_update_command = (f'gcloud container clusters get-credentials {cluster_name} --zone {region} --project '
    #                            f'{project_name}')
    #
    #   self.logger.info(f'Executing command: {gcloud_update_command}')
    #
    #   result = subprocess.run(gcloud_update_command, shell=True, check=True, text=True, stdout=subprocess.PIPE,
    #                           stderr=subprocess.PIPE)
    #
    #   # Load the kubeconfig file
    #   config.load_kube_config()
    #
    #   if result.returncode == 0:
    #     # Create API clients for different API groups
    #     v1 = client.CoreV1Api()
    #
    #     nodes = v1.list_node()
    #
    #     for node in nodes.items:
    #       if node.metadata.labels.get('addon.gke.io/node-local-dns-ds-ready') is not None:
    #         gke_autopilot = True
    #       else:
    #         gke_standard = True
    #
    #     if gke_standard:
    #       return 'gke-standard'
    #     elif gke_autopilot:
    #       return 'gke-autopilot'
    #
    # except Exception as e:
    #   self.logger.error(f'Error: {e}')
    #   return None

  def get_cluster_type(self):
    if self.aws_cluster_name and self.aws_region:
      eks_managed_node, eks_self_managed_node, eks_fargate = self.get_eks_cluster_type(
        cluster_name=self.aws_cluster_name, region=self.aws_region)

      if eks_managed_node and eks_fargate:
        return 'eks-managed-node-with-eks-fargate'
      elif eks_managed_node and not eks_fargate:
        return 'eks-managed-node'
      elif eks_self_managed_node and eks_fargate:
        return 'eks-self-managed-node-with-eks-fargate'
      elif eks_self_managed_node and not eks_fargate:
        return 'eks-self-managed-node'
      elif eks_fargate and not eks_managed_node and not eks_self_managed_node:
        return 'eks-fargate'
    elif self.azure_cluster_name and self.azure_resource_group_name:
      return 'azure-aks'
    elif self.gcp_cluster_name and self.gcp_region and self.gcp_project_id:
      gke_cluster_type = self.get_gke_cluster_type(cluster_name=self.gcp_cluster_name,
                                                   gcp_project_id=self.gcp_project_id)
      if gke_cluster_type == 'gke-standard':
        return 'gke-standard'
      elif gke_cluster_type == 'gke-autopilot':
        return 'gke-autopilot'
    else:
      return None

  def start_falcon_sensor_daemonset_deployment(self, sensor_mode, cluster_type=None):
    daemonset = FalconSensorDaemonset(falcon_client_id=self.falcon_client_id,
                                      falcon_client_secret=self.falcon_client_secret,
                                      falcon_image_repo=self.falcon_image_repo,
                                      falcon_image_tag=self.falcon_image_tag,
                                      proxy_server=self.proxy_server,
                                      proxy_port=self.proxy_port,
                                      tags=self.falcon_sensor_tags,
                                      logger=self.logger,
                                      sensor_mode=sensor_mode,
                                      cluster_type=cluster_type)

    daemonset.deploy_falcon_sensor_daemonset()

  def start_falcon_sensor_sidecar_deployment(self):
    sidecar = FalconSensorSidecar(falcon_client_id=self.falcon_client_id,
                                  falcon_client_secret=self.falcon_client_secret,
                                  monitor_namespaces=self.monitor_namespaces,
                                  exclude_namespaces=self.exclude_namespaces,
                                  falcon_image_repo=self.falcon_image_repo,
                                  falcon_image_tag=self.falcon_image_tag,
                                  ecr_iam_policy_name=self.ecr_iam_policy_name,
                                  ecr_iam_role_name=self.ecr_iam_role_name,
                                  proxy_server=self.proxy_server,
                                  proxy_port=self.proxy_port,
                                  tags=self.falcon_sensor_tags,
                                  sensor_mode='sidecar',
                                  logger=self.logger)

    os.environ['EKS_FARGATE_CLUSTER_NAME'] = self.aws_cluster_name

    sidecar.deploy_falcon_sensor_sidecar()

  def start_falcon_sensor_deployment(self, cluster_type):
    if self.kernel_mode:
      sensor_mode = 'kernel'
    else:
      sensor_mode = 'bpf'

    if (cluster_type == 'eks-managed-node' or cluster_type == 'eks-self-managed-node' or cluster_type == 'azure-aks'
       or cluster_type == 'gke-standard' or cluster_type == 'gke-autopilot'):
      self.start_falcon_sensor_daemonset_deployment(sensor_mode=sensor_mode, cluster_type=cluster_type)
    elif cluster_type == 'eks-managed-node-with-eks-fargate':
      # TODO: Implement the method
      pass
    elif cluster_type == 'eks-self-managed-node-with-eks-fargate':
      # TODO: Implement the method
      pass
    elif cluster_type == 'eks-fargate':
      self.start_falcon_sensor_sidecar_deployment()

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

  def start_detections_container_deployment(self, cluster_type):
    # install detections container and generate artificial detections + misconfigurations
    detection_container = DetectionsContainer(logger=self.logger)
    if cluster_type == 'eks-fargate':
      detection_container.deploy_detections_containers(cluster_type=cluster_type, mode='sidecar')
    else:
      detection_container.deploy_detections_containers(cluster_type=cluster_type, mode='daemonset')

    print('Generating kubernetes misconfigurations...')

    try:
      if cluster_type == 'eks-fargate':
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

  def check_csp_login(self):
    cli = AWSOps()

    if self.aws_region and self.aws_cluster_name:
      if cli.check_aws_login():
        return True
      else:
        print('AWS credentials profile validation failed. No valid default or saml profile found. '
              'Existing the Program.\n')
        exit()
    elif self.azure_cluster_name and self.azure_resource_group_name:
      az = AZOps(logger=self.logger)

      if az.check_azure_login():
        return True
    elif self.gcp_region and self.gcp_cluster_name and self.gcp_project_id:
      gcp = GCPOps(logger=self.logger)

      if not gcp.check_gcloud_login():
        print('You are not logged in to gcloud. Exiting program.')
        print("Try logging in to GCP using 'gcloud auth login' and try to run the program again\n")
        exit()
      else:
        return True
    else:
      return False

  def start_crowdstrike_sensor_operations(self):
    # ensure required parameters are passed with falcon sensor
    self.verify_parameters()

    start_time = time.time()
    print("\nStart Time:", time.strftime("%Y-%m-%d %H:%M:%S\n", time.localtime(start_time)))

    # Check Cloud Service Provider Login
    if not self.check_csp_login():
      print(f'Cloud provider session is not logged in. Attempt manual login to cloud provider before running '
            f'Abstrakt. \n')
      exit()

    # Get cluster credentials
    self.get_cluster_credentials()

    # Get cluster type
    cluster_type = self.get_cluster_type()

    if cluster_type is None:
      print('Error: Cluster type could not be determined. Exiting the program.')
      exit()

    # ensure required parameters are passed with falcon sensor
    self.verify_parameters(cluster_type=cluster_type)

    if cluster_type is not None:
      # install falcon sensor in daemonset mode
      if self.falcon_sensor:
        self.start_falcon_sensor_deployment(cluster_type=cluster_type)
    else:
      print('Cluster type cannot be determined. Installation will not proceed.\n')

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
      self.start_detections_container_deployment(cluster_type=cluster_type)

    # install vulnerable apps
    if self.vulnerable_apps:
      self.start_vulnerable_app_deployment()

    end_time = time.time()
    time_difference = end_time - start_time

    print(f'{"+" * 39}\n')
    print("End Time:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time)))

    print(f'Total deployment time: {int(int(time_difference) / 60)} minute/s and {int(time_difference) % 60} seconds\n')

  def delete_crowdstrike_sensors(self):
    start_time = time.time()
    print("\nStart Time:", time.strftime("%Y-%m-%d %H:%M:%S\n", time.localtime(start_time)))

    # Check Cloud Service Provider Login
    if not self.check_csp_login():
      print(f'Cloud provider session is not logged in. Attempt manual login to cloud provider before running '
            f'Abstrakt. \n')
      exit()

    # Get cluster credentials
    self.get_cluster_credentials()

    # Get cluster type
    cluster_type = self.get_cluster_type()

    if cluster_type is None:
      print('Error: Cluster type could not be determined. Exiting the program.')
      exit()

    helm = HelmOps(logger=self.logger)

    if self.falcon_sensor:
      if helm.is_helm_chart_deployed(release_name='daemonset-falcon-sensor', namespace='falcon-system'):
        print('Deleting Falcon Sensor...')
        helm.run_helm_delete("daemonset-falcon-sensor", "falcon-system")
      elif helm.is_helm_chart_deployed(release_name='falcon-helm', namespace='falcon-system'):
        print('Deleting Falcon Sensor...')
        helm.run_helm_delete("falcon-helm", "falcon-system")

    if self.kpa:
      if helm.is_helm_chart_deployed(release_name='kpagent', namespace='falcon-kubernetes-protection'):
        print('Deleting Kubernetes Protections Agent...')
        helm.run_helm_delete("kpagent", "falcon-kubernetes-protection")

    if self.kac:
      if helm.is_helm_chart_deployed(release_name='falcon-kac', namespace='falcon-kac'):
        print('Deleting Kubernetes Admission Controller...')
        helm.run_helm_delete("falcon-kac", "falcon-kac")

    if self.iar:
      if helm.is_helm_chart_deployed(release_name='image-analyzer', namespace='falcon-image-analyzer'):
        print('Deleting Image Assessment at Runtime...')
        helm.run_helm_delete("image-analyzer", "falcon-image-analyzer")
