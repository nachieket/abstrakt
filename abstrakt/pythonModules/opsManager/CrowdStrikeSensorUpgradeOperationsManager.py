import time
import json
import inspect
import subprocess
from typing import Optional
from kubernetes import client, config

from abstrakt.pythonModules.vendors.cloudServiceProviders.gcp.gcpOps import GCPOps
from abstrakt.pythonModules.vendors.cloudServiceProviders.azure.azOps.azOps import AZOps
from abstrakt.pythonModules.vendors.cloudServiceProviders.aws.awsCli.awsOps import AWSOps


class CrowdStrikeSensorInstallOperationsManager:
  def __init__(self, falcon_sensor=None,
               registry=None,
               repository=None,
               sensor_image_tag=None,
               aws_cluster=None,
               aws_region=None,
               aws_ecr_iam_policy=None,
               aws_sensor_iam_role=None,
               aws_kac_iam_role=None,
               aws_iar_iam_role=None,
               az_cluster=None,
               az_resource_group=None,
               az_location=None,
               az_acr_resource_group=None,
               az_sp_name=None,
               az_sp_pass=None,
               az_acr_sub_id=None,
               gcp_cluster=None,
               gcp_location=None,
               gcp_network=None,
               gcp_project_id=None,
               gcp_service_account=None,
               kac=None,
               kac_image_tag=None,
               iar=None,
               iar_image_tag=None,
               falcon_client_id=None,
               falcon_client_secret=None,
               logger=None):
    self.falcon_sensor = falcon_sensor
    self.registry = registry
    self.repository = repository
    self.sensor_image_tag = sensor_image_tag
    self.aws_cluster = aws_cluster
    self.aws_region = aws_region
    self.aws_ecr_iam_policy = aws_ecr_iam_policy
    self.aws_sensor_iam_role = aws_sensor_iam_role
    self.aws_kac_iam_role = aws_kac_iam_role
    self.aws_iar_iam_role = aws_iar_iam_role
    self.az_cluster = az_cluster
    self.az_resource_group = az_resource_group
    self.az_location = az_location
    self.az_acr_resource_group = az_acr_resource_group
    self.az_sp_name = az_sp_name
    self.az_sp_pass = az_sp_pass
    self.az_acr_sub_id = az_acr_sub_id
    self.gcp_cluster = gcp_cluster
    self.gcp_location = gcp_location
    self.gcp_network = gcp_network
    self.gcp_project_id = gcp_project_id
    self.gcp_service_account = gcp_service_account
    self.kac = kac
    self.kac_image_tag = kac_image_tag
    self.iar = iar
    self.iar_image_tag = iar_image_tag
    self.falcon_client_id = falcon_client_id
    self.falcon_client_secret = falcon_client_secret
    self.logger = logger

  def run_command(self, command: str) -> Optional[str]:
    """
    Executes a shell command and captures its output.

    Args:
        command (str): The shell command to run.

    Returns:
        Optional[str]: The standard output of the command if successful, None otherwise.
    """
    try:
      result = subprocess.run(
        command,
        shell=True,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
      )

      # Log stderr if any, but do not treat it as a failure
      if result.stderr:
        self.logger.error(f"Command stderr: {result.stderr}")

      if result.stdout:
        self.logger.info(f"Command output: {result.stdout}")

      # Return stdout if it exists, else return an empty string
      return result.stdout if result.stdout else '//EMPTY'

    except subprocess.CalledProcessError as e:
      self.logger.error(f"Command failed with error: {e.stderr}")
      return None
    except Exception as e:
      self.logger.error(f"Unexpected error occurred: {e}")
      return None

  def get_cluster_credentials(self):
    if self.aws_cluster and self.aws_region:
      command = f'aws eks update-kubeconfig --region {self.aws_region} --name {self.aws_cluster}'
    elif self.az_cluster and self.az_resource_group:
      command = (f'az aks get-credentials --resource-group {self.az_resource_group} --name'
                 f' {self.az_cluster} --overwrite-existing')
    elif self.gcp_cluster and self.gcp_location and self.gcp_project_id:
      command = (f'gcloud container clusters get-credentials {self.gcp_cluster} --zone {self.gcp_location} --project'
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
      result = subprocess.run(eks_update_command, shell=True, check=True, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

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

  def get_cluster_type(self):
    if self.aws_cluster and self.aws_region:
      eks_managed_node, eks_self_managed_node, eks_fargate = self.get_eks_cluster_type(
        cluster_name=self.aws_cluster, region=self.aws_region)

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
    elif self.az_cluster and self.az_resource_group:
      return 'azure-aks'
    elif self.gcp_cluster and self.gcp_location and self.gcp_project_id:
      gke_cluster_type = self.get_gke_cluster_type(cluster_name=self.gcp_cluster,
                                                   gcp_project_id=self.gcp_project_id)
      if gke_cluster_type == 'gke-standard':
        return 'gke-standard'
      elif gke_cluster_type == 'gke-autopilot':
        return 'gke-autopilot'
    else:
      return None

  def start_falcon_sensor_upgrade(self, cluster_type):
    if cluster_type == 'eks-managed-node':
      pass
    elif cluster_type == 'eks-fargate':
      pass
    elif cluster_type == 'aks' or cluster_type == 'azure-aks':
      pass
    elif cluster_type == 'gke-standard' or cluster_type == 'gke-autopilot':
      pass
    elif cluster_type == 'eks-managed-node-with-eks-fargate':
      pass
    elif cluster_type == 'eks-self-managed-node-with-eks-fargate':
      pass

  def start_kac_upgrade(self, cluster_type):
    if cluster_type == 'eks-managed-node':
      pass
    elif cluster_type == 'eks-fargate':
      pass
    elif cluster_type == 'aks' or cluster_type == 'azure-aks':
      pass
    elif cluster_type == 'gke-standard' or cluster_type == 'gke-autopilot':
      pass
    elif cluster_type == 'eks-managed-node-with-eks-fargate':
      pass
    elif cluster_type == 'eks-self-managed-node-with-eks-fargate':
      pass

  def start_iar_upgrade(self, cluster_type):
    if cluster_type == 'eks-managed-node':
      pass
    elif cluster_type == 'eks-fargate':
      pass
    elif cluster_type == 'aks' or cluster_type == 'azure-aks':
      pass
    elif cluster_type == 'gke-standard' or cluster_type == 'gke-autopilot':
      pass
    elif cluster_type == 'eks-managed-node-with-eks-fargate':
      pass
    elif cluster_type == 'eks-self-managed-node-with-eks-fargate':
      pass

  def check_csp_login(self):
    cli = AWSOps()

    if self.aws_region and self.aws_cluster:
      if cli.check_aws_login():
        return True
      else:
        print('AWS credentials profile validation failed. No valid default or saml profile found. '
              'Existing the Program.\n')
        exit()
    elif self.az_cluster and self.az_resource_group:
      az = AZOps(logger=self.logger)

      if az.check_azure_login():
        return True
    elif self.gcp_location and self.gcp_cluster and self.gcp_project_id:
      gcp = GCPOps(logger=self.logger)

      if not gcp.check_gcloud_login():
        print('You are not logged in to gcloud. Exiting program.')
        print("Try logging in to GCP using 'gcloud auth login' and try to run the program again\n")
        exit()
      else:
        return True
    else:
      return False

  def start_crowdstrike_upgrade_operations(self):
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

    end_time = time.time()
    time_difference = end_time - start_time

    print(f'{"+" * 39}\n')
    print("End Time:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time)))

    print(f'Total deployment time: {int(int(time_difference) / 60)} minute/s and {int(time_difference) % 60} seconds\n')
