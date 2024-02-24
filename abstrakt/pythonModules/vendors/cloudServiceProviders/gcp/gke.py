import subprocess

from abstrakt.pythonModules.parseConfigFile.parseConfigFile import ParseConfigFile
from abstrakt.pythonModules.terraformOps.convertToTFVars import ToTFVars
from abstrakt.pythonModules.kubernetesOps.updateKubeConfig import UpdateKubeConfig
from abstrakt.pythonModules.terraformOps.executeTerraform import ExecuteTerraform


class GKE:
  def __init__(self, logger):
    self.logger = logger

  def check_gcloud_login(self) -> bool:
    """Checks if gcloud is logged in and prompts for login if needed."""
    try:
      # Attempt to retrieve account information
      account = subprocess.check_output(["gcloud", "config", "get-value", "account"],
                                        stderr=subprocess.PIPE, text=True)
      if not account:
        print('You are not logged in to gcloud. Logging in...')
        subprocess.call(["gcloud", "auth", "login"])
      else:
        print(f"You are currently logged in to gcloud as: {account}")

      return True
    except subprocess.CalledProcessError as e:
      self.logger.error(e)
      return False

  def deploy_gke_cos_cluster(self, config_file):
    # Initialize necessary modules
    conf = ParseConfigFile(self.logger)
    convert = ToTFVars(self.logger)
    tf = ExecuteTerraform(self.logger)

    print('Deploying GKE COS Cluster...\n')

    try:
      if not self.check_gcloud_login():
        print('You are not logged in to gcloud. Exiting program.')
        print("Try logging in to GCP using 'gcloud auth login' and try to run the program again\n")
        exit()

      # Get GKE COS config file parameters
      gke_cos_parameters, tags = conf.read_gke_cos_config_file(config_file)

      convert.convert_gke_cos_to_tfvars(gke_cos_parameters, tags)

      gke_cos_terraform_code_path = './abstrakt/terraformModules/gcp/gke/cos/'

      # Execute Terraform commands to deploy AKS cluster
      if (
        tf.execute_terraform_get(path=gke_cos_terraform_code_path) and
        tf.execute_terraform_init(path=gke_cos_terraform_code_path)
      ):
        plan_status = tf.execute_terraform_plan(path=gke_cos_terraform_code_path)

        if plan_status == 0:
          print('Terraform execution to deploy GKE COS cluster failed. Exiting the program.\n')
          exit()
        elif plan_status == 1:
          if tf.execute_terraform_apply(path=gke_cos_terraform_code_path):
            kube_config = UpdateKubeConfig(self.logger)
            kube_config.update_kubeconfig(cloud='gcp', cluster_name=gke_cos_parameters['cluster_name'],
                                          region=gke_cos_parameters['region'])

            print('Terraform execution to deploy GKE COS cluster completed successfully.\n')
          else:
            print('Terraform execution to deploy GKE COS cluster failed. Exiting the program.\n')
            exit()
        elif plan_status == 2:
          kube_config = UpdateKubeConfig(self.logger)
          kube_config.update_kubeconfig(cloud='gcp', cluster_name=gke_cos_parameters['cluster_name'],
                                        region=gke_cos_parameters['region'])
          print('Terraform execution to create GKE COS cluster did not need any changes.\n')
      else:
        self.logger.error('Failed to deploy GKE COS cluster. Exiting the program.\n')
        exit()
    except Exception as e:
      self.logger.error(f'Error: {e}\n')
      self.logger.error('Exiting the program.\n')
      exit()

  def deploy_gke_autopilot_cluster(self, config_file):
    # Initialize necessary modules
    conf = ParseConfigFile(self.logger)
    convert = ToTFVars(self.logger)
    tf = ExecuteTerraform(self.logger)

    print('Deploying GKE Autopilot Cluster...\n')

    try:
      if not self.check_gcloud_login():
        print('You are not logged in to gcloud. Exiting program.')
        print("Try logging in to GCP using 'gcloud auth login' and try to run the program again\n")
        exit()

      # Get GKE Autopilot config file parameters
      gke_autopilot_parameters = conf.read_gke_autopilot_config_file(config_file)

      convert.convert_gke_autopilot_to_tfvars(gke_autopilot_parameters)

      gke_autopilot_terraform_code_path = './abstrakt/terraformModules/gcp/gke/autopilot/'

      # Execute Terraform commands to deploy AKS cluster
      if (
        tf.execute_terraform_get(path=gke_autopilot_terraform_code_path) and
        tf.execute_terraform_init(path=gke_autopilot_terraform_code_path)
      ):
        plan_status = tf.execute_terraform_plan(path=gke_autopilot_terraform_code_path)

        if plan_status == 0:
          print('Terraform execution to deploy GKE Autopilot cluster failed. Exiting the program.\n')
          exit()
        elif plan_status == 1:
          if tf.execute_terraform_apply(path=gke_autopilot_terraform_code_path):
            kube_config = UpdateKubeConfig(self.logger)
            kube_config.update_kubeconfig(cloud='gcp', cluster_name=gke_autopilot_parameters['cluster_name'],
                                          region=gke_autopilot_parameters['region'])

            print('Terraform execution to deploy GKE Autopilot cluster completed successfully.\n')
          else:
            print('Terraform execution to deploy GKE Autopilot cluster failed. Exiting the program.\n')
            exit()
        elif plan_status == 2:
          kube_config = UpdateKubeConfig(self.logger)
          kube_config.update_kubeconfig(cloud='gcp', cluster_name=gke_autopilot_parameters['cluster_name'],
                                        region=gke_autopilot_parameters['region'])
          print('Terraform execution to create GKE Autopilot cluster did not need any changes.\n')
      else:
        self.logger.error('Failed to deploy GKE Autopilot cluster. Exiting the program.\n')
        exit()
    except Exception as e:
      self.logger.error(f'Error: {e}\n')
      self.logger.error('Exiting the program.\n')
      exit()
