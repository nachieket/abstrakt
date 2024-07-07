from abstrakt.pythonModules.parseConfigFile.parseConfigFile import ParseConfigFile
from abstrakt.pythonModules.terraformOps.convertToTFVars import ToTFVars
from abstrakt.pythonModules.kubernetesOps.updateKubeConfig import UpdateKubeConfig
from abstrakt.pythonModules.terraformOps.executeTerraform import ExecuteTerraform
# from abstrakt.pythonModules.vendors.cloudServiceProviders.gcp.gcpOps import GCPOps


class GKE:
  def __init__(self, logger):
    self.logger = logger

  def deploy_gke_standard_cluster(self, config_file, gcp_project_id):
    # Initialize necessary modules
    conf = ParseConfigFile(self.logger)
    convert = ToTFVars(self.logger)
    tf = ExecuteTerraform(self.logger)

    print('Deploying GKE Standard Cluster...\n')

    try:
      # print('Checking GCP login...\n')
      #
      # gcp = GCPOps(logger=self.logger)
      #
      # if not gcp.check_gcloud_login():
      #   print('You are not logged in to gcloud. Exiting program.')
      #   print("Try logging in to GCP using 'gcloud auth login' and try to run the program again\n")
      #   exit()

      # Get GKE COS config file parameters
      gke_standard_parameters, tags = conf.read_gke_standard_config_file(config_file)

      convert.convert_gke_standard_to_tfvars(terraform_variables=gke_standard_parameters, gcp_project_id=gcp_project_id,
                                             common_tags=tags)

      gke_standard_terraform_code_path = './abstrakt/terraformModules/gcp/gke/standard/'

      # Execute Terraform commands to deploy AKS cluster
      if (
        tf.execute_terraform_get(path=gke_standard_terraform_code_path) and
        tf.execute_terraform_init(path=gke_standard_terraform_code_path)
      ):
        plan_status = tf.execute_terraform_plan(path=gke_standard_terraform_code_path)

        if plan_status == 0:
          print('Terraform execution to deploy GKE COS cluster failed. Exiting the program.\n')
          exit()
        elif plan_status == 1:
          if tf.execute_terraform_apply(path=gke_standard_terraform_code_path):
            kube_config = UpdateKubeConfig(self.logger)
            kube_config.update_kubeconfig(cloud='gcp', cluster_name=gke_standard_parameters['cluster_name'],
                                          region=gke_standard_parameters['region'], gcp_project_id=gcp_project_id)

            print('Terraform execution to deploy GKE COS cluster completed successfully.\n')
          else:
            print('Terraform execution to deploy GKE COS cluster failed. Exiting the program.\n')
            exit()
        elif plan_status == 2:
          kube_config = UpdateKubeConfig(self.logger)
          kube_config.update_kubeconfig(cloud='gcp', cluster_name=gke_standard_parameters['cluster_name'],
                                        region=gke_standard_parameters['region'])
          print('Terraform execution to create GKE COS cluster did not need any changes.\n')
      else:
        self.logger.error('Failed to deploy GKE COS cluster. Exiting the program.\n')
        exit()
    except Exception as e:
      self.logger.error(f'Error: {e}\n')
      self.logger.error('Exiting the program.\n')
      exit()

  def deploy_gke_autopilot_cluster(self, config_file, gcp_project_id):
    # Initialize necessary modules
    conf = ParseConfigFile(self.logger)
    convert = ToTFVars(self.logger)
    tf = ExecuteTerraform(self.logger)

    print('Deploying GKE Autopilot Cluster...\n')

    try:
      # print('Checking GCP login...\n')

      # gcp = GCPOps(logger=self.logger)
      #
      # if not gcp.check_gcloud_login():
      #   print('You are not logged in to gcloud. Exiting program.')
      #   print("Try logging in to GCP using 'gcloud auth login' and try to run the program again\n")
      #   exit()

      # Get GKE Autopilot config file parameters
      gke_autopilot_parameters = conf.read_gke_autopilot_config_file(config_file)

      convert.convert_gke_autopilot_to_tfvars(gke_autopilot_parameters, gcp_project_id)

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
