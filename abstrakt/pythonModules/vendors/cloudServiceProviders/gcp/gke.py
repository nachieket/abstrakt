from abstrakt.pythonModules.terraformOps.convertToTFVars import ToTFVars
from abstrakt.pythonModules.terraformOps.executeTerraform import ExecuteTerraform
from abstrakt.pythonModules.parseConfigFile.parseConfigFile import ParseConfigFile
from abstrakt.pythonModules.kubernetesOps.updateKubeConfig import UpdateKubeConfig


class GKE:
  def __init__(self, logger):
    self.logger = logger

  def deploy_gke_standard_cluster(self, cluster_name: str, vpc_network: str, region: str,
                                  asset_tags: str, config_file, project_id) -> str:
    conf = ParseConfigFile(self.logger)
    convert = ToTFVars(self.logger)
    tf = ExecuteTerraform(self.logger)

    print('Deploying GKE Standard Cluster...\n')

    try:
      gke_standard_parameters, tags = conf.read_gke_standard_config_file(config_file)

      convert.convert_gke_standard_to_tfvars(cluster_name=cluster_name,
                                             vpc_network=vpc_network,
                                             region=region,
                                             asset_tags=asset_tags,
                                             terraform_variables=gke_standard_parameters,
                                             project_id=project_id,
                                             common_tags=tags)

      gke_standard_terraform_code_path = './abstrakt/terraformModules/gcp/gke/standard/'

      if (
        tf.execute_terraform_get(path=gke_standard_terraform_code_path) and
        tf.execute_terraform_init(path=gke_standard_terraform_code_path)
      ):
        plan_status = tf.execute_terraform_plan(path=gke_standard_terraform_code_path)

        if plan_status == 0:
          print('Terraform execution to deploy GKE Standard cluster failed. Exiting the program.\n')
          exit()
        elif plan_status == 1:
          if tf.execute_terraform_apply(path=gke_standard_terraform_code_path):
            kube_config = UpdateKubeConfig(self.logger)
            if cluster_name and region:
              kube_config.update_kubeconfig(cloud='gcp', cluster_name=cluster_name,
                                            region=region, gcp_project_id=project_id)
            else:
              kube_config.update_kubeconfig(cloud='gcp', cluster_name=gke_standard_parameters['cluster_name'],
                                            region=gke_standard_parameters['region'], gcp_project_id=project_id)

            print('Terraform execution to deploy GKE Standard cluster completed successfully.\n')

            return f"{gke_standard_parameters['cluster_name']}"
          else:
            print('Terraform execution to deploy GKE Standard cluster failed. Exiting the program.\n')
            exit()
        elif plan_status == 2:
          kube_config = UpdateKubeConfig(self.logger)
          if cluster_name and region:
            kube_config.update_kubeconfig(cloud='gcp', cluster_name=cluster_name,
                                          region=region, gcp_project_id=project_id)
          else:
            kube_config.update_kubeconfig(cloud='gcp', cluster_name=gke_standard_parameters['cluster_name'],
                                          region=gke_standard_parameters['region'], gcp_project_id=project_id)
          print('Terraform execution to create GKE Standard cluster did not need any changes.\n')

          return f"{gke_standard_parameters['cluster_name']}"
      else:
        self.logger.error('Failed to deploy GKE Standard cluster. Exiting the program.\n')
        exit()
    except Exception as e:
      self.logger.error(f'Error: {e}\n')
      self.logger.error('Exiting the program.\n')
      exit()

  def deploy_gke_autopilot_cluster(self, cluster_name: str, vpc_network: str, region: str,
                                   config_file, project_id) -> str:
    conf = ParseConfigFile(self.logger)
    convert = ToTFVars(self.logger)
    tf = ExecuteTerraform(self.logger)

    print('Deploying GKE Autopilot Cluster...\n')

    try:
      gke_autopilot_parameters = conf.read_gke_autopilot_config_file(config_file)

      convert.convert_gke_autopilot_to_tfvars(cluster_name=cluster_name,
                                              vpc_network=vpc_network,
                                              region=region,
                                              terraform_variables=gke_autopilot_parameters,
                                              project_id=project_id)

      gke_autopilot_terraform_code_path = './abstrakt/terraformModules/gcp/gke/autopilot/'

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

            if cluster_name and region:
              kube_config.update_kubeconfig(cloud='gcp', cluster_name=cluster_name,
                                            region=region, gcp_project_id=project_id)
            else:
              kube_config.update_kubeconfig(cloud='gcp', cluster_name=gke_autopilot_parameters['cluster_name'],
                                            region=gke_autopilot_parameters['region'], gcp_project_id=project_id)

            print('Terraform execution to deploy GKE Autopilot cluster completed successfully.\n')

            return f"{gke_autopilot_parameters['cluster_name']}"
          else:
            print('Terraform execution to deploy GKE Autopilot cluster failed. Exiting the program.\n')
            exit()
        elif plan_status == 2:
          kube_config = UpdateKubeConfig(self.logger)

          if cluster_name and region:
            kube_config.update_kubeconfig(cloud='gcp', cluster_name=cluster_name,
                                          region=region, gcp_project_id=project_id)
          else:
            kube_config.update_kubeconfig(cloud='gcp', cluster_name=gke_autopilot_parameters['cluster_name'],
                                          region=gke_autopilot_parameters['region'], gcp_project_id=project_id)

          print('Terraform execution to create GKE Autopilot cluster did not need any changes.\n')

          return f"{gke_autopilot_parameters['cluster_name']}"
      else:
        self.logger.error('Failed to deploy GKE Autopilot cluster. Exiting the program.\n')
        exit()
    except Exception as e:
      self.logger.error(f'Error: {e}\n')
      self.logger.error('Exiting the program.\n')
      exit()
