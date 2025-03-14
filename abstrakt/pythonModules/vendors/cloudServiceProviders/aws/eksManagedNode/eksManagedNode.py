from abstrakt.pythonModules.parseConfigFile.parseConfigFile import ParseConfigFile
from abstrakt.pythonModules.terraformOps.convertToTFVars import ToTFVars
# from abstrakt.pythonModules.vendors.cloudServiceProviders.aws.awsCli.awsOps import AWSOps
from abstrakt.pythonModules.terraformOps.executeTerraform import ExecuteTerraform
from abstrakt.pythonModules.kubernetesOps.updateKubeConfig import UpdateKubeConfig


class EKSManagedNode:
  def __init__(self, logger):
    self.logger = logger

  def deploy_eks_managed_node_cluster(self, cluster_name: str, vpc_name: str, region: str,
                                      asset_tags: str, random_string: str, config_file: str):
    path = './abstrakt/terraformModules/aws/eks/eks-managed-node/'

    # get eks managed node config file parameters
    conf = ParseConfigFile(logger=self.logger)
    managed_node_parameters, node_groups, common_tags = conf.read_eks_managed_node_config_file(config_file)

    if managed_node_parameters['random_string'].lower() != 'no':
      managed_node_parameters['random_string'] = random_string

    # convert eks managed node config file parameters to terraform tfvars format
    convert = ToTFVars(logger=self.logger)
    convert.convert_eks_managed_node_to_tfvars(cluster_name=cluster_name,
                                               vpc_name=vpc_name,
                                               region=region,
                                               asset_tags=asset_tags,
                                               parameters=managed_node_parameters,
                                               common_tags=common_tags)

    print(' ')
    print('+' * 10)
    print('Terraform')
    print('+' * 10, '\n')

    tf = ExecuteTerraform(logger=self.logger)

    if (
      tf.execute_terraform_get(path=path) and
      tf.execute_terraform_init(path=path)
    ):
      plan_status = tf.execute_terraform_plan(path=path)

      if plan_status == 0:
        print('Terraform execution to deploy eks managed node cluster failed. Exiting the program.\n')
        exit()
      elif plan_status == 1:
        if tf.execute_terraform_apply(path=path):
          print('Terraform execution to deploy eks managed node cluster completed successfully.\n')

          kube_config = UpdateKubeConfig(self.logger)

          if managed_node_parameters['random_string'].lower() == 'no':
            if cluster_name:
              kube_config.update_kubeconfig(cloud='aws',
                                            region=region,
                                            cluster_name=f"{cluster_name}")
              return f"{cluster_name}"
            else:
              kube_config.update_kubeconfig(cloud='aws',
                                            region=region,
                                            cluster_name=managed_node_parameters['cluster_name'])
              return f"{cluster_name}"
          else:
            if cluster_name:
              kube_config.update_kubeconfig(cloud='aws',
                                            region=region,
                                            cluster_name=f"{cluster_name}{managed_node_parameters['random_string']}")
              return f"{cluster_name}{managed_node_parameters['random_string']}"
            else:
              kube_config.update_kubeconfig(cloud='aws',
                                            region=region,
                                            cluster_name=f"{managed_node_parameters['cluster_name']}"
                                                         f"{managed_node_parameters['random_string']}")
              return f"{managed_node_parameters['cluster_name']}{managed_node_parameters['random_string']}"
        else:
          print('Terraform execution to deploy eks managed node cluster failed. Exiting the program.\n')
          exit()
      elif plan_status == 2:
        print('Terraform execution to create eks managed node cluster did not need any changes.\n')

        kube_config = UpdateKubeConfig(self.logger)

        if managed_node_parameters['random_string'].lower() == 'no':
          if cluster_name:
            kube_config.update_kubeconfig(cloud='aws',
                                          region=region,
                                          cluster_name=f"{cluster_name}")
            return f"{cluster_name}"
          else:
            kube_config.update_kubeconfig(cloud='aws',
                                          region=region,
                                          cluster_name=managed_node_parameters['cluster_name'])
            return f"{cluster_name}"
        else:
          if cluster_name:
            kube_config.update_kubeconfig(cloud='aws',
                                          region=region,
                                          cluster_name=f"{cluster_name}{managed_node_parameters['random_string']}")
            return f"{cluster_name}{managed_node_parameters['random_string']}"
          else:
            kube_config.update_kubeconfig(cloud='aws',
                                          region=region,
                                          cluster_name=f"{managed_node_parameters['cluster_name']}"
                                                       f"{managed_node_parameters['random_string']}")
            return f"{managed_node_parameters['cluster_name']}{managed_node_parameters['random_string']}"
    else:
      print('Terraform execution to deploy eks managed node cluster failed. Exiting the program.\n')
      exit()
