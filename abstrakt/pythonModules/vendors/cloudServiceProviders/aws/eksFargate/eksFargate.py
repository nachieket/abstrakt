from abstrakt.pythonModules.terraformOps.convertToTFVars import ToTFVars
from abstrakt.pythonModules.terraformOps.executeTerraform import ExecuteTerraform
from abstrakt.pythonModules.kubernetesOps.updateKubeConfig import UpdateKubeConfig
from abstrakt.pythonModules.parseConfigFile.parseConfigFile import ParseConfigFile


class EKSFargate:
  def __init__(self, logger):
    self.logger = logger

  def deploy_eks_fargate_cluster(self, cluster_name: str, vpc_name: str, region: str,
                                 asset_tags: str, random_string: str, config_file: str) -> str:
    path = './abstrakt/terraformModules/aws/eks/eks-fargate/'

    # get eks fargate config file parameters
    parser = ParseConfigFile(logger=self.logger)

    tags: dict
    fargate_parameters: dict

    fargate_parameters, tags = parser.read_aws_k8s_cluster_config_file(cluster_type='EKS Fargate',
                                                                       config_file=config_file)

    if fargate_parameters['random_string'].lower() != 'no':
      fargate_parameters['random_string'] = random_string

    # convert eks managed node config file parameters to terraform tfvars format
    convert = ToTFVars(logger=self.logger)
    convert.convert_eks_fargate_to_tfvars(cluster_name=cluster_name,
                                          vpc_name=vpc_name,
                                          region=region,
                                          asset_tags=asset_tags,
                                          terraform_variables=fargate_parameters,
                                          common_tags=tags)

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
        print('Terraform execution to deploy eks fargate cluster failed. Exiting the program.\n')
        exit()
      elif plan_status == 1:
        tf.execute_terraform_apply(path=path)

        if tf.execute_terraform_apply(path=path):
          print('Terraform execution to deploy eks fargate cluster completed successfully.\n')

          kube_config = UpdateKubeConfig(self.logger)

          if fargate_parameters['random_string'].lower() == 'no':
            if cluster_name:
              kube_config.update_kubeconfig(cloud='aws',
                                            region=region,
                                            cluster_name=f"{cluster_name}")
              return f"{cluster_name}"
            else:
              kube_config.update_kubeconfig(cloud='aws',
                                            region=region,
                                            cluster_name=fargate_parameters['cluster_name'])
              return f"{cluster_name}"
          else:
            if cluster_name:
              kube_config.update_kubeconfig(cloud='aws',
                                            region=region,
                                            cluster_name=f"{cluster_name}{fargate_parameters['random_string']}")
              return f"{cluster_name}{fargate_parameters['random_string']}"
            else:
              kube_config.update_kubeconfig(cloud='aws',
                                            region=region,
                                            cluster_name=f"{fargate_parameters['cluster_name']}"
                                                         f"{fargate_parameters['random_string']}")
              return f"{fargate_parameters['cluster_name']}{fargate_parameters['random_string']}"
        else:
          print('Terraform execution to deploy eks fargate cluster failed. Exiting the program.\n')
          exit()
      elif plan_status == 2:
        print('Terraform execution to create eks fargate cluster did not need any changes.\n')

        kube_config = UpdateKubeConfig(self.logger)

        if fargate_parameters['random_string'].lower() == 'no':
          if cluster_name:
            kube_config.update_kubeconfig(cloud='aws',
                                          region=region,
                                          cluster_name=f"{cluster_name}")
            return f"{cluster_name}"
          else:
            kube_config.update_kubeconfig(cloud='aws',
                                          region=region,
                                          cluster_name=fargate_parameters['cluster_name'])
            return f"{cluster_name}"
        else:
          if cluster_name:
            kube_config.update_kubeconfig(cloud='aws',
                                          region=region,
                                          cluster_name=f"{cluster_name}{fargate_parameters['random_string']}")
            return f"{cluster_name}{fargate_parameters['random_string']}"
          else:
            kube_config.update_kubeconfig(cloud='aws',
                                          region=region,
                                          cluster_name=f"{fargate_parameters['cluster_name']}"
                                                       f"{fargate_parameters['random_string']}")
            return f"{fargate_parameters['cluster_name']}{fargate_parameters['random_string']}"
    else:
      print('Terraform execution to deploy eks fargate cluster failed. Exiting the program.\n')
      exit()
