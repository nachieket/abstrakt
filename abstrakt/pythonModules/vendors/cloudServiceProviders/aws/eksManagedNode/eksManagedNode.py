from abstrakt.pythonModules.parseConfigFile.parseConfigFile import ParseConfigFile
from abstrakt.pythonModules.terraformOps.convertToTFVars import ToTFVars
from abstrakt.pythonModules.vendors.cloudServiceProviders.aws.awsCliProfile.awsCliProfile import AWSCliProfile
from abstrakt.pythonModules.terraformOps.executeTerraform import ExecuteTerraform
from abstrakt.pythonModules.kubernetesOps.updateKubeConfig import UpdateKubeConfig


class EKSManagedNode:
  def __init__(self, logger):
    self.logger = logger

  def deploy_eks_managed_node_cluster(self, config_file):
    path = './abstrakt/terraformModules/aws/eks/eks-managed-node/'

    # get eks managed node config file parameters
    conf = ParseConfigFile(logger=self.logger)
    managed_node_parameters, node_groups, tags = conf.read_eks_managed_node_config_file(config_file)

    # convert eks managed node config file parameters to terraform tfvars format
    convert = ToTFVars(logger=self.logger)
    convert.convert_eks_managed_node_to_tfvars(managed_node_parameters, node_groups, tags)

    # cli object to validate aws credentials profile
    cli = AWSCliProfile()

    # execution of terraform commands if aws profile validation is successful and valid saml or default
    # profile is found
    if cli.check_aws_login():
      print('+' * 10)
      print('Terraform')
      print('+' * 10, '\n')

      tf = ExecuteTerraform(logger=self.logger)

      # execute terraform commands to deploy eks managed node cluster
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
            kube_config = UpdateKubeConfig(self.logger)
            kube_config.update_kubeconfig(cloud='aws', region=managed_node_parameters['region'],
                                          cluster_name=managed_node_parameters['cluster_name'])

            print('Terraform execution to deploy eks managed node cluster completed successfully.\n')
          else:
            print('Terraform execution to deploy eks managed node cluster failed. Exiting the program.\n')
            exit()
        elif plan_status == 2:
          print('Terraform execution to create eks managed node cluster did not need any changes.\n')
      else:
        print('Terraform execution to deploy eks managed node cluster failed. Exiting the program.\n')
        exit()
    else:
      print('AWS credentials profile validation failed. No valid default or saml profile found. '
            'Existing the Program.\n')
      exit()
