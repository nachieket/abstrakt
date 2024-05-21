from abstrakt.pythonModules.parseConfigFile.parseConfigFile import ParseConfigFile
from abstrakt.pythonModules.terraformOps.convertToTFVars import ToTFVars
from abstrakt.pythonModules.vendors.cloudServiceProviders.aws.awsCli.awsOps import AWSOps
from abstrakt.pythonModules.terraformOps.executeTerraform import ExecuteTerraform
from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf
from abstrakt.pythonModules.kubernetesOps.updateKubeConfig import UpdateKubeConfig


class EKSFargate:
  def __init__(self, logger):
    self.logger = logger

  def deploy_eks_fargate_cluster(self, config_file):
    path = './abstrakt/terraformModules/aws/eks/eks-fargate/'

    # get eks fargate config file parameters
    parser = ParseConfigFile(logger=self.logger)
    fargate_parameters, tags = parser.read_aws_k8s_cluster_config_file(cluster_type='EKS Fargate', config_file=config_file)

    # convert eks managed node config file parameters to terraform tfvars format
    convert = ToTFVars(logger=self.logger)
    convert.convert_eks_fargate_to_tfvars(fargate_parameters, tags)

    # cli object to validate aws credentials profile
    cli = AWSOps()

    # execution of terraform commands if aws profile validation is successful and valid saml or default
    # profile is found
    if cli.check_aws_login():
      print()
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
          print('Terraform execution to deploy eks fargate cluster failed. Exiting the program.\n')
          exit()
        elif plan_status == 1:
          tf.execute_terraform_apply(path=path)

          if tf.execute_terraform_apply(path=path):
            kube_config = UpdateKubeConfig(self.logger)
            kube_config.update_kubeconfig(cloud='aws', region=fargate_parameters['region'],
                                          cluster_name=fargate_parameters['cluster_name'])

            print('Terraform execution to deploy eks fargate cluster completed successfully.\n')
          else:
            print('Terraform execution to deploy eks fargate cluster failed. Exiting the program.\n')
            exit()
        elif plan_status == 2:
          print('Terraform execution to create eks fargate cluster did not need any changes.\n')
      else:
        print('Terraform execution to deploy eks fargate cluster failed. Exiting the program.\n')
        exit()
    else:
      printf('AWS credentials profile validation failed. No valid default or saml profile found.',
             'Existing the Program.\n', logger=self.logger)
      exit()
