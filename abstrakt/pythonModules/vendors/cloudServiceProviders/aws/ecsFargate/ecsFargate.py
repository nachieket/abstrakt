from abstrakt.pythonModules.parseConfigFile.parseConfigFile import ParseConfigFile
from abstrakt.pythonModules.terraformOps.convertToTFVars import ToTFVars
from abstrakt.pythonModules.vendors.cloudServiceProviders.aws.awsCliProfile.awsCliProfile import AWSCliProfile
from abstrakt.pythonModules.terraformOps.executeTerraform import ExecuteTerraform


class ECSFargate:
  def __init__(self, logger):
    self.logger = logger

  def deploy_ecs_fargate_cluster(self, config_file):
    # get eks fargate config file parameters
    parser = ParseConfigFile(logger=self.logger)
    ecs_fargate_parameters, tags = parser.read_aws_k8s_cluster_config_file(cluster_type='ECS Fargate', config_file=config_file)

    # convert eks managed node config file parameters to terraform tfvars format
    convert = ToTFVars(logger=self.logger)
    convert.convert_eks_fargate_to_tfvars(ecs_fargate_parameters, tags)

    # cli object to validate aws credentials profile
    cli = AWSCliProfile()

    ecs_fargate_terraform_module = './abstrakt/terraformModules/aws/ecs/ecs_fargate/'

    # execution of terraform commands if aws profile validation is successful and valid saml or default profile is found
    if cli.ensure_valid_aws_profile():
      tf = ExecuteTerraform(logger=self.logger)

      # execute terraform commands to deploy eks managed node cluster
      if (
        tf.execute_terraform_get(path=ecs_fargate_terraform_module) and
        tf.execute_terraform_init(path=ecs_fargate_terraform_module)
      ):
        plan_status = tf.execute_terraform_plan(path=ecs_fargate_terraform_module)

        if plan_status == 0:
          print('Terraform execution to deploy ecs fargate cluster failed. Exiting the program.\n')
          exit()
        elif plan_status == 1:
          if tf.execute_terraform_apply(path=ecs_fargate_terraform_module):
            print('Terraform execution to deploy ecs fargate cluster completed successfully.\n')
          else:
            print('Terraform execution to deploy ecs fargate cluster failed. Exiting the program.\n')
            exit()
        elif plan_status == 2:
          print('Terraform execution to create ecs fargate cluster did not need any changes.\n')
      else:
        print('Terraform execution to deploy ecs fargate cluster failed. Exiting the program.\n')
        exit()
    else:
      print('AWS credentials profile validation failed. No valid default or saml profile found. Existing the Program.\n')
      exit()
