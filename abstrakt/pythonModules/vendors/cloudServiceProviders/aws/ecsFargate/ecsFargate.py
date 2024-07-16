from abstrakt.pythonModules.parseConfigFile.parseConfigFile import ParseConfigFile
from abstrakt.pythonModules.terraformOps.convertToTFVars import ToTFVars
from abstrakt.pythonModules.vendors.cloudServiceProviders.aws.awsCli.awsOps import AWSOps
from abstrakt.pythonModules.terraformOps.executeTerraform import ExecuteTerraform


class ECSFargate:
  def __init__(self, logger):
    self.logger = logger

  def deploy_ecs_fargate_cluster(self, random_string, config_file):
    # get eks fargate config file parameters
    parser = ParseConfigFile(logger=self.logger)
    ecs_fargate_parameters, tags = parser.read_aws_k8s_cluster_config_file(cluster_type='ECS Fargate',
                                                                           config_file=config_file)

    if ecs_fargate_parameters['random_string'].lower() != 'no':
      ecs_fargate_parameters['random_string'] = random_string

    # convert eks managed node config file parameters to terraform tfvars format
    convert = ToTFVars(logger=self.logger)
    convert.convert_eks_fargate_to_tfvars(ecs_fargate_parameters, tags)

    ecs_fargate_terraform_module = './abstrakt/terraformModules/aws/ecs/ecs_fargate/'

    print()
    print('+' * 10)
    print('Terraform')
    print('+' * 10, '\n')

    tf = ExecuteTerraform(logger=self.logger)

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
