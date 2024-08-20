from abstrakt.pythonModules.parseConfigFile.parseConfigFile import ParseConfigFile
from abstrakt.pythonModules.terraformOps.convertToTFVars import ToTFVars
from abstrakt.pythonModules.vendors.cloudServiceProviders.aws.awsCli.awsOps import AWSOps
from abstrakt.pythonModules.terraformOps.executeTerraform import ExecuteTerraform


class ECSec2:
  def __init__(self, logger):
    self.logger = logger

  def deploy_ecs_ec2_cluster(self, random_string, config_file):
    # get eks fargate config file parameters
    parser = ParseConfigFile(logger=self.logger)
    ecs_ec2_parameters, tags = parser.read_aws_k8s_cluster_config_file(cluster_type='ECS EC2', config_file=config_file)

    if ecs_ec2_parameters['random_string'].lower() != 'no':
      ecs_ec2_parameters['random_string'] = random_string

    # convert eks managed node config file parameters to terraform tfvars format
    convert = ToTFVars(logger=self.logger)
    convert.convert_eks_fargate_to_tfvars(ecs_ec2_parameters, tags)

    ecs_ec2_terraform_module = './abstrakt/terraformModules/aws/ecs/ecs-ec2/'

    print(self)
    print('+' * 10)
    print('Terraform')
    print('+' * 10, '\n')

    tf = ExecuteTerraform(logger=self.logger)

    if (
      tf.execute_terraform_get(path=ecs_ec2_terraform_module) and
      tf.execute_terraform_init(path=ecs_ec2_terraform_module)
    ):
      plan_status = tf.execute_terraform_plan(path=ecs_ec2_terraform_module)

      if plan_status == 0:
        print('Terraform execution to deploy ecs with ec2 cluster failed. Exiting the program.\n')
        exit()
      elif plan_status == 1:
        if tf.execute_terraform_apply(path=ecs_ec2_terraform_module):
          print('Terraform execution to deploy ecs with ec2 cluster completed successfully.\n')

          return f"{ecs_ec2_parameters['cluster_name']}{ecs_ec2_parameters['random_string']}"
        else:
          print('Terraform execution to deploy ecs with ec2 cluster failed. Exiting the program.\n')
          exit()
      elif plan_status == 2:
        print('Terraform execution to create ecs with ec2 cluster did not need any changes.\n')
    else:
      print('Terraform execution to deploy ecs with ec2 cluster failed. Exiting the program.\n')
      exit()
