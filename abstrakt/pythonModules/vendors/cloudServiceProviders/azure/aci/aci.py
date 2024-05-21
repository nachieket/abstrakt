from abstrakt.pythonModules.parseConfigFile.parseConfigFile import ParseConfigFile
from abstrakt.pythonModules.terraformOps.convertToTFVars import ToTFVars
from abstrakt.pythonModules.terraformOps.executeTerraform import ExecuteTerraform
from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf
from abstrakt.pythonModules.vendors.cloudServiceProviders.azure.azOps.azOps import AZOps


class ACI:
  def __init__(self, logger):
    self.logger = logger

  def deploy_aci_cluster(self, config_file):
    # Initialize necessary modules
    conf = ParseConfigFile(self.logger)
    convert = ToTFVars(self.logger)
    tf = ExecuteTerraform(self.logger)
    az = AZOps(logger=self.logger)

    printf('Deploying Azure ACI Cluster...\n', logger=self.logger)

    try:
      # Ensure Azure login
      az.check_azure_login()

      # Get AKS config file parameters
      aci_parameters = conf.read_aci_config_file(config_file)

      convert.convert_aci_to_tfvars(aci_parameters)

      aci_terraform_code_path = './abstrakt/terraformModules/azure/aci/'

      # Execute Terraform commands to deploy AKS cluster
      if (
        tf.execute_terraform_get(path=aci_terraform_code_path) and
        tf.execute_terraform_init(path=aci_terraform_code_path)
      ):
        plan_status = tf.execute_terraform_plan(path=aci_terraform_code_path)

        if plan_status == 0:
          print('Terraform execution to deploy azure aci cluster failed. Exiting the program.\n')
          exit()
        elif plan_status == 1:
          if tf.execute_terraform_apply(path=aci_terraform_code_path):
            print('Terraform execution to deploy azure aci cluster completed successfully.\n')
          else:
            print('Terraform execution to deploy azure aci cluster failed. Exiting the program.\n')
            exit()
        elif plan_status == 2:
          print('Terraform execution to create azure aci cluster did not need any changes.\n')
      else:
        printf('Failed to deploy Azure ACI cluster. Exiting the program.\n', logger=self.logger)
        exit()
    except Exception as e:
      printf(f'Error: {e}\n', logger=self.logger)
      printf('Exiting the program.\n', logger=self.logger)
      exit()
