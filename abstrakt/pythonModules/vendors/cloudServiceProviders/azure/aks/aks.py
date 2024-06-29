import subprocess
import json
import re

from abstrakt.pythonModules.parseConfigFile.parseConfigFile import ParseConfigFile
from abstrakt.pythonModules.terraformOps.convertToTFVars import ToTFVars
from abstrakt.pythonModules.kubernetesOps.updateKubeConfig import UpdateKubeConfig
from abstrakt.pythonModules.terraformOps.executeTerraform import ExecuteTerraform
from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf
# from abstrakt.pythonModules.vendors.cloudServiceProviders.azure.azOps.azOps import AZOps


class AKS:
  def __init__(self, logger):
    self.logger = logger

  def create_service_principal_with_contributor_role(self):
    while True:
      service_principal_specs = {}

      print('Abstrakt needs an azure service principal with contributor role.\n')

      service_principal_name = input(
        'Enter the current service principal name with contributor role or press enter to create a new role: ')

      if not service_principal_name:
        print("Creating a new service principal with Contributor role for AKS cluster.")

        try:
          while arm_subscription_id := input("Enter your subscription ID (e.g., xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx): "):
            if re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',
                        arm_subscription_id):
              break
            else:
              print("Invalid subscription ID format.")

          service_principal_name = input("Enter a service principal name (default: crwdsp): ").strip() or "crwdsp"

          command = ['az', 'ad', 'sp', 'create-for-rbac', '--name', service_principal_name, '--role', 'Contributor',
                     '--scopes', f'/subscriptions/{arm_subscription_id}']

          process = subprocess.run(command, stdout=subprocess.PIPE, stdin=subprocess.PIPE, text=True)

          if process.stdout:
            output = json.loads(process.stdout)
            service_principal_specs['arm_subscription_id'] = arm_subscription_id
            service_principal_specs['arm_tenant_id'] = output['tenant']
            service_principal_specs['arm_client_id'] = output['appId']
            service_principal_specs['arm_client_secret'] = output['password']

            print('\nYou MUST NOTE DOWN these details and store in a secure location:\n')
            print(f'Tenant Id: {output["tenant"]}')
            print(f'Client Id: {output["appId"]}')
            print(f'Client Secret: {output["password"]}')
            input('\nPress enter to continue...')

            return service_principal_specs
          if process.stderr:
            self.logger.error(process.stderr)
        except Exception as e:
          self.logger.error(e)
      else:
        try:
          sp_command = ['az', 'ad', 'sp', 'list', '--display-name', f'{service_principal_name}', '-o', 'json']
          sp_extract = subprocess.run(sp_command, stdout=subprocess.PIPE, stdin=subprocess.PIPE, text=True)

          if sp_extract.stdout.strip() != '[]':
            sp_extract_output = json.loads(sp_extract.stdout)[0]
            sp_role_command = ['az', 'role', 'assignment', 'list', '--assignee', f'{sp_extract_output["id"]}', '--role',
                               'Contributor', '-o', 'json']

            sp_role_extract = subprocess.run(sp_role_command, stdout=subprocess.PIPE, stdin=subprocess.PIPE, text=True)

            sp_role_output: dict = json.loads(sp_role_extract.stdout) if sp_role_extract.stdout else 'NoStdout'

            if sp_role_output[0]['roleDefinitionName'] == 'Contributor':
              while arm_subscription_id := input(
                "Enter your subscription ID (e.g., xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx): "):

                if re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',
                            arm_subscription_id):
                  break
                else:
                  print("Invalid subscription ID format.")

              arm_tenant_id = sp_extract_output['appOwnerOrganizationId']
              arm_client_id = sp_extract_output['appId']

              arm_client_secret = input(f'Enter your service_principal {service_principal_name} password. '
                                        f'Press enter to go back: ')

              if arm_client_secret:
                service_principal_specs['arm_subscription_id'] = arm_subscription_id
                service_principal_specs['arm_tenant_id'] = arm_tenant_id
                service_principal_specs['arm_client_id'] = arm_client_id
                service_principal_specs['arm_client_secret'] = arm_client_secret

                print()
                return service_principal_specs
            else:
              print(f'The service principal {service_principal_name} does not have contributor role. Try again.')
        except Exception as e:
          self.logger.error(e)

  def deploy_aks_cluster(self, config_file):
    # Initialize necessary modules
    conf = ParseConfigFile(self.logger)
    convert = ToTFVars(self.logger)
    tf = ExecuteTerraform(self.logger)
    # az = AZOps(logger=self.logger)

    printf('Deploying Azure AKS Cluster...\n', logger=self.logger)

    try:
      # # Ensure Azure login
      # az.check_azure_login()

      # Get AKS config file parameters
      aks_parameters, tags = conf.read_aks_config_file(config_file)

      # service_principal_specs = self.create_service_principal_with_contributor_role()

      # Convert AKS config file parameters to Terraform tfvars format
      # convert.convert_aks_to_tfvars(aks_parameters, tags, service_principal_specs)
      convert.convert_aks_to_tfvars(aks_parameters, tags)

      aks_terraform_code_path = './abstrakt/terraformModules/azure/aks/'

      # Execute Terraform commands to deploy AKS cluster
      if (
        tf.execute_terraform_get(path=aks_terraform_code_path) and
        tf.execute_terraform_init(path=aks_terraform_code_path)
      ):
        plan_status = tf.execute_terraform_plan(path=aks_terraform_code_path)

        if plan_status == 0:
          print('Terraform execution to deploy azure aks cluster failed. Exiting the program.\n')
          exit()
        elif plan_status == 1:
          if tf.execute_terraform_apply(path=aks_terraform_code_path):
            kube_config = UpdateKubeConfig(self.logger)
            kube_config.update_kubeconfig(cloud='azure', cluster_name=aks_parameters['cluster_name'],
                                          resource_group=aks_parameters['resource_group_name'])

            print('Terraform execution to deploy azure aks cluster completed successfully.\n')
          else:
            print('Terraform execution to deploy azure aks cluster failed. Exiting the program.\n')
            exit()
        elif plan_status == 2:
          print('Terraform execution to create azure aks cluster did not need any changes.\n')
      else:
        printf('Failed to deploy Azure AKS cluster. Exiting the program.\n', logger=self.logger)
        exit()
    except Exception as e:
      printf(f'Error: {e}\n', logger=self.logger)
      printf('Exiting the program.\n', logger=self.logger)
      exit()
