import json
import os


class ToTFVars:
  def __init__(self, logger):
    self.logger = logger

  def convert_eks_managed_node_to_tfvars(self, parameters, managed_node_groups, tags):
    self.logger.info('Converting EKS Managed Node configuration file to terraform tfvars file')

    with open("./abstrakt/terraformModules/aws/eks/eks-managed-node/variables.tfvars", "w") as tfvars_file:
      for key, value in parameters.items():
        if key in ["private_subnets", "public_subnets"]:
          value_list = value.split(",")
          tfvars_file.write(f'{key} = {json.dumps(value_list)}\n')
        elif value.lower() in ["true", "false"]:
          tfvars_file.write(f'{key} = {value.lower()}\n')
        else:
          tfvars_file.write(f'{key} = "{value}"\n')

      tfvars_file.write(f'common_tags = {json.dumps(tags)}\n')
      # tfvars_file.write(f'eks_managed_node_groups = {json.dumps(managed_node_groups)}\n')

    self.logger.info('Finished converting EKS Managed Node configuration file to terraform tfvars file')

  def convert_eks_fargate_to_tfvars(self, terraform_variables, common_tags):
    self.logger.info('Converting EKS Fargate configuration file to terraform tfvars file')

    with open("./abstrakt/terraformModules/aws/eks/eks-fargate/variables.tfvars", "w") as tfvars_file:
      for key, value in terraform_variables.items():
        if value.lower() in ["true", "false"]:
          tfvars_file.write(f'{key} = {value.lower()}\n')
        else:
          if key == 'cluster_name':
            eks_fargate_cluster_name = value
          elif key == 'random_string':
            random_string = value
          tfvars_file.write(f'{key} = "{value}"\n')

      tfvars_file.write(f'common_tags = {json.dumps(common_tags)}\n')

      os.environ['EKS_FARGATE_CLUSTER_NAME'] = f'{eks_fargate_cluster_name}{random_string}'

    self.logger.info('Finished converting EKS Fargate configuration file to terraform tfvars file')

  def convert_gke_standard_to_tfvars(self, terraform_variables, gcp_project_id, common_tags):
    self.logger.info('Converting GKE COS configuration file to terraform tfvars file')

    with open("./abstrakt/terraformModules/gcp/gke/standard/variables.tfvars", "w") as tfvars_file:
      for key, value in terraform_variables.items():
        if value.lower() in ["true", "false"]:
          tfvars_file.write(f'{key} = {value.lower()}\n')
        else:
          tfvars_file.write(f'{key} = "{value}"\n')

      common_tags = [f"{x.lower()}-{y.lower()}" for x, y in common_tags.items()]
      common_tags = str(common_tags).replace("'", '"')
      common_tags = str(common_tags).replace(" ", '')

      tfvars_file.write(f'project_id = "{gcp_project_id}"\n')
      tfvars_file.write(f'common_tags = {common_tags}')

    self.logger.info('Finished converting GKE COS configuration file to terraform tfvars file')

  def convert_gke_autopilot_to_tfvars(self, terraform_variables, gcp_project_id):
    self.logger.info('Converting GKE Autopilot configuration file to terraform tfvars file')

    with open("./abstrakt/terraformModules/gcp/gke/autopilot/variables.tfvars", "w") as tfvars_file:
      for key, value in terraform_variables.items():
        if value.lower() in ["true", "false"]:
          tfvars_file.write(f'{key} = {value.lower()}\n')
        else:
          tfvars_file.write(f'{key} = "{value}"\n')

      tfvars_file.write(f'project_id = "{gcp_project_id}"')

    self.logger.info('Finished converting GKE Autopilot configuration file to terraform tfvars file')

  def convert_aks_to_tfvars(self, terraform_variables, common_tags):
    self.logger.info('Converting AKS configuration file to terraform tfvars file')

    with open("./abstrakt/terraformModules/azure/aks/variables.tfvars", "w") as tfvars_file:
      for key, value in terraform_variables.items():
        if value.lower() in ["true", "false"]:
          tfvars_file.write(f'{key} = {value.lower()}\n')
        else:
          tfvars_file.write(f'{key} = "{value}"\n')

      tfvars_file.write(f'common_tags = {json.dumps(common_tags)}\n')

    self.logger.info('Finished converting AKS configuration file to terraform tfvars file')

  def convert_aci_to_tfvars(self, terraform_variables):
    self.logger.info('Converting ACI configuration file to terraform tfvars file')

    with open("./abstrakt/terraformModules/azure/aci/variables.tfvars", "w") as tfvars_file:
      for key, value in terraform_variables.items():
        if value.lower() in ["true", "false"]:
          tfvars_file.write(f'{key} = {value.lower()}\n')
        else:
          tfvars_file.write(f'{key} = "{value}"\n')

    self.logger.info('Finished converting ACI configuration file to terraform tfvars file')

  # def convert_aks_to_tfvars(self, terraform_variables, common_tags, service_principal_specs: dict):
  #   self.logger.info('Converting AKS configuration file to terraform tfvars file')
  #
  #   with open("./abstrakt/terraformModules/azure/aks/variables.tfvars", "w") as tfvars_file:
  #     for key, value in service_principal_specs.items():
  #       tfvars_file.write(f'{key} = "{value}"\n')
  #
  #     for key, value in terraform_variables.items():
  #       if value.lower() in ["true", "false"]:
  #         tfvars_file.write(f'{key} = {value.lower()}\n')
  #       else:
  #         tfvars_file.write(f'{key} = "{value}"\n')
  #
  #     tfvars_file.write(f'common_tags = {json.dumps(common_tags)}\n')
  #
  #   self.logger.info('Finished converting AKS configuration file to terraform tfvars file')
