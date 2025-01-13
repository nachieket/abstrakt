import json


class ToTFVars:
  def __init__(self, logger):
    self.logger = logger

  def convert_eks_managed_node_to_tfvars(self, cluster_name: str, vpc_name: str, region: str,
                                         asset_tags: str, parameters, common_tags: dict):
    self.logger.info('Converting EKS Managed Node configuration file to terraform tfvars file')

    with open("./abstrakt/terraformModules/aws/eks/eks-managed-node/variables.tfvars", "w") as tfvars_file:
      for key, value in parameters.items():
        if key == 'random_string' and value == 'no':
          tfvars_file.write(f'{key} = ""\n')
        elif key in ["private_subnets", "public_subnets"]:
          value_list = value.split(",")
          tfvars_file.write(f'{key} = {json.dumps(value_list)}\n')
        elif value.lower() in ["true", "false"]:
          tfvars_file.write(f'{key} = {value.lower()}\n')
        else:
          if key == 'cluster_name':
            if cluster_name:
              tfvars_file.write(f'cluster_name = "{cluster_name}"\n')
            else:
              tfvars_file.write(f'{key} = "{value.lower()}"\n')
          elif key == 'vpc_name':
            if vpc_name:
              tfvars_file.write(f'vpc_name = "{vpc_name}"\n')
            else:
              tfvars_file.write(f'{key} = "{value.lower()}"\n')
          elif key == 'region':
            if region:
              tfvars_file.write(f'region = "{region}"\n')
            else:
              tfvars_file.write(f'{key} = "{value}"\n')
          else:
            tfvars_file.write(f'{key} = "{value}"\n')

      if asset_tags:
        tag_pairs = asset_tags.split(',')
        common_tags = {key_value.split('=')[0]: key_value.split('=')[1] for key_value in tag_pairs}
        tfvars_file.write(f'common_tags = {json.dumps(common_tags)}\n')
      elif common_tags:
        tfvars_file.write(f'common_tags = {json.dumps(common_tags)}\n')

    self.logger.info('Finished converting EKS Managed Node configuration file to terraform tfvars file')

  def convert_eks_fargate_to_tfvars(self, cluster_name: str, vpc_name: str, region: str,
                                    asset_tags: str, terraform_variables: dict, common_tags: dict):
    self.logger.info('Converting EKS Fargate configuration file to terraform tfvars file')

    with open("./abstrakt/terraformModules/aws/eks/eks-fargate/variables.tfvars", "w") as tfvars_file:
      for key, value in terraform_variables.items():
        if key == 'random_string' and value == 'no':
          tfvars_file.write(f'{key} = ""\n')
        elif value.lower() in ["true", "false"]:
          tfvars_file.write(f'{key} = {value.lower()}\n')
        else:
          if key == 'cluster_name':
            if cluster_name:
              tfvars_file.write(f'cluster_name = "{cluster_name}"\n')
            else:
              tfvars_file.write(f'{key} = "{value.lower()}"\n')
          elif key == 'vpc_name':
            if vpc_name:
              tfvars_file.write(f'vpc_name = "{vpc_name}"\n')
            else:
              tfvars_file.write(f'{key} = "{value.lower()}"\n')
          elif key == 'region':
            if region:
              tfvars_file.write(f'region = "{region}"\n')
            else:
              tfvars_file.write(f'{key} = "{value}"\n')
          else:
            tfvars_file.write(f'{key} = "{value}"\n')

      if asset_tags:
        tag_pairs = asset_tags.split(',')
        common_tags = {key_value.split('=')[0]: key_value.split('=')[1] for key_value in tag_pairs}
        tfvars_file.write(f'common_tags = {json.dumps(common_tags)}\n')
      elif common_tags:
        tfvars_file.write(f'common_tags = {json.dumps(common_tags)}\n')

    self.logger.info('Finished converting EKS Fargate configuration file to terraform tfvars file')

  def convert_gke_standard_to_tfvars(self, cluster_name: str, vpc_network: str, region: str,
                                     asset_tags: str, terraform_variables, project_id):
    self.logger.info('Converting GKE Standard configuration file to terraform tfvars file')

    with open("./abstrakt/terraformModules/gcp/gke/standard/variables.tfvars", "w") as tfvars_file:
      for key, value in terraform_variables.items():
        if value.lower() in ["true", "false"]:
          tfvars_file.write(f'{key} = {value.lower()}\n')
        else:
          if key == 'cluster_name':
            if cluster_name:
              tfvars_file.write(f'cluster_name = "{cluster_name}"\n')
            else:
              tfvars_file.write(f'{key} = "{value.lower()}"\n')
          elif key == 'vpc_network':
            if vpc_network:
              tfvars_file.write(f'vpc_network = "{vpc_network}"\n')
            else:
              tfvars_file.write(f'{key} = "{value.lower()}"\n')
          elif key == 'region':
            if region:
              tfvars_file.write(f'region = "{region}"\n')
            else:
              tfvars_file.write(f'{key} = "{value}"\n')
          elif key == 'project_id':
            if project_id:
              tfvars_file.write(f'project_id = "{project_id}"\n')
            else:
              tfvars_file.write(f'{key} = "{value}"\n')
          else:
            tfvars_file.write(f'{key} = "{value}"\n')

      if asset_tags:
        tag_pairs = asset_tags.split(',')
        tag_pairs = str(tag_pairs).replace("'", '"')
        tag_pairs = str(tag_pairs).replace(" ", '')
        tfvars_file.write(f'common_tags = {tag_pairs}')
      # elif common_tags:
      #   common_tags = [f"{x.lower()}-{y.lower()}" for x, y in common_tags.items()]
      #   common_tags = str(common_tags).replace("'", '"')
      #   common_tags = str(common_tags).replace(" ", '')
      #   tfvars_file.write(f'common_tags = {common_tags}')

    self.logger.info('Finished converting GKE Standard configuration file to terraform tfvars file')

  def convert_gke_autopilot_to_tfvars(self, cluster_name: str, vpc_network: str, region: str,
                                      terraform_variables, project_id):
    self.logger.info('Converting GKE Autopilot configuration file to terraform tfvars file')

    with open("./abstrakt/terraformModules/gcp/gke/autopilot/variables.tfvars", "w") as tfvars_file:
      for key, value in terraform_variables.items():
        if value.lower() in ["true", "false"]:
          tfvars_file.write(f'{key} = {value.lower()}\n')
        else:
          if key == 'cluster_name':
            if cluster_name:
              tfvars_file.write(f'cluster_name = "{cluster_name}"\n')
            else:
              tfvars_file.write(f'{key} = "{value.lower()}"\n')
          elif key == 'vpc_network':
            if vpc_network:
              tfvars_file.write(f'vpc_network = "{vpc_network}"\n')
            else:
              tfvars_file.write(f'{key} = "{value.lower()}"\n')
          elif key == 'region':
            if region:
              tfvars_file.write(f'region = "{region}"\n')
            else:
              tfvars_file.write(f'{key} = "{value}"\n')
          elif key == 'project_id':
            if project_id:
              tfvars_file.write(f'project_id = "{project_id}"\n')
            else:
              tfvars_file.write(f'{key} = "{value}"\n')
          else:
            tfvars_file.write(f'{key} = "{value}"\n')

    self.logger.info('Finished converting GKE Autopilot configuration file to terraform tfvars file')

  def convert_aks_to_tfvars(self, cluster_name: str, rg_name: str, rg_location: str, asset_tags: str,
                            terraform_variables, common_tags):
    self.logger.info('Converting AKS configuration file to terraform tfvars file')

    with open("./abstrakt/terraformModules/azure/aks/variables.tfvars", "w") as tfvars_file:
      for key, value in terraform_variables.items():
        if value.lower() in ["true", "false"]:
          tfvars_file.write(f'{key} = {value.lower()}\n')
        else:
          if key == 'cluster_name':
            if cluster_name:
              tfvars_file.write(f'cluster_name = "{cluster_name}"\n')
            else:
              tfvars_file.write(f'{key} = "{value.lower()}"\n')
          elif key == 'resource_group_name':
            if rg_name:
              tfvars_file.write(f'resource_group_name = "{rg_name}"\n')
            else:
              tfvars_file.write(f'{key} = "{value.lower()}"\n')
          elif key == 'resource_group_location':
            if rg_location:
              tfvars_file.write(f'resource_group_location = "{rg_location}"\n')
            else:
              tfvars_file.write(f'{key} = "{value}"\n')
          else:
            tfvars_file.write(f'{key} = "{value}"\n')

      if asset_tags:
        tag_pairs = asset_tags.split(',')
        common_tags = {key_value.split('=')[0]: key_value.split('=')[1] for key_value in tag_pairs}
        tfvars_file.write(f'common_tags = {json.dumps(common_tags)}\n')
      elif common_tags:
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
