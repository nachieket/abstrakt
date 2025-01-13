import configparser


# import pytz
# from datetime import datetime
#
# from ...modules.customLogging.customLogging import CustomLogger
# from ...modules.pythonOps.customPrint.customPrint import printf


class ParseConfigFile:
  def __init__(self, logger):
    self.logger = logger

  def read_eks_managed_node_config_file(self, file_path):
    self.logger.info('Reading EKS Managed Node Configuration File')

    config = configparser.ConfigParser()
    config.read(file_path)

    parameters = {key: config.get("terraform_variables", key).strip('"')
                  for key in config.options("terraform_variables")}

    if 'terraform_variables:common_tags' in config.sections():
      common_tags = {key: config.get("terraform_variables:common_tags", key).strip('"')
                     for key in config.options("terraform_variables:common_tags")}
    else:
      common_tags = {}

    node_groups = {
      key.split(":")[-1]: {
        subkey: [config.get(key, subkey).strip('"')] if subkey == "instance_types" else config.get(key, subkey).strip(
          '"')
        for subkey in config.options(key)
      }
      for key in config.sections()
      if key.startswith("terraform_variables:group")
    }

    self.logger.info('Finished reading EKS Managed Node Configuration file. Returning captured values.')

    return parameters, node_groups, common_tags

  def read_aws_k8s_cluster_config_file(self,
                                       cluster_type: str,
                                       config_file: str) -> tuple[dict[str, str], dict[str, str]]:
    self.logger.info(f'Reading {cluster_type} Configuration File')

    config = configparser.ConfigParser()
    config.read(config_file)

    terraform_variables = {key: config.get("terraform_variables", key).strip('"')
                           for key in config.options("terraform_variables")}

    if 'terraform_variables:common_tags' in config.sections():
      tags = {key: config.get("terraform_variables:common_tags", key).strip('"')
              for key in config.options("terraform_variables:common_tags")}
    else:
      tags = {}

    self.logger.info(f'Finished reading {cluster_type} Configuration file. Returning captured values.')

    return terraform_variables, tags

  def read_aks_config_file(self, file_path):
    self.logger.info('Reading AKS Configuration File')

    config = configparser.ConfigParser()
    config.read(file_path)

    terraform_variables = {key: config.get("terraform_variables", key).strip('"')
                           for key in config.options("terraform_variables")}

    tags = {key: config.get("terraform_variables:common_tags", key).strip('"') for key in
            config.options("terraform_variables:common_tags")}

    self.logger.info('Finished reading AKS Configuration file. Returning captured values.')

    return terraform_variables, tags

  def read_gke_standard_config_file(self, file_path):
    self.logger.info('Reading GKE Standard Configuration File')

    config = configparser.ConfigParser()
    config.read(file_path)

    terraform_variables = {key: config.get("terraform_variables", key).strip('"')
                           for key in config.options("terraform_variables")}

    # tags = {key: config.get("terraform_variables:common_tags", key).strip('"') for key in
    #         config.options("terraform_variables:common_tags")}

    self.logger.info('Finished reading GKE Standard Configuration file. Returning captured values.')

    # return terraform_variables, tags
    return terraform_variables

  def read_gke_autopilot_config_file(self, file_path):
    self.logger.info('Reading GKE Autopilot Configuration File')

    config = configparser.ConfigParser()
    config.read(file_path)

    terraform_variables = {key: config.get("terraform_variables", key).strip('"')
                           for key in config.options("terraform_variables")}

    self.logger.info('Finished reading GKE Autopilot Configuration file. Returning captured values.')

    return terraform_variables

  def read_aci_config_file(self, file_path):
    self.logger.info('Reading ACI Configuration File')

    config = configparser.ConfigParser()
    config.read(file_path)

    terraform_variables = {key: config.get("terraform_variables", key).strip('"')
                           for key in config.options("terraform_variables")}

    self.logger.info('Finished reading ACI Configuration file. Returning captured values.')

    return terraform_variables
