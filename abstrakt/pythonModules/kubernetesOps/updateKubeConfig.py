import subprocess

from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf


class UpdateKubeConfig:
  def __init__(self, logger):
    self.logger = logger

  def update_kubeconfig(self, cloud, region=None, cluster_name=None, resource_group=None, gcp_project_id=None):
    command = ''

    try:
      if cloud == 'aws':
        command = ["aws", "eks", "update-kubeconfig", "--region", region, "--name", cluster_name]
      elif cloud == 'azure':
        command = ["az", "aks", "get-credentials", "--resource-group", resource_group, "--name", cluster_name,
                   "--overwrite-existing"]
      elif cloud == 'gcp':
        command = ['gcloud', 'container', 'clusters', 'get-credentials', cluster_name, '--region', region,
                   '--project', gcp_project_id]
    except Exception as e:
      printf('Kubeconfig update did not receive right parameters. Check log file for more information.\n')
      self.logger.error(f'{e}')
      return False

    try:
      if command != '':
        self.logger.info(f'Executing command: {command}')
        process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if process.stdout:
          self.logger.info(process.stdout)

        if process.stderr:
          self.logger.error(process.stderr)

        if process.returncode == 0:
          printf("Kubeconfig updated successfully.\n", logger=self.logger)
          # return stdout.strip()
          return True
        else:
          printf("Error updating kubeconfig:", logger=self.logger)
          printf(process.stderr, logger=self.logger)
          return False
      else:
        printf('Error occurred while updating kubeconfig. Check log file for more information.')
        self.logger.error('Incorrect parameters passed. Check update_kubeconfig method.\n')
    except Exception as e:
      printf('Kubeconfig update did not succeed. Check log file for more information.\n')
      self.logger.error(f'{e}')

# def update_eks_kubeconfig(self, region, cluster_name):
  #   try:
  #     command = ["aws", "eks", "update-kubeconfig", "--region", region, "--name", cluster_name]
  #     self.logger.info(f'Command to execute: {command}')
  #
  #     process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
  #
  #     if process.stdout:
  #       self.logger.info(process.stdout)
  #
  #     if process.stderr:
  #       self.logger.info(process.stderr)
  #
  #     if process.returncode == 0:
  #       printf("Kubeconfig updated successfully.\n", logger=self.logger)
  #       # return stdout.strip()
  #       return True
  #     else:
  #       printf("Error updating kubeconfig:", logger=self.logger)
  #       printf(process.stderr, logger=self.logger)
  #       return False
  #   except Exception as e:
  #     printf(f"Error executing command: {e}", logger=self.logger)
  #     return False

  # def update_aks_kubeconfig(self, resource_group_name, cluster_name):
  #   try:
  #
  #     command = ["az", "aks", "get-credentials", "--resource-group", resource_group_name, "--name", cluster_name,
  #                "--overwrite-existing"]
  #
  #     self.logger.info(f'Command to execute: {command}')
  #
  #     process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
  #
  #     if process.stdout:
  #       self.logger.info(process.stdout)
  #
  #     if process.stderr:
  #       self.logger.info(process.stderr)
  #
  #     printf("Kubeconfig updated successfully.\n", logger=self.logger)
  #     return True
  #   except Exception as e:
  #     printf(f"Error updating kubeconfig: {e}", logger=self.logger)
  #     return False
