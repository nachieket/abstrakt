import subprocess


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
      print('Kubeconfig update did not receive right parameters. Check log file for more information.\n')
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
          print("Kubeconfig updated successfully.\n")
          # return stdout.strip()
          return True
        else:
          self.logger.error(process.stderr)
          return False
      else:
        print('Error occurred while updating kubeconfig. Check log file for more information.')
        self.logger.error('Incorrect parameters passed. Check update_kubeconfig method.\n')
        return False
    except Exception as e:
      self.logger.error('Kubeconfig update did not succeed. Check log file for more information.\n')
      self.logger.error(f'{e}')
      return False
