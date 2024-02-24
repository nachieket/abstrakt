import subprocess


class HelmOps:
  def __init__(self, logger):
    self.logger = logger

  def run_helm_delete(self, release_name, namespace):
    try:
      process = subprocess.run(["helm", "delete", release_name, "-n", namespace], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, check=True)

      if process.stdout:
        self.logger.info(process.stdout)
      if process.stderr:
        self.logger.info(process.stderr)

      self.logger.info(f"Deleted Helm release {release_name} in namespace {namespace}")
    except subprocess.CalledProcessError as e:
      self.logger.info(f"Error deleting Helm release {release_name} in namespace {namespace}: {e}")
