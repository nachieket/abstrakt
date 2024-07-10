import subprocess
from kubernetes import client, config


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

  def is_helm_chart_deployed(self, release_name, namespace="default"):
    try:
        # Run the Helm command to list releases in the specified namespace
        result = subprocess.run(
            ["helm", "list", "-n", namespace, "--filter", release_name, "--output", "json"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Parse the output
        output = result.stdout.decode("utf-8")
        if release_name in output:
            return True
        else:
            return False

    except subprocess.CalledProcessError as e:
        self.logger.error(f"Error running Helm command: {e.stderr.decode('utf-8')}")
        return False
