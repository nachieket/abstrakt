import subprocess

from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf


class K8sLoadSimulator:
  def __init__(self, logger):
    self.logger = logger

  def install_load_test_apps(self):
    """
    Apply Kubernetes YAML files using `kubectl apply`.
    """
    print('+' * 23)
    print('Generic Load Test Apps')
    print('+' * 23, '\n')

    print('Installing Load Test Apps...\n')

    yaml_files = [
      "./modules/vendors/generic/k8sLoadSimulator/definitions/metrics.yaml",
      "./modules/vendors/generic/k8sLoadSimulator/definitions/phpApache.yaml",
      "./modules/vendors/generic/k8sLoadSimulator/definitions/infiniteCalls.yaml"
    ]

    try:
      for file_path in yaml_files:
        # Run `kubectl apply` command for each file
        process = subprocess.run(["kubectl", "apply", "-f", file_path], check=True, text=True, capture_output=True)

        if process.stdout:
          self.logger.info(process.stdout)

        if process.stderr:
          self.logger.info(process.stderr)

        printf("Load test apps installed successfully.\n", logger=self.logger)
    except subprocess.CalledProcessError as e:
      # Handle any errors or exceptions
      printf(f"Error running 'kubectl apply': {e}\n", logger=self.logger)
      printf("Failed to install load test apps.\n", logger=self.logger)
