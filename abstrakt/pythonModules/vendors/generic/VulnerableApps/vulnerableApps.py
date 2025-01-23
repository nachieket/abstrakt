import subprocess

# from abstrakt.pythonModules.multiThread.multithreading import MultiThreading
from abstrakt.pythonModules.multiProcess.multiProcessing import MultiProcessing


class VulnerableApps:
  def __init__(self, logger):
    self.logger = logger

  def run_command(self, command, logger=None):
    logger = logger or self.logger

    try:
      process = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
      logger.info(f"Command executed successfully: {command}")
      return process.stdout.strip()
    except subprocess.CalledProcessError as e:
      logger.error(f"Error executing command: {command}\n{e}")
      return None

  def vulnerable_app_thread(self, logger=None):
    logger = logger or self.logger

    try:
      self.run_command("kubectl create namespace crowdstrike-detections", logger=logger)

      with open('./abstrakt/conf/vulnerableImages/vulnerableImages.txt', 'r') as f:
        for image_path in f.readlines():
          image_name = image_path.strip().split(':')[0]

          if "/" in image_name:
            image_name = image_name.split('/')[-1]

          self.run_command(
            f"kubectl create deploy -n crowdstrike-detections {image_name} --image={image_path.strip()} "
            f"--replicas 1 --dry-run=client -o yaml > ./abstrakt/conf/vulnerableImages/{image_name}.yaml",
            logger=logger)

          if self.run_command(f"kubectl apply -f ./abstrakt/conf/vulnerableImages/{image_name}.yaml",
                              logger=logger) is not None:
            pass

      return True
    except Exception as f:
      logger.error(f)
      return False

  def deploy_vulnerable_apps(self, logger=None):
    logger = logger or self.logger

    try:
      print(f"{'+' * 16}\nVulnerable Apps\n{'+' * 16}\n")

      print("Deploying Vulnerable Apps...")

      with MultiProcessing() as mp:
        if mp.execute_with_progress_indicator(self.vulnerable_app_thread, logger,0.5, 300):
          print("Vulnerable apps deployed successfully.\n")
        else:
          print('Vulnerable apps did not deploy successfully. Check log files under /var/logs/crowdstrike for more '
                'details')
    except Exception as e:
      logger.error(e)
      print('Vulnerable apps deployment failed with errors\n')
