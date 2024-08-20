import subprocess

from abstrakt.pythonModules.multiThread.multithreading import MultiThreading


class VulnerableApps:
  def __init__(self, logger):
    self.logger = logger

  def run_command(self, command):
    try:
      process = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
      self.logger.info(f"Command executed successfully: {command}")
      return process.stdout.strip()
    except subprocess.CalledProcessError as e:
      self.logger.error(f"Error executing command: {command}\n{e}")
      return None

  def deploy_vulnerable_apps(self):
    try:
      print(f"{'+' * 16}\nVulnerable Apps\n{'+' * 16}\n")

      print("Deploying Vulnerable Apps...")

      def thread():
        try:
          self.run_command("kubectl create namespace crowdstrike-detections")

          with open('./abstrakt/conf/vulnerableImages/vulnerableImages.txt', 'r') as f:
            for image_path in f.readlines():
              image_name = image_path.strip().split(':')[0]

              if "/" in image_name:
                image_name = image_name.split('/')[-1]

              self.run_command(
                f"kubectl create deploy -n crowdstrike-detections {image_name} --image={image_path.strip()} "
                f"--replicas 1 --dry-run=client -o yaml > ./abstrakt/conf/vulnerableImages/{image_name}.yaml")

              if self.run_command(f"kubectl apply -f ./abstrakt/conf/vulnerableImages/{image_name}.yaml") is not None:
                # container = ContainerOps(logger=self.logger)
                # container.pod_checker(pod_name=image_name, namespace='crowdstrike-detections',
                #                       kubeconfig_path='~/.kube/config')
                pass

          return True
        except Exception as f:
          self.logger.error(f)
          return False

      with MultiThreading() as mt:
        if mt.run_with_progress_indicator(thread, 1):
          print("Vulnerable apps deployed successfully.\n")
        else:
          print('Vulnerable apps did not deploy successfully. Check log files under /var/logs/crowdstrike for more '
                'details')
    except Exception as e:
      self.logger.error(e)
      print('Vulnerable apps deployment failed with errors\n')
