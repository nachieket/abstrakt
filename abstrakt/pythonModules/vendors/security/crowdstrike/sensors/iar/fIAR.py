import random
import string
import subprocess

from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading
from abstrakt.pythonModules.vendors.security.crowdstrike.crowdstrike import CrowdStrike


class IAR(CrowdStrike):
  def __init__(self, falcon_client_id: str, falcon_client_secret: str, logger):
    super().__init__(falcon_client_id, falcon_client_secret, logger)
    self.falcon_cid, _, self.falcon_cloud_region = self.get_cid_api_region()
    self.logger = logger

  def run_command(self, command):
    if command != "kubectl create namespace falcon-image-analyzer":
      try:
        process = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        if process.returncode == 0:
          self.logger.info(f"Command executed successfully: {command}")
          return process.stdout.strip()
        else:
          self.logger.info(f"Failed to execute: {command}")
          raise
      except subprocess.CalledProcessError as e:
        self.logger.error(f"Error executing command: {command}\n{e}")
        raise
    else:
      try:
        subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
      except Exception as e:
        self.logger.error(f"Error executing command: {command}\n{e}")

  def execute_iar_installation_process(self):
    try:
      self.run_command(
        'curl -sSL -o falcon-container-sensor-pull.sh '
        '"https://raw.githubusercontent.com/CrowdStrike/falcon-scripts/main/bash/containers/falcon-container-sensor'
        '-pull/falcon-container-sensor-pull.sh"')

      self.run_command("chmod +x falcon-container-sensor-pull.sh")

      falcon_image_full_path = self.run_command(
        f"./falcon-container-sensor-pull.sh --client-id {self.falcon_client_id} --client-secret "
        f"{self.falcon_client_secret} -t falcon-imageanalyzer --get-image-path"
      )

      falcon_image_repo = falcon_image_full_path.split(':')[0]
      falcon_image_tag = falcon_image_full_path.split(':')[1]

      falcon_image_pull_token = self.run_command(
        f"./falcon-container-sensor-pull.sh --client-id {self.falcon_client_id} --client-secret "
        f"{self.falcon_client_secret} -t falcon-imageanalyzer --get-pull-token")

      self.run_command("helm repo add crowdstrike https://crowdstrike.github.io/falcon-helm")
      self.run_command("helm repo update")
      self.run_command("kubectl create namespace falcon-image-analyzer")
      self.run_command("kubectl label --overwrite ns falcon-image-analyzer "
                       "pod-security.kubernetes.io/enforce=privileged")
      output = self.run_command("kubectl config view --minify --output jsonpath={..cluster}")

      # Generate a random 4-character string including letters and digits
      random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
      cluster_name = f"random_{random_string}_cluster"

      if output:
        for x in output.split(' '):
          if 'certificate-authority-data' not in x:
            cluster_name = x

      helm_install_cmd = f"""helm upgrade --install image-analyzer crowdstrike/falcon-image-analyzer \
                          -n falcon-image-analyzer --create-namespace \
                          --set deployment.enabled=true \
                          --set crowdstrikeConfig.cid="{self.falcon_cid}" \
                          --set crowdstrikeConfig.clusterName="{cluster_name}" \
                          --set crowdstrikeConfig.clientID={self.falcon_client_id} \
                          --set crowdstrikeConfig.clientSecret={self.falcon_client_secret} \
                          --set image.registryConfigJSON={falcon_image_pull_token} \
                          --set crowdstrikeConfig.agentRegion={self.falcon_cloud_region} \
                          --set image.repository="{falcon_image_repo}" \
                          --set image.tag="{falcon_image_tag}" """

      self.run_command(helm_install_cmd)

      return True
    except Exception as e:
      self.logger.error(e)
      return None

  def deploy_falcon_iar(self):
    print(f"\n{'+' * 40}\nCrowdStrike Image Assessment at Runtime\n{'+' * 40}\n")

    print('Installing IAR...')

    with MultiThreading() as mt:
      status = mt.run_with_progress_indicator(self.execute_iar_installation_process, 1)

    if status:
      print('IAR installation successful\n')

      container = ContainerOps(logger=self.logger)
      container.pod_checker(pod_name='image-analyzer', namespace='falcon-image-analyzer',
                            kubeconfig_path='~/.kube/config')
    else:
      print('IAR installation failed\n')
