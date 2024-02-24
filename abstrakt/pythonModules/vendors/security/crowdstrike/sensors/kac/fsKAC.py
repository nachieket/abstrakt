import subprocess
import json
import base64

from time import sleep

from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading
from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf


class FalconKAC:
  def __init__(self, falcon_client_id: str, falcon_client_secret: str, falcon_cloud_region: str, falcon_cid: str,
               logger):
    self.falcon_client_id = falcon_client_id
    self.falcon_client_secret = falcon_client_secret
    self.falcon_cloud_region = falcon_cloud_region
    self.falcon_cid = falcon_cid
    self.logger = logger

  def deploy_falcon_kac(self):
    printf(f"\n{'+' * 44}\nCrowdStrike Kubernetes Admission Controller\n{'+' * 44}\n", logger=self.logger)

    printf('Installing Kubernetes Admission Controller...', logger=self.logger)

    try:
      def thread():
        # Step 1: Download falcon-container-sensor-pull.sh
        process = subprocess.run(["curl", "-sSL", "-o", "falcon-container-sensor-pull.sh",
                                  "https://raw.githubusercontent.com/CrowdStrike/falcon-scripts/main/bash/containers/"
                                  "falcon-container-sensor-pull/falcon-container-sensor-pull.sh"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

        if process.stdout:
          self.logger.info(process.stdout)

        if process.stderr:
          self.logger.info(process.stderr)

        # Step 2: Make the script executable
        process = subprocess.run(["chmod", "+x", "falcon-container-sensor-pull.sh"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

        if process.stdout:
          self.logger.info(process.stdout)

        if process.stderr:
          self.logger.info(process.stderr)

        # Step 3: Run falcon-container-sensor-pull.sh with the required arguments to get KAC version
        process = subprocess.run(["./falcon-container-sensor-pull.sh",
                                  "-u", f"{self.falcon_client_id}",
                                  "-s", f"{self.falcon_client_secret}",
                                  "--list-tags",
                                  "-t", "falcon-kac"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

        if process.stdout:
          self.logger.info(process.stdout)

        if process.stderr:
          self.logger.info(process.stderr)

        # Parse the JSON output and get the latest KAC version
        kac_version = json.loads(process.stdout)['tags'][-1]

        # Step 4: Set image repo and tag variables
        falcon_image_repo = f"registry.crowdstrike.com/falcon-kac/{self.falcon_cloud_region}/release/falcon-kac"
        falcon_image_tag = f"{kac_version}"

        # Step 5: Run falcon-container-sensor-pull.sh to dump credentials
        process = subprocess.run(["./falcon-container-sensor-pull.sh",
                                  "-u", f"{self.falcon_client_id}",
                                  "-s", f"{self.falcon_client_secret}",
                                  "--dump-credentials"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

        if process.stdout:
          self.logger.info(process.stdout)

        if process.stderr:
          self.logger.info(process.stderr)

        # Split the output and extract Falcon Art credentials
        text_output = process.stdout.split(' ')
        falcon_art_username = text_output[-4].split('\n')[0]
        falcon_art_password = text_output[-1].split('\n')[0]

        # Step 6: Generate Falcon Image Pull Token
        partial_pull_token = base64.b64encode(f"{falcon_art_username}:{falcon_art_password}".encode()).decode()

        falcon_image_pull_data = {
          "auths": {
            "registry.crowdstrike.com": {
              "auth": partial_pull_token
            }
          }
        }

        falcon_image_pull_token = base64.b64encode(json.dumps(falcon_image_pull_data).encode()).decode()

        # Step 7: Install Helm repository and release
        process = subprocess.run(["helm", "repo", "add", "crowdstrike", "https://crowdstrike.github.io/falcon-helm"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

        if process.stdout:
          self.logger.info(process.stdout)

        if process.stderr:
          self.logger.info(process.stderr)

        process = subprocess.run(["helm", "repo", "update"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, check=True)

        if process.stdout:
          self.logger.info(process.stdout)

        if process.stderr:
          self.logger.info(process.stderr)

        process = subprocess.run(["helm", "repo", "list"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, check=True)

        if process.stdout:
          self.logger.info(process.stdout)

        if process.stderr:
          self.logger.info(process.stderr)

        falcon_kac_repo = "crowdstrike/falcon-kac"

        install_process = subprocess.run(["helm", "install", "falcon-kac", falcon_kac_repo,
                                          "-n", "falcon-kac", "--create-namespace",
                                          "--set", f"falcon.cid={self.falcon_cid}",
                                          "--set", f"image.repository={falcon_image_repo}",
                                          "--set", f"image.tag={falcon_image_tag}",
                                          "--set", f"image.registryConfigJSON={falcon_image_pull_token}"],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

        if install_process.stdout:
          self.logger.info(install_process.stdout)

        if install_process.stderr:
          self.logger.info(install_process.stderr)

      with MultiThreading() as mt:
        mt.run_with_progress_indicator(thread, 1)

      printf('Kubernetes admission controller installed successfully.\n', logger=self.logger)

      # print('Waiting for Kubernetes Admission Controller pod to come up...')
      #
      # with MultiThreading() as mt:
      #   mt.run_with_progress_indicator(sleep, 1, 10)

      # printf('Checking Kubernetes Admission Controller status...\n', logger=self.logger)

      container = ContainerOps(logger=self.logger)
      container.pod_checker(pod_name='falcon-kac', namespace='falcon-kac', kubeconfig_path='~/.kube/config')
    except subprocess.CalledProcessError as e:
      printf(f"Error: {e}", logger=self.logger)
      printf(f"Command output: {e.stdout}", logger=self.logger)
      printf(f"Command error: {e.stderr}", logger=self.logger)
      printf(f'Kubernetes admission controller installation failed\n', logger=self.logger)
