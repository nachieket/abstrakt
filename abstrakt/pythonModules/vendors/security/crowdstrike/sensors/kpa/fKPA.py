import subprocess
import json
import os
import re

from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading


class FalconKPA:
  def __init__(self, falcon_client_id, falcon_client_secret, cluster_Name, logger):
    self.falcon_client_id = falcon_client_id
    self.falcon_client_secret = falcon_client_secret
    self.cluster_name = cluster_Name
    self.logger = logger

  def get_base_url(self):
    try:
      # Step 1: Download falcon-container-sensor-pull.sh
      process = subprocess.run(["curl", "-sSL", "-o", "falcon-container-sensor-pull.sh",
                                "https://raw.githubusercontent.com/CrowdStrike/falcon-scripts/main/bash/containers/"
                                "falcon-container-sensor-pull/falcon-container-sensor-pull.sh"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

      if process.stdout:
        self.logger.info(process.stdout)
      if process.stderr:
        self.logger.error(process.stderr)

      # Step 2: Make the script executable
      process = subprocess.run(["chmod", "+x", "falcon-container-sensor-pull.sh"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

      if process.stdout:
        self.logger.info(process.stdout)
      if process.stderr:
        self.logger.error(process.stderr)

      # Step 3: Get API Information
      process = subprocess.run(["./falcon-container-sensor-pull.sh", "--client-id", f"{self.falcon_client_id}",
                                "--client-secret", f"{self.falcon_client_secret}", "--dump-credentials"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

      # Regular expression to match 'Falcon Region' and capture its value
      if process.stdout:
        match = re.search(r'Falcon Region:\s*(\S+)', process.stdout)

        # Extract the matched value
        if match:
          return match.group(1)
        else:
          self.logger.error("Falcon Region not found.")
          return ""
      elif process.stderr:
        self.logger.error(process.stderr)
        return ""
    except Exception as e:
      self.logger.error(e)
      return ""

  def get_api_access_token(self, falcon_api_base_url):
    result = subprocess.run([
      "curl", "-sL", "-X", "POST", f"https://{falcon_api_base_url}/oauth2/token",
      "-H", "Content-Type: application/x-www-form-urlencoded",
      "--data-urlencode", f"client_id={self.falcon_client_id}",
      "--data-urlencode", f"client_secret={self.falcon_client_secret}"
    ], capture_output=True, text=True)

    access_token = json.loads(result.stdout)['access_token']
    return access_token

  def configure_falcon_integration(self):
    def thread():
      falcon_api_base_url = self.get_base_url()

      if falcon_api_base_url == "":
        return False
      else:
        if falcon_api_base_url == 'api.crowdstrike.com':
          falcon_cloud_region = 'us-1'
        else:
          falcon_cloud_region = falcon_api_base_url.split('.')[1]

      access_token = self.get_api_access_token(falcon_api_base_url)

      # Set FALCON_API_ACCESS_TOKEN
      os.environ['FALCON_API_ACCESS_TOKEN'] = access_token

      # Get FALCON_CCID and set FALCON_CID, FALCON_KPA_USERNAME
      ccid_command = [
        "curl", "-sL", "-X", "GET", f"https://{falcon_api_base_url}/sensors/queries/installers/ccid/v1",
        "-H", f"Authorization: Bearer {access_token}"
      ]

      ccid_result = subprocess.run(ccid_command, capture_output=True, text=True)

      if ccid_result.stdout:
        self.logger.info(ccid_result.stdout)
      if ccid_result.stderr:
        self.logger.error(ccid_result.stderr)

      falcon_ccid = json.loads(ccid_result.stdout)['resources'][0].lower()

      os.environ['FALCON_CCID'] = falcon_ccid
      os.environ['FALCON_CID'] = falcon_ccid.split('-')[0]
      os.environ['FALCON_KPA_USERNAME'] = f"kp-{falcon_ccid.split('-')[0]}"

      # Get FALCON_KPA_PASSWORD
      kpa_password_command = [
        "curl", "-sL", "-X", "GET",
        f"https://{falcon_api_base_url}/kubernetes-protection/entities/integration/agent/v1?cluster_name=&is_self_managed_cluster=true",
        "-H", "Accept: application/yaml",
        "-H", f"Authorization: Bearer {access_token}"
      ]

      kpa_password_result = subprocess.run(kpa_password_command, capture_output=True, text=True)

      if kpa_password_result.stdout:
        self.logger.info(kpa_password_result.stdout)
      if kpa_password_result.stderr:
        self.logger.error(kpa_password_result.stderr)

      falcon_kpa_password = kpa_password_result.stdout.split('dockerAPIToken:')[1].strip()

      os.environ['FALCON_KPA_PASSWORD'] = falcon_kpa_password

      # Run Helm upgrade/install command
      process = subprocess.run([
        "helm", "upgrade", "--install", "kpagent", "kpagent-helm/cs-k8s-protection-agent",
        "-n", "falcon-kubernetes-protection", "--create-namespace",
        "--set", f"crowdstrikeConfig.clientID={self.falcon_client_id}",
        "--set", f"crowdstrikeConfig.clientSecret={self.falcon_client_secret}",
        "--set", f"crowdstrikeConfig.clusterName={self.cluster_name}",
        "--set", f"crowdstrikeConfig.env={falcon_cloud_region}",
        "--set", f"crowdstrikeConfig.cid={os.environ['FALCON_CID']}",
        "--set", f"crowdstrikeConfig.dockerAPIToken={os.environ['FALCON_KPA_PASSWORD']}"
      ], capture_output=True, text=True)

      if process.stdout:
        self.logger.info(process.stdout)
        return True
      if process.stderr:
        self.logger.error(process.stderr)
        return False

    with MultiThreading() as mt:
      status = mt.run_with_progress_indicator(thread, 1)

    if status:
      print('Kubernetes protection agent installation successful\n')

      container = ContainerOps(logger=self.logger)
      container.pod_checker(pod_name='kpagent', namespace='falcon-kubernetes-protection',
                            kubeconfig_path='~/.kube/config')
    else:
      print('Failed to install kubernetes protection agent\n')
