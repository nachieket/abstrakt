import subprocess
import json
# import os
import random
import string

from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading
from abstrakt.pythonModules.vendors.security.crowdstrike.crowdstrike import CrowdStrike


class FalconKPA(CrowdStrike):
  def __init__(self, falcon_client_id, falcon_client_secret, logger):
    super().__init__(falcon_client_id, falcon_client_secret, logger)
    self.falcon_client_id = falcon_client_id
    self.falcon_client_secret = falcon_client_secret
    self.logger = logger

  def get_api_access_token(self, falcon_cloud_api):
    try:
      result = subprocess.run([
        "curl", "-sL", "-X", "POST", f"https://{falcon_cloud_api}/oauth2/token",
        "-H", "Content-Type: application/x-www-form-urlencoded",
        "--data-urlencode", f"client_id={self.falcon_client_id}",
        "--data-urlencode", f"client_secret={self.falcon_client_secret}"
      ], capture_output=True, text=True)

      access_token = json.loads(result.stdout)['access_token']
      return access_token
    except Exception as e:
      self.logger.error(e)
      return ""

  def execute_kpa_installation_process(self):
    falcon_cid, falcon_cloud_api, falcon_cloud_region = self.get_cid_api_region()

    if access_token := self.get_api_access_token(falcon_cloud_api) and falcon_cid and falcon_cloud_region:
      try:
        # Set FALCON_API_ACCESS_TOKEN
        # os.environ['FALCON_API_ACCESS_TOKEN'] = access_token

        # Get FALCON_CCID and set FALCON_CID, FALCON_KPA_USERNAME
        # ccid_command = [
        #   "curl", "-sL", "-X", "GET", f"https://{falcon_cloud_api}/sensors/queries/installers/ccid/v1",
        #   "-H", f"Authorization: Bearer {access_token}"
        # ]

        # ccid_result = subprocess.run(ccid_command, capture_output=True, text=True)

        # if ccid_result.stdout:
        #   self.logger.info(ccid_result.stdout)
        # if ccid_result.stderr:
        #   self.logger.error(ccid_result.stderr)
        #
        # falcon_ccid = json.loads(ccid_result.stdout)['resources'][0].lower()

        # os.environ['FALCON_CCID'] = falcon_ccid
        # os.environ['FALCON_CID'] = falcon_cid.split('-')[0]
        # os.environ['FALCON_KPA_USERNAME'] = f"kp-{falcon_ccid.split('-')[0]}"

        # Get FALCON_KPA_PASSWORD
        kpa_password_command = [
          "curl", "-sL", "-X", "GET",
          f"https://{falcon_cloud_api}/"
          f"kubernetes-protection/entities/integration/agent/v1?cluster_name=&is_self_managed_cluster=true",
          "-H", "Accept: application/yaml",
          "-H", f"Authorization: Bearer {access_token}"
        ]

        kpa_password_result = subprocess.run(kpa_password_command, capture_output=True, text=True)

        if kpa_password_result.stdout:
          self.logger.info(kpa_password_result.stdout)
        if kpa_password_result.stderr:
          self.logger.error(kpa_password_result.stderr)

        falcon_kpa_password = kpa_password_result.stdout.split('dockerAPIToken:')[1].strip()

        # os.environ['FALCON_KPA_PASSWORD'] = falcon_kpa_password

        cluster_name_command = [
          "kubectl", "config", "view", "--minify", "--output", "'jsonpath={..cluster}'", "|", "awk", "'{ print $NF }'"
        ]

        process = subprocess.run(cluster_name_command, capture_output=True, text=True)

        if process.stdout:
          cluster_name = process.stdout
        else:
          # Generate a random 4-character string including letters and digits
          random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
          cluster_name = f"random_{random_string}_cluster"

        # Run Helm upgrade/install command
        process = subprocess.run([
          "helm", "upgrade", "--install", "kpagent", "kpagent-helm/cs-k8s-protection-agent",
          "-n", "falcon-kubernetes-protection", "--create-namespace",
          "--set", f"crowdstrikeConfig.clientID={self.falcon_client_id}",
          "--set", f"crowdstrikeConfig.clientSecret={self.falcon_client_secret}",
          "--set", f"crowdstrikeConfig.clusterName={cluster_name}",
          "--set", f"crowdstrikeConfig.env={falcon_cloud_region}",
          "--set", f"crowdstrikeConfig.cid={falcon_cid.split('-')[0]}",
          "--set", f"crowdstrikeConfig.dockerAPIToken={falcon_kpa_password}"
        ], capture_output=True, text=True)

        if process.stdout:
          self.logger.info(process.stdout)
          return True
        if process.stderr:
          self.logger.error(process.stderr)
          return False
      except Exception as e:
        self.logger.erro(e)
        return False
    else:
      return False

  def deploy_falcon_kpa(self):
    print('Installing Kubernetes Protection Agent...\n')

    with MultiThreading() as mt:
      status = mt.run_with_progress_indicator(self.execute_kpa_installation_process(), 1)

    if status:
      print('Kubernetes protection agent installation successful\n')

      container = ContainerOps(logger=self.logger)
      container.pod_checker(pod_name='kpagent', namespace='falcon-kubernetes-protection',
                            kubeconfig_path='~/.kube/config')
    else:
      print('Failed to install kubernetes protection agent\n')
