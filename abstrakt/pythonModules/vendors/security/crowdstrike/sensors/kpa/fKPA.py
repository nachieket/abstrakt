import subprocess
import json
import random
import string

from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading
from abstrakt.pythonModules.vendors.security.crowdstrike.crowdstrike import CrowdStrike


class FalconKPA(CrowdStrike):
  def __init__(self, falcon_client_id: str, falcon_client_secret: str, logger):
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

    if (falcon_cid or falcon_cloud_api or falcon_cloud_region) is None:
      self.logger.info(falcon_cid, falcon_cloud_api, falcon_cloud_region)
      self.logger.error('Either of falcon_cid, falcon_cloud_api, or falcon_cloud_region not found.')
      return False

    access_token = self.get_api_access_token(falcon_cloud_api)

    if access_token:
      try:
        kpa_password_command = [
          "curl", "-sL", "-X", "GET",
          f"https://{falcon_cloud_api}/"
          f"kubernetes-protection/entities/integration/agent/v1?cluster_name=&is_self_managed_cluster=true",
          "-H", "Accept: application/yaml",
          "-H", f"Authorization: Bearer {access_token}"
        ]

        # Debug Log
        self.logger.info(kpa_password_command)

        kpa_password_result = subprocess.run(kpa_password_command, capture_output=True, text=True)

        if kpa_password_result.stdout:
          self.logger.info(kpa_password_result.stdout)
        if kpa_password_result.stderr:
          self.logger.error(kpa_password_result.stderr)

        falcon_kpa_password = kpa_password_result.stdout.split('dockerAPIToken:')[1].strip()

        # Debug Log
        self.logger.info(falcon_kpa_password)

        cluster_name_command = [
          "kubectl", "config", "view", "--minify", "--output", "jsonpath={..cluster}"
        ]

        # Generate a random 4-character string including letters and digits
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
        cluster_name = f"random_{random_string}_cluster"

        process = subprocess.run(cluster_name_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, check=True)

        if process.stdout:
          # Debug Log
          self.logger.info(process.stdout)
          for x in process.stdout.split(' '):
            if 'certificate-authority-data' not in x:
              cluster_name = x
              # if '/' in cluster_name:
              #     cluster_name = cluster_name.split('/')[-1]
              # Debug Log
              self.logger.info(cluster_name)

        command = ["helm", "repo", "add", "kpagent-helm", "https://registry.crowdstrike.com/kpagent-helm"]

        process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

        if process.stdout:
          self.logger.info(process.stdout)
        if process.stderr:
          self.logger.error(process.stderr)

        command = ["helm", "repo", "update"]

        process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

        if process.stdout:
          self.logger.info(process.stdout)
        if process.stderr:
          self.logger.error(process.stderr)

        command = [
          "helm", "upgrade", "--install", "kpagent", "kpagent-helm/cs-k8s-protection-agent",
          "-n", "falcon-kubernetes-protection", "--create-namespace",
          "--set", f"crowdstrikeConfig.clientID={self.falcon_client_id}",
          "--set", f"crowdstrikeConfig.clientSecret={self.falcon_client_secret}",
          "--set", f"crowdstrikeConfig.clusterName={cluster_name}",
          "--set", f"crowdstrikeConfig.env={falcon_cloud_region}",
          "--set", f"crowdstrikeConfig.cid={falcon_cid.split('-')[0]}",
          "--set", f"crowdstrikeConfig.dockerAPIToken={falcon_kpa_password}"
        ]

        self.logger.info(command)

        # Run Helm upgrade/install command
        process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

        if process.stdout:
          self.logger.info(process.stdout)
          return True
        if process.stderr:
          self.logger.error(process.stderr)
          return False
      except Exception as e:
        self.logger.error(e)
        return False
    else:
      return False

  def deploy_falcon_kpa(self):
    print(f"\n{'+' * 40}\nCrowdStrike Kubernetes Protection Agent\n{'+' * 40}\n")

    print('Installing Kubernetes Protection Agent...')

    k8s = KubectlOps(logger=self.logger)

    if k8s.namespace_exists(namespace_name='falcon-kubernetes-protection'):
      captured_pods, status = k8s.find_pods_with_status(pod_string='kpagent', namespace='falcon-kubernetes-protection')

      if (status is True) and (len(captured_pods['running']) > 0):
        print('Kubernetes Protection Agent found up and running in falcon-kubernetes-protection namespace. Not '
              'proceeding with installation.')

        for pod in captured_pods['running']:
          print(pod)

        print()
        return

    with MultiThreading() as mt:
      status = mt.run_with_progress_indicator(self.execute_kpa_installation_process, 1)

    if status:
      print('Kubernetes protection agent installation successful\n')

      container = ContainerOps(logger=self.logger)
      container.pod_checker(pod_name='kpagent', namespace='falcon-kubernetes-protection',
                            kubeconfig_path='~/.kube/config')
    else:
      print('Failed to install kubernetes protection agent\n')
