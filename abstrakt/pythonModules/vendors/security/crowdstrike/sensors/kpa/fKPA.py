import subprocess

from time import sleep

from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading
from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf


class FalconKPA:
  def __init__(self, logger, config_file_path="./abstrakt/conf/crowdstrike/kpa/config_value.yaml"):
    self.add_helm_repo_cmd = ["helm", "repo", "add", "kpagent-helm", "https://registry.crowdstrike.com/kpagent-helm"]
    self.update_helm_repo_cmd = ["helm", "repo", "update"]
    self.config_file_path = config_file_path
    self.helm_upgrade_install_cmd = [
      "helm", "upgrade", "--install",
      "-f", self.config_file_path,
      "--create-namespace",
      "-n", "falcon-kubernetes-protection",
      "kpagent", "kpagent-helm/cs-k8s-protection-agent",
    ]
    self.logger = logger

  def deploy_kpa(self):
    printf(f"\n{'+' * 40}\nCrowdStrike Kubernetes Protection Agent\n{'+' * 40}\n", logger=self.logger)

    print('Installing Kubernetes Protection Agent...\n')

    try:
      add_helm_repo = subprocess.run(self.add_helm_repo_cmd, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, check=True)

      if add_helm_repo.stdout:
        self.logger.info(add_helm_repo.stdout)

      if add_helm_repo.stderr:
        self.logger.info(add_helm_repo.stderr)

      update_helm_repo = subprocess.run(self.update_helm_repo_cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, check=True)

      if update_helm_repo.stdout:
        self.logger.info(update_helm_repo.stdout)

      if update_helm_repo.stderr:
        self.logger.info(update_helm_repo.stderr)

      printf('Helm repo added and updated successfully', logger=self.logger)
    except subprocess.CalledProcessError as e:
      printf(f"error: {e}. failed to add and update helm repo.\n", logger=self.logger)
      return

    try:
      def thread():
        helm_install = subprocess.run(self.helm_upgrade_install_cmd, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, check=True)
        if helm_install.stdout:
          self.logger.info(helm_install.stdout)

        if helm_install.stderr:
          self.logger.info(helm_install.stderr)

      with MultiThreading() as mt:
        mt.run_with_progress_indicator(thread, 1)

      printf('Kubernetes protection agent installation successful\n', logger=self.logger)

      # print('Waiting for kubernetes protection agent pod to come up...')
      #
      # with MultiThreading() as mt:
      #   mt.run_with_progress_indicator(sleep, 1, 10)

      # print('Checking Kubernetes Protection Agent status...\n')

      container = ContainerOps(logger=self.logger)
      container.pod_checker(pod_name='kpagent', namespace='falcon-kubernetes-protection',
                            kubeconfig_path='~/.kube/config')

      # container = ContainerOps(logger=self.logger)
      # sensors = container.get_running_container_name('kpagent', 'falcon-kubernetes-protection')

      # if sensors != 'None':
      #   printf('Kubernetes Protection Agent deployed and running successfully:', logger=self.logger)
      #   for sensor in sensors:
      #     printf(sensor, logger=self.logger)
      #   else:
      #     print()
      # else:
      #   printf('No running Kubernetes Protection Agent found. Ensure it is up and running with kubectl get pods -n',
      #          'falcon-kubernetes-protection command\n', logger=self.logger)
    except subprocess.CalledProcessError as e:
      printf(f"Error: {e}. failed to install Kubernetes Protection Agent.\n", logger=self.logger)
