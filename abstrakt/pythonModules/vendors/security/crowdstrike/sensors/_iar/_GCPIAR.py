import random
import string
import inspect

from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors._falconsensor._GCP import _GCP


class _GCPIAR(_GCP):
  def __init__(self, falcon_client_id: str,
               falcon_client_secret: str,
               logger,
               registry: str,
               repository: str,
               project_id: str,
               service_account: str,
               location: str,
               iar_image_tag: str):
    super().__init__(falcon_client_id,
                     falcon_client_secret,
                     logger,
                     registry,
                     repository,
                     project_id,
                     service_account,
                     location)

    self.iar_image_tag: str = iar_image_tag

  def execute_iar_installation_process(self) -> bool:
    try:
      if self.repository:
        repository: str = self.repository
      else:
        repository: str = self.get_default_repository_name(sensor_type='falcon-imageanalyzer')

      registry_type: str = self.check_registry_type(registry=self.registry)

      if registry_type == 'artifact':
        # Get the access token for the target Google Artifact Registry
        access_token = self.get_access_token(repository=repository, location=self.location,
                                             service_account=self.service_account)
        if not access_token:
          self.logger.error("Failed to retrieve access token for the Google Artifact Registry.")
          return False
      else:
        access_token = None

      registry: str = self.get_image_registry(registry=self.registry,
                                              registry_type=registry_type,
                                              sensor_type='falcon-imageanalyzer')

      image_tag = self.get_image_tag(registry=registry,
                                     registry_type=registry_type,
                                     repository=repository,
                                     image_tag=self.iar_image_tag,
                                     location=self.location,
                                     project=self.project_id,
                                     access_token=access_token,
                                     sensor_type='falcon-imageanalyzer')
      if image_tag is None:
        self.logger.error('No image tag found.')
        return False

      pull_token = self.get_image_pull_token(registry=registry, access_token=access_token)

      if pull_token is None:
        self.logger.error('No image pull token found.')
        return False

      self.run_command("helm repo add crowdstrike https://crowdstrike.github.io/falcon-helm")
      self.run_command("helm repo update")
      self.run_command("kubectl create namespace falcon-image-analyzer")
      self.run_command("kubectl label --overwrite ns falcon-image-analyzer "
                       "pod-security.kubernetes.io/enforce=privileged")

      output = self.run_command("kubectl config view --minify --output jsonpath={..cluster}")

      random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
      cluster_name = f"random_{random_string}_cluster"

      if output:
        for x in output.split(' '):
          if 'certificate-authority-data' not in x:
            cluster_name = x

      iar_helm_chart = f"""helm upgrade --install image-analyzer crowdstrike/falcon-image-analyzer \
                          -n falcon-image-analyzer --create-namespace \
                          --set deployment.enabled=true \
                          --set crowdstrikeConfig.cid="{self.falcon_cid}" \
                          --set crowdstrikeConfig.clusterName="{cluster_name}" \
                          --set crowdstrikeConfig.clientID={self.falcon_client_id} \
                          --set crowdstrikeConfig.clientSecret={self.falcon_client_secret} \
                          --set image.registryConfigJSON={pull_token} \
                          --set crowdstrikeConfig.agentRegion={self.falcon_region} \
                          --set image.tag="{image_tag}" """

      if registry_type == 'crwd':
        iar_helm_chart += f' --set image.repository={registry}'
      elif registry_type == 'artifact':
        iar_helm_chart += f' --set image.repository={registry}/{self.project_id}/{repository}/{image_tag.lower()}'

      self.run_command(iar_helm_chart)

      return True
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return False

  def deploy_falcon_iar(self):
    print(f"\n{'+' * 40}\nCrowdStrike Image Assessment at Runtime\n{'+' * 40}\n")

    print('Installing IAR...')

    k8s = KubectlOps(logger=self.logger)

    if k8s.namespace_exists(namespace_name='falcon-image-analyzer'):
      captured_pods, status = k8s.find_pods_with_status(pod_string='image-analyzer', namespace='falcon-image-analyzer')

      if (status is True) and (len(captured_pods['running']) > 0):
        print('Falcon Image Analyzer found up and running in falcon-image-analyzer namespace. Skipping installation...')

        for pod in captured_pods['running']:
          print(pod)

        print(' ')
        return

    with MultiThreading() as mt:
      status = mt.run_with_progress_indicator(self.execute_iar_installation_process, 1)

    if status:
      print('IAR installation successful\n')

      container = ContainerOps(logger=self.logger)
      container.pod_checker(pod_name='image-analyzer', namespace='falcon-image-analyzer',
                            kubeconfig_path='~/.kube/config')
    else:
      print('IAR installation failed\n')
