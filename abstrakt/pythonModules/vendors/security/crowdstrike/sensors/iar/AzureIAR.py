import random
import string
import inspect

from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
# from abstrakt.pythonModules.multiThread.multithreading import MultiThreading
from abstrakt.pythonModules.multiProcess.multiProcessing import MultiProcessing
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.falconsensor.Azure import Azure


class AzureIAR(Azure):
  def __init__(self, falcon_client_id: str,
               falcon_client_secret: str,
               logger,
               registry: str,
               repository: str,
               rg_name: str,
               rg_location: str,
               acr_rg: str,
               iar_image_tag: str,
               sp_name: str,
               sp_pass: str):
    super().__init__(falcon_client_id,
                     falcon_client_secret,
                     logger,
                     registry,
                     repository,
                     rg_name,
                     rg_location,
                     acr_rg)
    self.iar_image_tag: str = iar_image_tag
    self.sp_name: str = sp_name
    self.sp_pass: str = sp_pass

  def execute_iar_installation_process(self, logger) -> bool:
    logger = logger or self.logger

    try:
      if self.repository:
        repository: str = self.repository
      else:
        repository: str = self.get_default_repository_name(sensor_type='falcon-imageanalyzer')

      registry_type: str = self.check_registry_type(registry=self.registry, logger=logger)

      registry: str = self.get_image_registry(registry=self.registry,
                                              registry_type=registry_type,
                                              sensor_type='falcon-imageanalyzer')

      if registry_type == 'acr':
        sp_name, sp_pass = self.get_service_principal_credentials(registry=registry,
                                                                  sp_name=self.sp_name,
                                                                  sp_pass=self.sp_pass,
                                                                  logger=logger)

        if sp_name is None or sp_pass is None:
          return False
      else:
        sp_name, sp_pass = None, None
        logger.info(f'None Service Principal Credentials {sp_name} {sp_pass}')

      image_tag = self.get_azure_image_tag(registry=registry,
                                           registry_type=registry_type,
                                           repository=repository,
                                           image_tag=self.iar_image_tag,
                                           acr_rg=self.acr_rg,
                                           sp_name=sp_name,
                                           sp_pass=sp_pass,
                                           sensor_type='falcon-imageanalyzer',
                                           logger=logger)
      if image_tag is None:
        logger.error('No image tag found.')
        return False

      pull_token = self.get_azure_image_pull_token(registry=registry,
                                                   registry_type=registry_type,
                                                   sp_name=sp_name,
                                                   sp_pass=sp_pass,
                                                   logger=logger)
      if pull_token is None:
        logger.error('No image pull token found.')
        return False

      self.run_command("helm repo add crowdstrike https://crowdstrike.github.io/falcon-helm", logger=logger)
      self.run_command("helm repo update", logger=logger)
      self.run_command("kubectl create namespace falcon-image-analyzer", logger=logger)
      self.run_command("kubectl label --overwrite ns falcon-image-analyzer "
                       "pod-security.kubernetes.io/enforce=privileged", logger=logger)

      output, error = self.run_command("kubectl config view --minify --output jsonpath={..cluster}", logger=logger)

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
      elif registry_type == 'acr':
        iar_helm_chart += f' --set image.repository={registry}/{repository}'

      self.run_command(iar_helm_chart, logger=logger)

      return True
    except Exception as e:
      logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      logger.error(f'{e}')
      return False

  def deploy_falcon_iar(self, logger=None):
    logger = logger or self.logger

    print(f"\n{'+' * 40}\nCrowdStrike Image Assessment at Runtime\n{'+' * 40}\n")

    print('Installing IAR...')

    k8s = KubectlOps(logger=logger)

    if k8s.namespace_exists(namespace_name='falcon-image-analyzer'):
      captured_pods, status = k8s.find_pods_with_status(pod_string='image-analyzer', namespace='falcon-image-analyzer')

      if (status is True) and (len(captured_pods['running']) > 0):
        print('Falcon Image Analyzer found up and running in falcon-image-analyzer namespace. Skipping installation...')

        for pod in captured_pods['running']:
          print(pod)

        print(' ')
        return

    with MultiProcessing() as mp:
      status = mp.execute_with_progress_indicator(self.execute_iar_installation_process, logger, 0.5, 900)
    # with MultiThreading() as mt:
    #   status = mt.run_with_progress_indicator(self.execute_iar_installation_process, 1, 300)

    if status:
      print('IAR installation successful\n')

      container = ContainerOps(logger=logger)
      container.pod_checker(pod_name='image-analyzer', namespace='falcon-image-analyzer',
                            kubeconfig_path='~/.kube/config', logger=logger)
    else:
      print('IAR installation failed\n')
