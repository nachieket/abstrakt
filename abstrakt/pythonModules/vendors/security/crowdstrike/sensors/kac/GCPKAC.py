import inspect
import subprocess

from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
# from abstrakt.pythonModules.multiThread.multithreading import MultiThreading
from abstrakt.pythonModules.multiProcess.multiProcessing import MultiProcessing
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.falconsensor.GCP import GCP


class GCPKAC(GCP):
  def __init__(self, falcon_client_id: str,
               falcon_client_secret: str,
               logger,
               registry: str,
               repository: str,
               project_id: str,
               service_account: str,
               location: str,
               kac_image_tag: str,
               sensor_tags: str,):
    super().__init__(falcon_client_id,
                     falcon_client_secret,
                     logger,
                     registry,
                     repository,
                     project_id,
                     service_account,
                     location)

    self.kac_image_tag: str = kac_image_tag
    self.sensor_tags: str = sensor_tags

  def aws_daemonset_kac_thread(self, logger=None):
    logger = logger or self.logger

    if self.repository:
      repository: str = self.repository
    else:
      repository: str = self.get_default_repository_name(sensor_type='falcon-kac')

    registry_type: str = self.check_registry_type(registry=self.registry, logger=logger)

    if registry_type == 'artifact':
      # Get the access token for the target Google Artifact Registry
      access_token = self.get_access_token(repository=repository, location=self.location,
                                           service_account=self.service_account, logger=logger)
      if not access_token:
        self.logger.error("Failed to retrieve access token for the Google Artifact Registry.")
        return None
    else:
      access_token = None

    registry: str = self.get_image_registry(registry=self.registry,
                                            registry_type=registry_type,
                                            sensor_type='falcon-kac')

    image_tag = self.get_image_tag(registry=registry,
                                   registry_type=registry_type,
                                   repository=repository,
                                   image_tag=self.kac_image_tag,
                                   location=self.location,
                                   project=self.project_id,
                                   access_token=access_token,
                                   sensor_type='falcon-kac',
                                   logger=logger)

    if image_tag is None:
      logger.error('No image tag found.')
      return False

    pull_token = self.get_image_pull_token(registry=registry, access_token=access_token, logger=logger)

    if pull_token is None:
      logger.error('No image pull token found.')
      return False

    # Install Helm repository and release
    command = 'helm repo add crowdstrike https://crowdstrike.github.io/falcon-helm'
    self.run_command(command=command, logger=logger)

    command = 'helm repo update'
    self.run_command(command=command, logger=logger)

    command = 'helm repo list'
    self.run_command(command=command, logger=logger)

    falcon_kac_repo = "crowdstrike/falcon-kac"

    kac_helm_chart = ["helm", "install", "falcon-kac", falcon_kac_repo, "-n", "falcon-kac", "--create-namespace",
                      "--set", f"falcon.cid={self.falcon_cid}",
                      "--set", f"image.tag={image_tag}",
                      "--set", f"image.registryConfigJSON={pull_token}"]

    if registry_type == 'crwd':
      kac_helm_chart.append('--set')
      kac_helm_chart.append(f'image.repository={registry}')
    elif registry_type == 'artifact':
      kac_helm_chart.append('--set')
      kac_helm_chart.append(f'image.repository={registry}/{self.project_id}/{repository}/{image_tag.lower()}')

    if self.sensor_tags:
      tags = '\\,'.join(self.sensor_tags.split(','))
      kac_helm_chart.append("--set")
      kac_helm_chart.append(f'falcon.tags="{tags}"')

    command = ' '.join(kac_helm_chart)

    self.run_command(command=command, logger=logger)

  def deploy_falcon_kac(self, logger=None):
    logger = logger or self.logger

    print(f"\n{'+' * 44}\nCrowdStrike Kubernetes Admission Controller\n{'+' * 44}\n")

    print('Installing Kubernetes Admission Controller...')

    k8s = KubectlOps(logger=logger)

    if k8s.namespace_exists(namespace_name='falcon-kac'):
      captured_pods, status = k8s.find_pods_with_status(pod_string='falcon-kac', namespace='falcon-kac')

      if (status is True) and (len(captured_pods['running']) > 0):
        print('Kubernetes Admission Controller found up and running in falcon-kac namespace. Skipping installation...')

        for pod in captured_pods['running']:
          print(pod)

        print(' ')
        return

    try:
      with MultiProcessing() as mp:
        mp.execute_with_progress_indicator(self.aws_daemonset_kac_thread, logger, 0.5, 900)
      # with MultiThreading() as mt:
      #   mt.run_with_progress_indicator(self.aws_daemonset_kac_thread, 1, 300)

      print('Kubernetes admission controller installed successfully.\n')

      container = ContainerOps(logger=logger)
      container.pod_checker(pod_name='falcon-kac', namespace='falcon-kac',
                            kubeconfig_path='~/.kube/config', logger=logger)
    except subprocess.CalledProcessError as e:
      logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      logger.error(f'{e}')
      logger.error(f"Command output: {e.stdout}")
      logger.error(f"Command error: {e.stderr}")
      logger.error(f'Kubernetes admission controller installation failed\n')
    except Exception as e:
      logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      logger.error(f'{e}')
      logger.error(f'Kubernetes admission controller installation failed\n')
