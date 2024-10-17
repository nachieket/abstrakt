import inspect
import subprocess

from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors._falconsensor._AWS import _AWS, _AWSSpecs


class _AWSDaemonsetKAC(_AWS):
  def __init__(self, falcon_client_id: str,
               falcon_client_secret: str,
               logger,
               registry: str,
               repository: str,
               cluster_name: str,
               cluster_type: str,
               kac_image_tag: str):
    super().__init__(falcon_client_id,
                     falcon_client_secret,
                     logger,
                     registry,
                     repository)
    self.cluster_name: str = cluster_name
    self.cluster_type: str = cluster_type
    self.kac_image_tag: str = kac_image_tag

  def aws_daemonset_kac_thread(self):
    if self.repository:
      repository: str = self.repository
    else:
      repository: str = self.get_default_repository_name(sensor_type='falcon-kac')

    registry_type: str = self.check_registry_type(registry=self.registry)

    registry: str = self.get_image_registry(registry=self.registry,
                                            registry_type=registry_type,
                                            sensor_type='falcon-kac')

    image_tag: str = self.get_image_tag(registry=registry,
                                        repository=repository,
                                        image_tag=self.kac_image_tag,
                                        sensor_type='falcon-kac')

    pull_token: str = self.get_image_pull_token(registry=registry)

    # Install Helm repository and release
    command = 'helm repo add crowdstrike https://crowdstrike.github.io/falcon-helm'
    self.run_command(command=command)

    command = 'helm repo update'
    self.run_command(command=command)

    command = 'helm repo list'
    self.run_command(command=command)

    falcon_kac_repo = "crowdstrike/falcon-kac"

    kac_helm_chart = ["helm", "install", "falcon-kac", falcon_kac_repo, "-n", "falcon-kac", "--create-namespace",
                      "--set", f"falcon.cid={self.falcon_cid}",
                      "--set", f"image.tag={image_tag}",
                      "--set", f"image.registryConfigJSON={pull_token}"]

    if registry_type == 'crwd':
      kac_helm_chart.append('--set')
      kac_helm_chart.append(f'image.repository={registry}')
    elif registry_type == 'ecr':
      kac_helm_chart.append('--set')
      kac_helm_chart.append(f'image.repository={registry}/{repository}')

    command = ' '.join(kac_helm_chart)

    self.run_command(command=command)

  def deploy_falcon_kac(self):
    print(f"\n{'+' * 44}\nCrowdStrike Kubernetes Admission Controller\n{'+' * 44}\n")

    print('Installing Kubernetes Admission Controller...')

    k8s = KubectlOps(logger=self.logger)

    if k8s.namespace_exists(namespace_name='falcon-kac'):
      captured_pods, status = k8s.find_pods_with_status(pod_string='falcon-kac', namespace='falcon-kac')

      if (status is True) and (len(captured_pods['running']) > 0):
        print('Kubernetes Admission Controller found up and running in falcon-kac namespace. Skipping installation...')

        for pod in captured_pods['running']:
          print(pod)

        print(' ')
        return

    try:
      with MultiThreading() as mt:
        mt.run_with_progress_indicator(self.aws_daemonset_kac_thread, 1)

      print('Kubernetes admission controller installed successfully.\n')

      container = ContainerOps(logger=self.logger)
      container.pod_checker(pod_name='falcon-kac', namespace='falcon-kac', kubeconfig_path='~/.kube/config')
    except subprocess.CalledProcessError as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      self.logger.error(f"Command output: {e.stdout}")
      self.logger.error(f"Command error: {e.stderr}")
      self.logger.error(f'Kubernetes admission controller installation failed\n')
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      self.logger.error(f'Kubernetes admission controller installation failed\n')


class _AWSSidecarKAC(_AWSSpecs):
  def __init__(self, falcon_client_id: str,
               falcon_client_secret: str,
               logger,
               registry: str,
               repository: str,
               iam_policy: str,
               cluster_name: str,
               cluster_type: str,
               kac_image_tag: str,
               kac_iam_role: str
               ):
    super().__init__(falcon_client_id,
                     falcon_client_secret,
                     logger,
                     registry,
                     repository,
                     iam_policy)

    self.cluster_name = cluster_name
    self.cluster_type = cluster_type
    self.kac_image_tag = kac_image_tag
    self.kac_iam_role = kac_iam_role

  def aws_sidecar_kac_thread(self):
    if self.repository:
      repository: str = self.repository
    else:
      repository: str = self.get_default_repository_name(sensor_type='falcon-kac')

    registry_type: str = self.check_registry_type(registry=self.registry)

    registry: str = self.get_image_registry(registry=self.registry,
                                            registry_type=registry_type,
                                            sensor_type='falcon-kac')

    image_tag: str = self.get_image_tag(registry=registry,
                                        repository=repository,
                                        image_tag=self.kac_image_tag,
                                        sensor_type='falcon-kac')

    pull_token: str = self.get_image_pull_token(registry=registry)

    # Install Helm repository and release
    command = 'helm repo add crowdstrike https://crowdstrike.github.io/falcon-helm'
    self.run_command(command=command)

    command = 'helm repo update'
    self.run_command(command=command)

    command = 'helm repo list'
    self.run_command(command=command)

    falcon_kac_repo = "crowdstrike/falcon-kac"

    kac_helm_chart = ["helm", "install", "falcon-kac", falcon_kac_repo, "-n", "falcon-kac", "--create-namespace",
                      "--set", f"falcon.cid={self.falcon_cid}",
                      "--set", f"image.tag={image_tag}",
                      "--set", f"image.registryConfigJSON={pull_token}"]

    if registry_type == 'crwd':
      kac_helm_chart.append('--set')
      kac_helm_chart.append(f'image.repository={registry}')
    elif registry_type == 'ecr':
      kac_helm_chart.append('--set')
      kac_helm_chart.append(f'image.repository={registry}/{repository}')

    if registry_type == 'ecr_registry' and self.cluster_type == 'eks-fargate':
      region = registry.split('.')[3]

      iam_role_arn = self.set_and_attach_policy_to_iam_role(region=region,
                                                            namespace='falcon-kac',
                                                            service_account='falcon-kac-sa',
                                                            iam_role=self.kac_iam_role,
                                                            cluster_name=self.cluster_name)

      if iam_role_arn is not None:
        kac_helm_chart.append("--set")
        kac_helm_chart.append(f'serviceAccount.annotations."eks\\.amazonaws\\.com/role-arn"="{iam_role_arn}"')
      else:
        return False

    command = ' '.join(kac_helm_chart)

    self.run_command(command=command)

  def deploy_falcon_kac(self):
    print(f"\n{'+' * 44}\nCrowdStrike Kubernetes Admission Controller\n{'+' * 44}\n")

    print('Installing Kubernetes Admission Controller...')

    k8s = KubectlOps(logger=self.logger)

    if k8s.namespace_exists(namespace_name='falcon-kac'):
      captured_pods, status = k8s.find_pods_with_status(pod_string='falcon-kac', namespace='falcon-kac')

      if (status is True) and (len(captured_pods['running']) > 0):
        print('Kubernetes Admission Controller found up and running in falcon-kac namespace. Skipping installation...')

        for pod in captured_pods['running']:
          print(pod)

        print(' ')
        return

    try:
      with MultiThreading() as mt:
        mt.run_with_progress_indicator(self.aws_sidecar_kac_thread, 1)

      print('Kubernetes admission controller installed successfully.\n')

      container = ContainerOps(logger=self.logger)
      container.pod_checker(pod_name='falcon-kac', namespace='falcon-kac', kubeconfig_path='~/.kube/config')
    except subprocess.CalledProcessError as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      self.logger.error(f"Command output: {e.stdout}")
      self.logger.error(f"Command error: {e.stderr}")
      self.logger.error(f'Kubernetes admission controller installation failed\n')
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
