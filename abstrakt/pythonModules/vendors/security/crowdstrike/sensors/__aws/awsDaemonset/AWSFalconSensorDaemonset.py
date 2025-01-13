import random
import string
import inspect
import subprocess

from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.__aws.AWSFalconSensor import AWSFalconSensor


class AWSFalconSensorDaemonset(AWSFalconSensor):
  def __init__(self, falcon_client_id, falcon_client_secret, logger, image_registry=None,
               sensor_image_tag=None, proxy_server=None, proxy_port=None, sensor_tags=None, cluster_name=None,
               cluster_type=None, sensor_mode=None):
    super().__init__(falcon_client_id, falcon_client_secret, logger, image_registry, sensor_image_tag, proxy_server,
                     proxy_port, sensor_tags, cluster_name, cluster_type)

    self.sensor_mode = sensor_mode

  def get_helm_chart(self):
    registry_type, falcon_image_repo, falcon_image_tag, falcon_image_pull_token = self.get_repo_tag_token(
      sensor_type='_daemonset', image_tag=self.sensor_image_tag)

    if falcon_image_repo != 'None' and falcon_image_tag != 'None' and falcon_image_pull_token != 'None':
      helm_chart = [
        "helm", "upgrade", "--install", "_daemonset-falcon-sensor", "crowdstrike/falcon-sensor",
        "-n", "falcon-system", "--create-namespace",
        "--set", f"falcon.cid={self.falcon_cid}",
        "--set", f"node.image.repository={falcon_image_repo}",
        "--set", f"node.image.tag={falcon_image_tag}",
        "--set", f"node.image.registryConfigJSON={falcon_image_pull_token}",
        "--set", f'node.backend={self.sensor_mode}'
      ]

      if self.proxy_server and self.proxy_port:
        helm_chart.append("--set")
        helm_chart.append(f'falcon.apd=false')
        helm_chart.append("--set")
        helm_chart.append(f'falcon.aph=http://{self.proxy_server}')
        helm_chart.append("--set")
        helm_chart.append(f'falcon.app={self.proxy_port}')

      if self.sensor_tags:
        tags = '\\,'.join(self.sensor_tags.split(','))
        helm_chart.append("--set")
        helm_chart.append(f'falcon.tags="{tags}"')

      return helm_chart
    else:
      return False

  def aws_daemonset_falcon_sensor_thread(self):
    helm_chart = self.get_helm_chart()

    if helm_chart is not False:
      command = ' '.join(helm_chart)

      self.logger.info(f'Running command: {command}')
      output, error = self.run_command(command=command, output=True)

      self.logger.info(output)
      self.logger.error(error)
    else:
      return False

  def execute_helm_chart(self):
    try:
      with MultiThreading() as mt:
        mt.run_with_progress_indicator(self.aws_daemonset_falcon_sensor_thread, 1, 300)
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      return False
    else:
      return True

  def deploy_falcon_sensor_daemonset(self):
    """Deploys the CrowdStrike Falcon Sensor _daemonset on a Kubernetes cluster."""

    print(f"{'+' * 26}\nCrowdStrike Falcon Sensor\n{'+' * 26}\n")

    print("Installing Falcon Sensor...")

    k8s = KubectlOps(logger=self.logger)

    falcon_sensor_names = ['_daemonset-falcon-sensor', 'falcon-helm-falcon-sensor']

    for falcon_sensor in falcon_sensor_names:
      if k8s.namespace_exists(namespace_name='falcon-system'):
        captured_pods, status = k8s.find_pods_with_status(pod_string=falcon_sensor, namespace='falcon-system')

        if (status is True) and (len(captured_pods['running']) > 0):
          print('Falcon sensors found up and running in falcon-system namespace. Not proceeding with installation.')

          for pod in captured_pods['running']:
            print(pod)

          print(' ')
          return

    if self.execute_helm_chart():
      print("Falcon sensor installation successful\n")

      container = ContainerOps(logger=self.logger)
      container.pod_checker(pod_name='falcon-sensor', namespace='falcon-system', kubeconfig_path='~/.kube/config')
    else:
      print("Falcon sensor installation failed\n")


class AWSDaemonsetKAC(AWSFalconSensorDaemonset):
  def __init__(self, falcon_client_id, falcon_client_secret, logger, image_registry, cluster_name, cluster_type,
               kac_image_tag):
    super().__init__(falcon_client_id, falcon_client_secret, logger, image_registry, cluster_name, cluster_type)

    self.kac_image_tag = kac_image_tag

  def aws_daemonset_kac_thread(self):
    registry_type, kac_image_repo, kac_image_tag, kac_image_pull_token = self.get_repo_tag_token(
      sensor_type='falcon-kac', image_tag=self.kac_image_tag)

    # Install Helm repository and release
    command = 'helm repo add crowdstrike https://crowdstrike.github.io/falcon-helm'
    output, error = self.run_command(command=command, output=True)

    self.logger.info(output)
    self.logger.error(error)

    command = 'helm repo update'
    output, error = self.run_command(command=command, output=True)

    self.logger.info(output)
    self.logger.error(error)

    command = 'helm repo list'
    output, error = self.run_command(command=command, output=True)

    self.logger.info(output)
    self.logger.error(error)

    falcon_kac_repo = "crowdstrike/falcon-kac"

    kac_helm_chart = ["helm", "install", "falcon-kac", falcon_kac_repo, "-n", "falcon-kac", "--create-namespace",
                      "--set", f"falcon.cid={self.falcon_cid}",
                      "--set", f"image.repository={kac_image_repo}",
                      "--set", f"image.tag={kac_image_tag}",
                      "--set", f"image.registryConfigJSON={kac_image_pull_token}"]

    command = ' '.join(kac_helm_chart)

    output, error = self.run_command(command=command, output=True)

    self.logger.info(output)
    self.logger.error(error)

  def deploy_falcon_kac(self):
    print(f"\n{'+' * 44}\nCrowdStrike Kubernetes Admission Controller\n{'+' * 44}\n")

    print('Installing Kubernetes Admission Controller...')

    k8s = KubectlOps(logger=self.logger)

    if k8s.namespace_exists(namespace_name='falcon-kac'):
      captured_pods, status = k8s.find_pods_with_status(pod_string='falcon-kac', namespace='falcon-kac')

      if (status is True) and (len(captured_pods['running']) > 0):
        print('Kubernetes Admission Controller found up and running in falcon-kac namespace. Not proceeding with '
              'installation.')

        for pod in captured_pods['running']:
          print(pod)

        print(' ')
        return

    try:
      with MultiThreading() as mt:
        mt.run_with_progress_indicator(self.aws_daemonset_kac_thread, 1, 300)

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


class AWSDaemonsetIAR(AWSFalconSensorDaemonset):
  def __init__(self, falcon_client_id, falcon_client_secret, logger, image_registry=None,
               iar_image_tag='latest', proxy_server=None, proxy_port=None, sensor_tags=None, cluster_name=None,
               cluster_type=None, ecr_iam_policy=None, iar_iam_role=None):
    super().__init__(falcon_client_id, falcon_client_secret, logger, image_registry, proxy_server, proxy_port,
                     sensor_tags, cluster_name, ecr_iam_policy, iar_iam_role)

    self.iar_image_tag = iar_image_tag
    self.cluster_type = cluster_type

  def execute_iar_installation_process(self) -> bool:
    try:
      registry_type, iar_image_repo, iar_image_tag, iar_image_pull_token = self.get_repo_tag_token(
        sensor_type='falcon-iar', image_tag=self.iar_image_tag)

      self.run_command("helm repo add crowdstrike https://crowdstrike.github.io/falcon-helm")
      self.run_command("helm repo update")
      self.run_command("kubectl create namespace falcon-image-analyzer")
      self.run_command("kubectl label --overwrite ns falcon-image-analyzer "
                       "pod-security.kubernetes.io/enforce=privileged")

      output = self.run_command("kubectl config view --minify --output jsonpath={..cluster}", output=True)

      # Generate a random 4-character string including letters and digits
      random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
      cluster_name = f"random_{random_string}_cluster"

      # pattern = r"arn:aws:eks:[a-zA-Z0-9-]+:[0-9]{12}:cluster/[a-zA-Z0-9-]+"

      if output:
        for x in output[0].split(' '):
          if 'certificate-authority-data' not in x:
            cluster_name = x

      iar_helm_chart = f"""helm upgrade --install image-analyzer crowdstrike/falcon-image-analyzer \
                          -n falcon-image-analyzer --create-namespace \
                          --set deployment.enabled=true \
                          --set crowdstrikeConfig.cid="{self.falcon_cid}" \
                          --set crowdstrikeConfig.clusterName="{cluster_name}" \
                          --set crowdstrikeConfig.clientID={self.falcon_client_id} \
                          --set crowdstrikeConfig.clientSecret={self.falcon_client_secret} \
                          --set image.registryConfigJSON={iar_image_pull_token} \
                          --set crowdstrikeConfig.agentRegion={self.falcon_cloud_region} \
                          --set image.repository="{iar_image_repo}" \
                          --set image.tag="{iar_image_tag}" """

      output, error = self.run_command(iar_helm_chart, output=True)

      if output:
        self.logger.info(output)
      if error:
        self.logger.error(error)

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
        print('Falcon Image Analyzer found up and running in falcon-image-analyzer namespace. Not proceeding with '
              'installation.')

        for pod in captured_pods['running']:
          print(pod)

        print(' ')
        return

    with MultiThreading() as mt:
      status = mt.run_with_progress_indicator(self.execute_iar_installation_process, 1, 300)

    if status:
      print('IAR installation successful\n')

      container = ContainerOps(logger=self.logger)
      container.pod_checker(pod_name='image-analyzer', namespace='falcon-image-analyzer',
                            kubeconfig_path='~/.kube/config')
    else:
      print('IAR installation failed\n')
