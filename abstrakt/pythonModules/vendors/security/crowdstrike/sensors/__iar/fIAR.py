import random
import string
import inspect

from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading
# from abstrakt.pythonModules.vendors.security.crowdstrike.crowdstrike import CrowdStrike
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.__crowdStrikeSensors import CrowdStrikeSensors


class IAR(CrowdStrikeSensors):
  def __init__(self, falcon_client_id, falcon_client_secret, logger, image_registry=None,
               iar_image_tag='latest', proxy_server=None, proxy_port=None, sensor_tags=None, cluster_name=None,
               cluster_type=None, iam_policy=None, sensor_iam_role=None, kac_iam_role=None,
               iar_iam_role=None):
    super().__init__(falcon_client_id, falcon_client_secret, logger, image_registry, proxy_server, proxy_port,
                     sensor_tags, cluster_name, iam_policy, sensor_iam_role, kac_iam_role, iar_iam_role)
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

      if registry_type == 'ecr_registry' and self.cluster_type == 'eks-fargate':
        ecr_region = iar_image_repo.split('.')[3]

        iam_role_arn = self.set_and_attach_policy_to_iam_role(
          ecr_region=ecr_region, namespace='falcon-image-analyzer',
          service_account='image-analyzer-falcon-image-analyzer')

        if iam_role_arn is not None:
          iar_helm_chart += f'--set serviceAccount.annotations."eks\\.amazonaws\\.com/role-arn"="{iam_role_arn}"'
        else:
          return False

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
