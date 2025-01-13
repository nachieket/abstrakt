import json
import random
import string
import inspect
import subprocess

from pathlib import Path

from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf
from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.__aws.AWSFalconSensor import AWSFalconSensor


class AWSFalconSensorSidecar(AWSFalconSensor):
  def __init__(self, falcon_client_id, falcon_client_secret, logger, image_registry=None,
               sensor_image_tag=None, proxy_server=None, proxy_port=None, sensor_tags=None, cluster_name=None,
               cluster_type=None, monitor_namespaces=None, exclude_namespaces=None, ecr_iam_policy=None,
               sensor_iam_role=None, kac_iam_role=None, iar_iam_role=None):
    super().__init__(falcon_client_id, falcon_client_secret, logger, image_registry, sensor_image_tag, proxy_server,
                     proxy_port, sensor_tags, cluster_name, cluster_type)

    self.sensor_image_tag = sensor_image_tag
    self.monitor_namespaces = monitor_namespaces
    self.exclude_namespaces = exclude_namespaces
    self.ecr_iam_policy = ecr_iam_policy
    self.sensor_iam_role = sensor_iam_role
    self.kac_iam_role = kac_iam_role
    self.iar_iam_role = iar_iam_role

  def create_and_get_eks_fargate_permissions_policy(self, ecr_region, permission_policy_name) -> str | None:
    policy_arn: str = self.check_aws_iam_policy(policy_name=permission_policy_name)
    permissions_policy_file_path: str = './abstrakt/conf/aws/eks/policies/eks-fargate-permission-policy.json'

    if policy_arn is not None:
      return policy_arn
    else:
      permission_policy_file = Path(permissions_policy_file_path)

      create_policy_command = (
        f'aws iam create-policy --region "{ecr_region}" --policy-name {permission_policy_name} '
        f'--policy-document file://{permission_policy_file} --description "Policy to enable '
        f'Falcon Sensors to pull container image from ECR"')

      output, error = self.run_command(command=create_policy_command, output=True)

      if output is not None:
        output = json.loads(output)

        return output['Policy']['Arn']
      else:
        return None

  def create_eks_fargate_trust_policy_json_file(self, account_id, region, oidc_issuer, namespace,
                                                service_account) -> str | None:
    trust_policy = f"""{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Effect": "Allow",
      "Principal": {{
        "Federated": "arn:aws:iam::{account_id}:oidc-provider/oidc.eks.{region}.amazonaws.com/id/{oidc_issuer}"
      }},
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {{
        "StringEquals": {{
          "oidc.eks.{region}.amazonaws.com/id/{oidc_issuer}:aud": "sts.amazonaws.com",
          "oidc.eks.{region}.amazonaws.com/id/{oidc_issuer}:sub": "system:serviceaccount:{namespace}:{service_account}"
        }}
      }}
    }}
  ]
}}
"""

    if service_account == 'crowdstrike-falcon-sa':
      file_name = './abstrakt/conf/aws/eks/policies/sensor-eks-fargate-trust-policy.json'
    elif service_account == 'falcon-kac-sa':
      file_name = './abstrakt/conf/aws/eks/policies/kac-eks-fargate-trust-policy.json'
    elif service_account == 'image-analyzer-falcon-image-analyzer':
      file_name = './abstrakt/conf/aws/eks/policies/iar-eks-fargate-trust-policy.json'
    else:
      return None

    try:
      with open(file_name, 'w') as file:
        file.write(trust_policy)
      return file_name
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'{e}')
      return None

  def create_and_get_eks_fargate_role(self, account_id, region, oidc_issuer, role_name,
                                      namespace, service_account) -> str | None:
    file_name = self.create_eks_fargate_trust_policy_json_file(account_id=account_id,
                                                               region=region,
                                                               oidc_issuer=oidc_issuer,
                                                               namespace=namespace,
                                                               service_account=service_account)

    if file_name is None:
      return None

    iam_role_arn = self.check_aws_iam_role(role_name)

    if iam_role_arn is None:
      command = f'aws iam create-role --role-name {role_name} --assume-role-policy-document file://{file_name}'

      output, error = self.run_command(command=command, output=True)

      if output is not None:
        output = json.loads(output)
        return output['Role']['Arn']

      return None
    else:
      return iam_role_arn

  def set_and_attach_policy_to_iam_role(self, ecr_region, namespace, service_account) -> str | None:
    permission_policy_arn: str
    account_id: str
    oidc_issuer: str
    iam_role_arn: str

    permission_policy_arn = self.create_and_get_eks_fargate_permissions_policy(
      ecr_region=ecr_region, permission_policy_name=self.ecr_iam_policy)

    if permission_policy_arn is None:
      return None

    account_id = self.get_aws_account_id()

    if account_id is None:
      return None

    oidc_issuer = self.get_cluster_oidc_issuer(region=ecr_region)

    if oidc_issuer is None:
      return None

    if service_account == 'crowdstrike-falcon-sa':
      role_name = self.sensor_iam_role
    elif service_account == 'falcon-kac-sa':
      role_name = self.kac_iam_role
    elif service_account == 'image-analyzer-falcon-image-analyzer':
      role_name = self.iar_iam_role
    else:
      return None

    iam_role_arn = self.create_and_get_eks_fargate_role(account_id=account_id,
                                                        region=ecr_region,
                                                        oidc_issuer=oidc_issuer,
                                                        role_name=role_name,
                                                        namespace=namespace,
                                                        service_account=service_account)

    if iam_role_arn is None:
      return None

    if self.attach_policy_to_iam_role(policy_arn=permission_policy_arn, iam_role_arn=iam_role_arn):
      return iam_role_arn
    else:
      return None

  def get_helm_chart(self, namespaces=None):
    self.get_falcon_art_password()
    self.get_falcon_art_username()

    registry_type, falcon_image_repo, falcon_image_tag, falcon_image_pull_token = self.get_repo_tag_token(
      sensor_type='_sidecar', image_tag=self.sensor_image_tag)

    if falcon_image_repo != 'None' and falcon_image_tag != 'None' and falcon_image_pull_token != 'None':
      helm_chart = [
        "helm", "upgrade", "--install", "_sidecar-falcon-sensor", "crowdstrike/falcon-sensor",
        "-n", "falcon-system", "--create-namespace",
        "--set", "node.enabled=false",
        "--set", "container.enabled=true",
        "--set", f"falcon.cid={self.falcon_cid}",
        "--set", f"container.image.repository={falcon_image_repo}",
        "--set", f"container.image.tag={falcon_image_tag}",
        "--set", "container.image.pullSecrets.enable=true",
        "--set", f"container.image.pullSecrets.registryConfigJSON={falcon_image_pull_token}"
      ]

      kube = KubectlOps(logger=self.logger)

      if self.monitor_namespaces.lower() == 'all' and self.exclude_namespaces:
        updated_namespaces = []
        for ns in namespaces:
          if ns in self.exclude_namespaces:
            kube.run_kubectl_command(
              f'kubectl label namespace {ns} sensor.falcon-system.crowdstrike.com/injection=disabled'
            )
          else:
            updated_namespaces.append(ns)
        temp = '\\,'.join(updated_namespaces)
        helm_chart.append("--set")
        helm_chart.append(f'container.image.pullSecrets.namespaces="{temp}"')
      elif self.monitor_namespaces.lower() == 'all':
        temp = '\\,'.join(namespaces)
        helm_chart.append("--set")
        helm_chart.append(f'container.image.pullSecrets.namespaces="{temp}"')
      elif self.monitor_namespaces.lower() != 'all' and not self.exclude_namespaces:
        if len(self.monitor_namespaces.split(',')) == 1:
          for ns in namespaces:
            if ns != self.monitor_namespaces:
              kube.run_kubectl_command(
                f'kubectl label namespace {ns} sensor.falcon-system.crowdstrike.com/injection=disabled'
              )
          helm_chart.append(f'container.image.pullSecrets.namespaces="default\\,{self.monitor_namespaces}"')
        else:
          for ns in namespaces:
            if ns not in self.monitor_namespaces:
              kube.run_kubectl_command(
                f'kubectl label namespace {ns} sensor.falcon-system.crowdstrike.com/injection=disabled'
              )
          temp = '\\,'.join(self.monitor_namespaces.split(','))
          helm_chart.append("--set")
          helm_chart.append(f'container.image.pullSecrets.namespaces="{temp}"')

      if self.proxy_server and self.proxy_port:
        helm_chart.append("--set")
        helm_chart.append(f'falcon.apd=false')
        helm_chart.append("--set")
        helm_chart.append(f'falcon.aph=http://{self.proxy_server}')
        helm_chart.append("--set")
        helm_chart.append(f'falcon.app={self.proxy_port}')

      if registry_type == 'ecr_registry':
        ecr_region = falcon_image_repo.split('.')[3]

        iam_role_arn = self.set_and_attach_policy_to_iam_role(ecr_region=ecr_region,
                                                              namespace='falcon-system',
                                                              service_account='crowdstrike-falcon-sa')
        if iam_role_arn is not None:
          helm_chart.append("--set")
          helm_chart.append(f'serviceAccount.annotations."eks\\.amazonaws\\.com/role-arn"="{iam_role_arn}"')
        else:
          return False

      if self.sensor_tags:
        tags = '\\,'.join(self.sensor_tags.split(','))
        helm_chart.append("--set")
        helm_chart.append(f'falcon.tags="{tags}"')

      return helm_chart
    else:
      return False

  def execute_helm_chart(self, namespaces=None):
    try:
      helm_chart = self.get_helm_chart(namespaces)

      if helm_chart is not False:
        command = ' '.join(helm_chart)

        self.logger.info(f'Running command: {command}')
        output, error = self.run_command(command=command, output=True)

        self.logger.info(output)
        self.logger.error(error)
      else:
        return False
    except Exception as e:
      printf(f"An error occurred: {e}\n", logger=self.logger)
      return False
    else:
      return True

  def deploy_falcon_sensor_sidecar(self):
    """Deploys the CrowdStrike Falcon Sensor _sidecar on a Kubernetes cluster."""

    k8s = KubectlOps(logger=self.logger)

    def thread():
      kube = KubectlOps(logger=self.logger)

      crowdstrike_namespaces = ['falcon-system', 'falcon-kubernetes-protection', 'falcon-kac', 'falcon-image-analyzer']

      try:
        for namespace in crowdstrike_namespaces:
          if not k8s.namespace_exists(namespace_name=namespace):
            kube.run_kubectl_command(f'kubectl create namespace {namespace}')
            kube.run_kubectl_command(
              f'kubectl label namespace {namespace} sensor.falcon-system.crowdstrike.com/injection=disabled'
            )
          else:
            self.logger.info(f'{namespace} already exists.')
      except Exception as e:
        self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
        self.logger.error(f'{e}')

      generic_namespaces = ['crowdstrike-detections', 'ns1', 'ns2']

      try:
        for namespace in generic_namespaces:
          if not k8s.namespace_exists(namespace_name=namespace):
            kube.run_kubectl_command(f'kubectl create namespace {namespace}')
          else:
            self.logger.info(f'{namespace} already exists.')
      except Exception as e:
        self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
        self.logger.error(f'{e}')

      namespaces: list = kube.get_all_namespaces('~/.kube/config')
      namespaces = [ns for ns in namespaces if 'kube-' not in ns]
      namespaces = [ns for ns in namespaces if ns not in crowdstrike_namespaces]

      if self.execute_helm_chart(namespaces):
        return True
      else:
        return False

    print(f"{'+' * 26}\nCrowdStrike Falcon Sensor\n{'+' * 26}\n")

    print("Installing Falcon Sensor...")

    falcon_sensor_names = ['_sidecar-falcon-sensor', 'falcon-sensor-injector']

    for falcon_sensor in falcon_sensor_names:
      if k8s.namespace_exists(namespace_name='falcon-system'):
        captured_pods, status = k8s.find_pods_with_status(pod_string=falcon_sensor, namespace='falcon-system')

        if (status is True) and (len(captured_pods['running']) > 0):
          print('Falcon sensors found up and running in falcon-system namespace. Not proceeding with installation.')

          for pod in captured_pods['running']:
            print(pod)

          print(' ')
          return

    with MultiThreading() as mt:
      if mt.run_with_progress_indicator(thread, 1, 300):
        print("Falcon sensor installation successful\n")
        container = ContainerOps(logger=self.logger)
        container.pod_checker(pod_name='falcon-sensor', namespace='falcon-system', kubeconfig_path='~/.kube/config')
      else:
        print("Falcon sensor installation failed\n")


class AWSSidecarKAC(AWSFalconSensorSidecar):
  def __init__(self, falcon_client_id, falcon_client_secret, logger, image_registry=None,
               sensor_image_tag=None, proxy_server=None, proxy_port=None, sensor_tags=None, cluster_name=None,
               cluster_type=None, monitor_namespaces=None, exclude_namespaces=None, ecr_iam_policy=None,
               sensor_iam_role=None, kac_iam_role=None, iar_iam_role=None, kac_image_tag=None):
    super().__init__(falcon_client_id, falcon_client_secret, logger, image_registry,
                     sensor_image_tag, proxy_server, proxy_port, sensor_tags, cluster_name,
                     cluster_type, monitor_namespaces, exclude_namespaces, ecr_iam_policy,
                     sensor_iam_role, kac_iam_role, iar_iam_role)

    self.kac_image_tag = kac_image_tag

  def aws_sidecar_kac_thread(self):
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

    if registry_type == 'ecr_registry' and self.cluster_type == 'eks-fargate':
      ecr_region = kac_image_repo.split('.')[3]

      iam_role_arn = self.set_and_attach_policy_to_iam_role(ecr_region=ecr_region,
                                                            namespace='falcon-kac',
                                                            service_account='falcon-kac-sa')

      if iam_role_arn is not None:
        kac_helm_chart.append("--set")
        kac_helm_chart.append(f'serviceAccount.annotations."eks\\.amazonaws\\.com/role-arn"="{iam_role_arn}"')
      else:
        return False

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
        mt.run_with_progress_indicator(self.aws_sidecar_kac_thread, 1, 300)

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


class AWSSidecarIAR(AWSFalconSensorSidecar):
  def __init__(self, falcon_client_id, falcon_client_secret, logger, image_registry=None,
               sensor_image_tag=None, proxy_server=None, proxy_port=None, sensor_tags=None, cluster_name=None,
               cluster_type=None, monitor_namespaces=None, exclude_namespaces=None, ecr_iam_policy=None,
               sensor_iam_role=None, kac_iam_role=None, iar_iam_role=None, iar_image_tag=None):
    super().__init__(falcon_client_id, falcon_client_secret, logger, image_registry,
                     sensor_image_tag, proxy_server, proxy_port, sensor_tags, cluster_name,
                     cluster_type, monitor_namespaces, exclude_namespaces, ecr_iam_policy,
                     sensor_iam_role, kac_iam_role, iar_iam_role)

    self.iar_image_tag = iar_image_tag

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
