import json
import os
import subprocess
import boto3

from pathlib import Path
from botocore.exceptions import ClientError

from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.crowdStrikeSensors import CrowdStrikeSensors
from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf
from abstrakt.pythonModules.kubernetesOps.updateKubeConfig import UpdateKubeConfig
from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading


class FalconSensorSidecar(CrowdStrikeSensors):
  def __init__(self, falcon_client_id, falcon_client_secret, sensor_mode, logger, falcon_image_repo=None,
               falcon_image_tag=None, proxy_server=None, proxy_port=None, tags=None, monitor_namespaces=None,
               exclude_namespaces=None, ecr_iam_policy_name=None, ecr_iam_role_name=None):
    super().__init__(falcon_client_id, falcon_client_secret, sensor_mode, logger, falcon_image_repo, falcon_image_tag,
                     proxy_server, proxy_port, tags)

    self.monitor_namespaces = monitor_namespaces
    self.exclude_namespaces = exclude_namespaces
    self.ecr_iam_policy_name = ecr_iam_policy_name
    self.ecr_iam_role_name = ecr_iam_role_name

  def get_aws_account_id(self):
    output, error = self.run_command(command='aws sts get-caller-identity --query "Account" --output text', output=True)

    if output is not None:
      return output.strip()
    else:
      return None

  def get_cluster_oidc_issuer(self, region):
    cluster_name = os.getenv('EKS_FARGATE_CLUSTER_NAME')

    command = (f'aws eks describe-cluster --name {cluster_name} --region {region} --query '
               '"cluster.identity.oidc.issuer" --output text')

    output, error = self.run_command(command=command, output=True)

    if output is not None:
      return output.split('/')[-1].rstrip()
    else:
      return None

  def check_aws_iam_policy(self, policy_name):
    iam = boto3.client('iam')

    try:
      # List policies with the given name
      response = iam.list_policies(Scope='Local')

      # Check if the policy exists in the list of policies
      for policy in response['Policies']:
        if policy['PolicyName'] == policy_name:
          self.logger.info(f"IAM policy '{policy_name}' exists with ARN: {policy['Arn']}")
          return policy['Arn']

      self.logger.info(f"IAM policy '{policy_name}' does not exist.")
      return None
    except ClientError as e:
      self.logger.error(f"An error occurred: {e}")
      return None

  def create_and_get_eks_fargate_permissions_policy(self, ecr_region, permission_policy_name):
    if policy_arn := self.check_aws_iam_policy(policy_name=permission_policy_name):
      return policy_arn
    else:
      permission_policy_file = Path('./abstrakt/conf/aws/eks/eks-fargate-permission-policy.json')

      create_policy_command = (f'aws iam create-policy --region "{ecr_region}" --policy-name {permission_policy_name} '
                               f'--policy-document file://{permission_policy_file} --description "Policy to enable '
                               f'Falcon Container Injector to pull container image from ECR"')

      output, error = self.run_command(command=create_policy_command, output=True)

      if output is not None:
        output = json.loads(output)

        return output['Policy']['Arn']
      else:
        return None

  def create_eks_fargate_trust_policy_json_file(self, account_id, region, oidc_issuer):
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
          "oidc.eks.{region}.amazonaws.com/id/{oidc_issuer}:sub": "system:serviceaccount:falcon-system:crowdstrike-falcon-sa"
        }}
      }}
    }}
  ]
}}
"""

    try:
      with open('./abstrakt/conf/aws/eks/eks-fargate-trust-policy.json', 'w') as file:
        file.write(trust_policy)
      return True
    except Exception as e:
      self.logger.error(f'Error: {e}')
      return False

  def check_aws_iam_role(self, role_name):
    iam = boto3.client('iam')

    try:
      # Get the role
      response = iam.get_role(RoleName=role_name)

      # If the role exists, return the ARN
      role_arn = response['Role']['Arn']
      self.logger.info(f"IAM role '{role_name}' exists with ARN: {role_arn}")
      return role_arn
    except ClientError as e:
      # Check if the error is because the role does not exist
      if e.response['Error']['Code'] == 'NoSuchEntity':
        self.logger.info(f"IAM role '{role_name}' does not exist.")
        return None
      else:
        self.logger.error(f"An error occurred: {e}")
        return None

  def create_and_get_eks_fargate_role(self, account_id, region, oidc_issuer, role_name):
    if self.create_eks_fargate_trust_policy_json_file(account_id=account_id, region=region, oidc_issuer=oidc_issuer):
      if iam_role_arn := self.check_aws_iam_role(role_name):
        return iam_role_arn
      else:
        command = (f'aws iam create-role --role-name {role_name} --assume-role-policy-document '
                   f'file://./abstrakt/conf/aws/eks/eks-fargate-trust-policy.json')

        output, error = self.run_command(command=command, output=True)

        if output is not None:
          output = json.loads(output)
          return output['Role']['Arn']

    return None

  def attach_policy_to_iam_role(self, policy_arn, iam_role_arn):
    role_name = iam_role_arn.split('role/')[-1]
    command = f'aws iam attach-role-policy --role-name {role_name} --policy-arn {policy_arn} --output json'

    try:
      result = subprocess.run(command, shell=True, check=True, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)

      if result.returncode == 0:
        return True
    except Exception as e:
      self.logger.error(f'Error: {e}')
      return False

  def get_helm_chart(self, namespaces=None):
    self.get_falcon_art_password()
    self.get_falcon_art_username()

    registry_type, falcon_image_repo, falcon_image_tag, falcon_image_pull_token = self.get_image_repo_tag_pull_token()

    iam_role_arn = None

    if registry_type == 'ecr_registry':
      ecr_region = falcon_image_repo.split('.')[3]

      permission_policy_arn = self.create_and_get_eks_fargate_permissions_policy(
        ecr_region=ecr_region, permission_policy_name=self.ecr_iam_policy_name)

      account_id = self.get_aws_account_id()
      oidc_issuer = self.get_cluster_oidc_issuer(region=ecr_region)

      iam_role_arn = self.create_and_get_eks_fargate_role(account_id=account_id, region=ecr_region,
                                                          oidc_issuer=oidc_issuer,
                                                          role_name=self.ecr_iam_role_name)

      if not self.attach_policy_to_iam_role(policy_arn=permission_policy_arn, iam_role_arn=iam_role_arn):
        return False

    if falcon_image_repo is not None and falcon_image_tag is not None and falcon_image_pull_token is not None:
      helm_chart = [
        "helm", "upgrade", "--install", "sidecar-falcon-sensor", "crowdstrike/falcon-sensor",
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

      if registry_type == 'ecr_registry' and iam_role_arn is not None:
        helm_chart.append("--set")
        helm_chart.append(f'serviceAccount.annotations."eks\\.amazonaws\\.com/role-arn"="{iam_role_arn}"')

      if self.tags:
        tags = '\\,'.join(self.tags.split(','))
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
    """Deploys the CrowdStrike Falcon Sensor sidecar on a Kubernetes cluster."""

    k8s = KubectlOps(logger=self.logger)

    def thread():
      # if region and cluster_name:
      #   kube = UpdateKubeConfig(logger=self.logger)
      #   kube.update_kubeconfig(cloud='aws', region=region, cluster_name=cluster_name)
      # elif cluster_name and resource_group:
      #   kube = UpdateKubeConfig(logger=self.logger)
      #   kube.update_kubeconfig(cloud='azure', cluster_name=cluster_name, resource_group=resource_group)
      # elif cloud_provider == 'gcp':
      #   pass

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
        self.logger.error(f'{e}')

      generic_namespaces = ['crowdstrike-detections', 'ns1', 'ns2']

      try:
        for namespace in generic_namespaces:
          if not k8s.namespace_exists(namespace_name=namespace):
            kube.run_kubectl_command(f'kubectl create namespace {namespace}')
          else:
            self.logger.info(f'{namespace} already exists.')
      except Exception as e:
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

    falcon_sensor_names = ['sidecar-falcon-sensor', 'falcon-sensor-injector']

    for falcon_sensor in falcon_sensor_names:
      if k8s.namespace_exists(namespace_name='falcon-system'):
        captured_pods, status = k8s.find_pods_with_status(pod_string=falcon_sensor, namespace='falcon-system')

        if (status is True) and (len(captured_pods['running']) > 0):
          print('Falcon sensors found up and running in falcon-system namespace. Not proceeding with installation.')

          for pod in captured_pods['running']:
            print(pod)

          print()
          return

    with MultiThreading() as mt:
      if mt.run_with_progress_indicator(thread, 1):
        printf("Falcon sensor installation successful\n", logger=self.logger)
        container = ContainerOps(logger=self.logger)
        container.pod_checker(pod_name='falcon-sensor', namespace='falcon-system', kubeconfig_path='~/.kube/config')
      else:
        printf("Falcon sensor installation failed\n", logger=self.logger)
