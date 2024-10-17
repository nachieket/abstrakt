import json
import boto3
import inspect
import subprocess

from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.CrowdStrikeSensors import CrowdStrikeSensors
from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf
from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading


class FalconSensorDaemonset(CrowdStrikeSensors):
  def __init__(self, falcon_client_id, falcon_client_secret, sensor_mode, logger, image_registry=None,
               sensor_image_tag=None, proxy_server=None, proxy_port=None, sensor_tags=None, cluster_name=None,
               cluster_type=None, iam_policy=None):
    super().__init__(falcon_client_id, falcon_client_secret, logger, image_registry, proxy_server, proxy_port,
                     sensor_tags, cluster_name, iam_policy)

    self.sensor_mode = sensor_mode
    self.sensor_image_tag = sensor_image_tag
    self.cluster_name = cluster_name
    self.cluster_type = cluster_type

#   def get_aws_account_id(self) -> str | None:
#     output, error = self.run_command(command='aws sts get-caller-identity --query "Account" --output text',
#                                      output=True)
#
#     if output is not None:
#       return output.strip()
#     else:
#       return None
#
#   def get_cluster_oidc_issuer(self, region) -> str | None:
#     cluster_name = self.cluster_name
#
#     command = (f'aws eks describe-cluster --name {cluster_name} --region {region} --query '
#                '"cluster.identity.oidc.issuer" --output text')
#
#     output, error = self.run_command(command=command, output=True)
#
#     if output is not None:
#       return output.split('/')[-1].rstrip()
#     else:
#       return None
#
#   def check_aws_iam_policy(self, policy_name) -> str | None:
#     iam = boto3.client('iam')
#
#     try:
#       # List policies with the given name
#       response = iam.list_policies(Scope='Local')
#
#       # Check if the policy exists in the list of policies
#       for policy in response['Policies']:
#         if policy['PolicyName'] == policy_name:
#           self.logger.info(f"IAM policy '{policy_name}' exists with ARN: {policy['Arn']}")
#           return policy['Arn']
#
#       self.logger.info(f"IAM policy '{policy_name}' does not exist.")
#       return None
#     except Exception as e:
#       self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
#       self.logger.error(f'{e}')
#       return None
#
#   def create_and_get_eks_fargate_permissions_policy(self, ecr_region, permission_policy_name) -> str | None:
#     policy_arn: str = self.check_aws_iam_policy(policy_name=permission_policy_name)
#     permissions_policy_file_path: str = './abstrakt/conf/aws/eks/policies/eks-fargate-permission-policy.json'
#
#     if policy_arn is not None:
#       return policy_arn
#     else:
#       permission_policy_file = Path(permissions_policy_file_path)
#
#       create_policy_command = (
#         f'aws iam create-policy --region "{ecr_region}" --policy-name {permission_policy_name} '
#         f'--policy-document file://{permission_policy_file} --description "Policy to enable '
#         f'Falcon Sensors to pull container image from ECR"')
#
#       output, error = self.run_command(command=create_policy_command, output=True)
#
#       if output is not None:
#         output = json.loads(output)
#
#         return output['Policy']['Arn']
#       else:
#         return None
#
#   def create_eks_fargate_trust_policy_json_file(self, account_id, region, oidc_issuer, namespace,
#                                                 service_account) -> str | None:
#     trust_policy = f"""{{
#   "Version": "2012-10-17",
#   "Statement": [
#     {{
#       "Effect": "Allow",
#       "Principal": {{
#         "Federated": "arn:aws:iam::{account_id}:oidc-provider/oidc.eks.{region}.amazonaws.com/id/{oidc_issuer}"
#       }},
#       "Action": "sts:AssumeRoleWithWebIdentity",
#       "Condition": {{
#         "StringEquals": {{
#           "oidc.eks.{region}.amazonaws.com/id/{oidc_issuer}:aud": "sts.amazonaws.com",
#           "oidc.eks.{region}.amazonaws.com/id/{oidc_issuer}:sub": "system:serviceaccount:{namespace}:{service_account}"
#         }}
#       }}
#     }}
#   ]
# }}
# """
#
#     if service_account == 'crowdstrike-falcon-sa':
#       file_name = './abstrakt/conf/aws/eks/policies/sensor-eks-fargate-trust-policy.json'
#     elif service_account == 'falcon-kac-sa':
#       file_name = './abstrakt/conf/aws/eks/policies/kac-eks-fargate-trust-policy.json'
#     elif service_account == 'image-analyzer-falcon-image-analyzer':
#       file_name = './abstrakt/conf/aws/eks/policies/iar-eks-fargate-trust-policy.json'
#     else:
#       return None
#
#     try:
#       with open(file_name, 'w') as file:
#         file.write(trust_policy)
#       return file_name
#     except Exception as e:
#       self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
#       self.logger.error(f'{e}')
#       return None
#
#   def check_aws_iam_role(self, role_name) -> str | None:
#     iam = boto3.client('iam')
#
#     try:
#       # Get the role
#       response = iam.get_role(RoleName=role_name)
#
#       # If the role exists, return the ARN
#       role_arn = response['Role']['Arn']
#       self.logger.info(f"IAM role '{role_name}' exists with ARN: {role_arn}")
#       return role_arn
#     except ClientError as e:
#       # Check if the error is because the role does not exist
#       if e.response['Error']['Code'] == 'NoSuchEntity':
#         self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
#         self.logger.info(f"IAM role '{role_name}' does not exist.")
#         self.logger.error(f'{e}')
#         return None
#       else:
#         self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
#         self.logger.error(f'{e}')
#         return None
#     except Exception as e:
#       self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
#       self.logger.error(f'{e}')
#       return None
#
#   def create_and_get_eks_fargate_role(self, account_id, region, oidc_issuer, role_name,
#                                       namespace, service_account) -> str | None:
#     file_name = self.create_eks_fargate_trust_policy_json_file(account_id=account_id,
#                                                                region=region,
#                                                                oidc_issuer=oidc_issuer,
#                                                                namespace=namespace,
#                                                                service_account=service_account)
#
#     if file_name is None:
#       return None
#
#     iam_role_arn = self.check_aws_iam_role(role_name)
#
#     if iam_role_arn is None:
#       command = f'aws iam create-role --role-name {role_name} --assume-role-policy-document file://{file_name}'
#
#       output, error = self.run_command(command=command, output=True)
#
#       if output is not None:
#         output = json.loads(output)
#         return output['Role']['Arn']
#
#       return None
#     else:
#       return iam_role_arn
#
#   def attach_policy_to_iam_role(self, policy_arn, iam_role_arn):
#     role_name = iam_role_arn.split('role/')[-1]
#     command = f'aws iam attach-role-policy --role-name {role_name} --policy-arn {policy_arn} --output json'
#
#     try:
#       result = subprocess.run(command, shell=True, check=True, text=True, stdout=subprocess.PIPE,
#                               stderr=subprocess.PIPE)
#
#       if result.returncode == 0:
#         return True
#     except Exception as e:
#       self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
#       self.logger.error(f'{e}')
#       return False
#
#   def set_and_attach_policy_to_iam_role(self, ecr_region, namespace, service_account) -> str | None:
#     permission_policy_arn: str
#     account_id: str
#     oidc_issuer: str
#     iam_role_arn: str
#
#     permission_policy_arn = self.create_and_get_eks_fargate_permissions_policy(
#       ecr_region=ecr_region, permission_policy_name=self.iam_policy)
#
#     if permission_policy_arn is None:
#       return None
#
#     account_id = self.get_aws_account_id()
#
#     if account_id is None:
#       return None
#
#     oidc_issuer = self.get_cluster_oidc_issuer(region=ecr_region)
#
#     if oidc_issuer is None:
#       return None
#
#     if service_account == 'crowdstrike-falcon-sa':
#       role_name = self.sensor_iam_role
#     elif service_account == 'falcon-kac-sa':
#       role_name = self.kac_iam_role
#     elif service_account == 'image-analyzer-falcon-image-analyzer':
#       role_name = self.iar_iam_role
#     else:
#       return None
#
#     iam_role_arn = self.create_and_get_eks_fargate_role(account_id=account_id,
#                                                         region=ecr_region,
#                                                         oidc_issuer=oidc_issuer,
#                                                         role_name=role_name,
#                                                         namespace=namespace,
#                                                         service_account=service_account)
#
#     if iam_role_arn is None:
#       return None
#
#     if self.attach_policy_to_iam_role(policy_arn=permission_policy_arn, iam_role_arn=iam_role_arn):
#       return iam_role_arn
#     else:
#       return None

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

      if self.cluster_type == 'gke-autopilot':
        helm_chart.append('--set')
        helm_chart.append('node.gke.autopilot=true')

      if self.proxy_server and self.proxy_port:
        helm_chart.append("--set")
        helm_chart.append(f'falcon.apd=false')
        helm_chart.append("--set")
        helm_chart.append(f'falcon.aph=http://{self.proxy_server}')
        helm_chart.append("--set")
        helm_chart.append(f'falcon.app={self.proxy_port}')

      if self.sensor_tags:
        # tags = '\\,'.join(self.tags.strip('"').split(','))
        tags = '\\,'.join(self.sensor_tags.split(','))
        helm_chart.append("--set")
        helm_chart.append(f'falcon.tags="{tags}"')

      return helm_chart
    else:
      return False

  def execute_helm_chart(self):
    try:
      def thread():
        helm_chart = self.get_helm_chart()

        if helm_chart is not False:
          command = ' '.join(helm_chart)

          self.logger.info(f'Running command: {command}')
          output, error = self.run_command(command=command, output=True)

          self.logger.info(output)
          self.logger.error(error)
        else:
          return False

      with MultiThreading() as mt:
        mt.run_with_progress_indicator(thread, 1)
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_back.f_code.co_name}')
      self.logger.error(f'Error: {e}')
      return False
    else:
      return True

  def deploy_falcon_sensor_daemonset(self):
    """Deploys the CrowdStrike Falcon Sensor _daemonset on a Kubernetes cluster."""

    printf(f"{'+' * 26}\nCrowdStrike Falcon Sensor\n{'+' * 26}\n", logger=self.logger)

    printf("Installing Falcon Sensor...", logger=self.logger)

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
      printf("Falcon sensor installation successful\n", logger=self.logger)

      container = ContainerOps(logger=self.logger)
      container.pod_checker(pod_name='falcon-sensor', namespace='falcon-system', kubeconfig_path='~/.kube/config')
    else:
      printf("Falcon sensor installation failed\n", logger=self.logger)
