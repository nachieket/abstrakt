# import json
# import os
# import subprocess
# import boto3
#
# from pathlib import Path
# from botocore.exceptions import ClientError
import inspect

from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.CrowdStrikeSensors import CrowdStrikeSensors
from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf
from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading


class FalconSensorSidecar(CrowdStrikeSensors):
  def __init__(self, falcon_client_id, falcon_client_secret, sensor_mode, logger, image_registry=None,
               falcon_sensor_image_tag=None, proxy_server=None, proxy_port=None, sensor_tags=None, cluster_name=None,
               monitor_namespaces=None, exclude_namespaces=None, iam_policy=None, sensor_iam_role=None,
               kac_iam_role=None, iar_iam_role=None):
    super().__init__(falcon_client_id, falcon_client_secret, logger, image_registry, proxy_server, proxy_port,
                     sensor_tags, cluster_name, iam_policy, sensor_iam_role, kac_iam_role, iar_iam_role)

    self.sensor_mode = sensor_mode
    self.falcon_sensor_image_tag = falcon_sensor_image_tag
    self.monitor_namespaces = monitor_namespaces
    self.exclude_namespaces = exclude_namespaces

  def get_helm_chart(self, namespaces=None):
    self.get_falcon_art_password()
    self.get_falcon_art_username()

    registry_type, falcon_image_repo, falcon_image_tag, falcon_image_pull_token = self.get_repo_tag_token(
      sensor_type='_sidecar', image_tag=self.falcon_sensor_image_tag)

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
        printf("Falcon sensor installation successful\n", logger=self.logger)
        container = ContainerOps(logger=self.logger)
        container.pod_checker(pod_name='falcon-sensor', namespace='falcon-system', kubeconfig_path='~/.kube/config')
      else:
        printf("Falcon sensor installation failed\n", logger=self.logger)
