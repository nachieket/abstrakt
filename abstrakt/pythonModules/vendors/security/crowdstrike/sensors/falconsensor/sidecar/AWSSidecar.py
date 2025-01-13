import inspect

from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.customLogging.customLogging import CustomLogger
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.falconsensor.FalconSensorSidecar import FalconSensorSidecar
from abstrakt.pythonModules.vendors.security.crowdstrike.sensors.falconsensor.AWS import AWSSpecs


class AWSSidecar(AWSSpecs, FalconSensorSidecar):
  def __init__(self, falcon_client_id: str,
               falcon_client_secret: str,
               logger: CustomLogger,
               registry: str,
               repository: str,
               ecr_iam_policy: str,
               proxy_server: str,
               proxy_port: int,
               sensor_image_tag: str,
               sensor_tags: str,
               sensor_mode: str,
               monitor_namespaces: str,
               exclude_namespaces: str,
               ecr_sensor_iam_role: str,
               ecr_kac_iam_role: str,
               ecr_iar_iam_role: str,
               cluster_name: str
               ):
    super().__init__(falcon_client_id,
                     falcon_client_secret,
                     logger,
                     registry,
                     repository,
                     ecr_iam_policy)
    self.proxy_server: str = proxy_server
    self.proxy_port: int = proxy_port
    self.sensor_image_tag: str = sensor_image_tag
    self.sensor_tags: str = sensor_tags
    self.sensor_mode: str = sensor_mode
    self.monitor_namespaces: str = monitor_namespaces
    self.exclude_namespaces: str = exclude_namespaces
    self.ecr_sensor_iam_role: str = ecr_sensor_iam_role
    self.ecr_kac_iam_role: str = ecr_kac_iam_role
    self.ecr_iar_iam_role: str = ecr_iar_iam_role
    self.cluster_name = cluster_name

  def get_sidecar_image_registry(self, registry: str, registry_type: str, sensor_type: str) -> str | None:
    if registry:
      if registry_type == 'ecr':
        return f'{registry}'
      elif registry_type == 'crwd':
        return self.get_crowdstrike_registry(sensor_type=sensor_type)
      else:
        return None
    else:
      return self.get_crowdstrike_registry(sensor_type=sensor_type)

  def get_sidecar_image_tag(self, registry: str, registry_type: str, repository: str,
                            image_tag: str, sensor_type: str) -> str | None:
    if registry_type == 'crwd':
      if 'latest' in image_tag:
        return self.get_crowdstrike_sensor_image_tag(sensor_type=sensor_type, image_tag=image_tag)
      elif self.verify_crowdstrike_sensor_image_tag(image_tag=image_tag, sensor_type=sensor_type):
        return image_tag
      return None

    if registry_type == 'ecr' and self.check_ecr_registry_exists(registry=registry):
      if not self.check_ecr_repository_exists(registry=registry, repository=repository):
        self.create_ecr_repository(registry=registry, repository=repository, sensor_type=sensor_type)

      if 'latest' in image_tag:
        image_tag: str = self.get_crowdstrike_sensor_image_tag(sensor_type=sensor_type, image_tag=image_tag)
      elif not self.verify_crowdstrike_sensor_image_tag(image_tag=image_tag, sensor_type=sensor_type):
        return None

      if self.check_image_exists_on_ecr(registry=registry, repository=repository, image_tag=image_tag):
        return image_tag

      source_registry = self.get_crowdstrike_registry(sensor_type=sensor_type)
      if self.copy_crowdstrike_image_to_ecr(source_registry=source_registry, repository=repository,
                                            target_registry=registry, image_tag=image_tag):
        if self.check_image_exists_on_ecr(registry=registry, repository=repository, image_tag=image_tag):
          return image_tag

    return None

  def get_sidecar_image_pull_token(self, registry: str) -> str | None:
    registry_type: str = self.check_registry_type(registry=registry)

    if registry_type == 'crwd':
      return self.get_crowdstrike_image_pull_token()
    elif registry_type == 'ecr':
      return self.get_ecr_image_pull_token(registry=registry)
    else:
      return None

  def get_helm_chart(self, namespaces: list):
    if self.repository:
      repository: str = self.repository
    else:
      repository: str = self.get_default_repository_name(sensor_type='sidecar')

    registry_type: str = self.check_registry_type(registry=self.registry)

    registry: str = self.get_sidecar_image_registry(registry=self.registry,
                                                    registry_type=registry_type,
                                                    sensor_type='sidecar')

    image_tag: str = self.get_sidecar_image_tag(registry=registry,
                                                registry_type=registry_type,
                                                repository=repository,
                                                image_tag=self.sensor_image_tag,
                                                sensor_type='sidecar')

    pull_token: str = self.get_sidecar_image_pull_token(registry=registry)

    if registry and image_tag and pull_token:
      helm_chart = [
        "helm", "upgrade", "--install", "sidecar-falcon-sensor", "crowdstrike/falcon-sensor",
        "-n", "falcon-system", "--create-namespace",
        "--set", "node.enabled=false",
        "--set", "container.enabled=true",
        "--set", f"falcon.cid={self.falcon_cid}",
        "--set", f"container.image.tag={image_tag}",
        "--set", "container.image.pullSecrets.enable=true",
        "--set", f"container.image.pullSecrets.registryConfigJSON={pull_token}"
      ]

      if registry_type == 'crwd':
        helm_chart.append('--set')
        helm_chart.append(f'container.image.repository={registry}')
      elif registry_type == 'ecr':
        helm_chart.append('--set')
        helm_chart.append(f'container.image.repository={registry}/{repository}')

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

      if registry_type == 'ecr':
        region = registry.split('.')[3]

        iam_role_arn = self.set_and_attach_policy_to_iam_role(region=region,
                                                              namespace='falcon-system',
                                                              service_account='crowdstrike-falcon-sa',
                                                              iam_role=self.ecr_sensor_iam_role,
                                                              cluster_name=self.cluster_name)
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

  def execute_sidecar_falcon_sensor_thread(self):
    k8s = KubectlOps(logger=self.logger)
    namespaces_to_create = {
      'crowdstrike': ['falcon-system', 'falcon-kubernetes-protection', 'falcon-kac', 'falcon-image-analyzer'],
      'generic': ['crowdstrike-detections', 'ns1', 'ns2']
    }

    def create_namespaces(ns, label=None):
      try:
        for namespace in ns:
          if not k8s.namespace_exists(namespace_name=namespace):
            k8s.run_kubectl_command(f'kubectl create namespace {namespace}')
            if label:
              k8s.run_kubectl_command(f'kubectl label namespace {namespace} {label}')
          else:
            self.logger.info(f'{namespace} already exists.')
      except Exception as x:
        self.logger.error(f'Error in function {inspect.currentframe().f_code.co_name}')
        self.logger.error(f'{x}')

    # Create CrowdStrike namespaces with a label
    create_namespaces(ns=namespaces_to_create['crowdstrike'],
                      label='sensor.falcon-system.crowdstrike.com/injection=disabled')

    # Create generic namespaces without a label
    create_namespaces(ns=namespaces_to_create['generic'])

    # Filter and prepare the namespaces for Helm chart installation
    try:
      namespaces = k8s.get_all_namespaces('~/.kube/config')
      namespaces = [ns for ns in namespaces if 'kube-' not in ns and ns not in namespaces_to_create['crowdstrike']]

      helm_chart = self.get_helm_chart(namespaces=namespaces)

      if helm_chart:
        command = ' '.join(helm_chart)
        self.logger.info(f'Running command: {command}')
        self.run_command(command=command)
        return True
      else:
        self.logger.error('Helm chart not found.')
        return False
    except Exception as e:
      self.logger.error(f'Error in function {inspect.currentframe().f_code.co_name}')
      self.logger.error(f'{e}')
      return False

  def deploy_sidecar_falcon_sensor(self):
    print(f"{'+' * 26}\nCrowdStrike Falcon Sensor\n{'+' * 26}\n")

    print("Installing Falcon Sensor in Sidecar Mode...")

    # falcon_sensor_names = ['sidecar-falcon-sensor', 'falcon-sensor-injector', 'falcon-sensor']

    if self.check_falcon_sensor_installation(sensor_names=['sidecar-falcon-sensor', 'falcon-sensor-injector',
                                                           'falcon-sensor'],
                                             namespace='falcon-system',
                                             logger=self.logger):
      return

    if self.execute_helm_chart(self.execute_sidecar_falcon_sensor_thread, logger=self.logger):
      print("Falcon sensor installation successful\n")

      self.check_falcon_sensor_pods(pod_name='falcon-sensor', namespace='falcon-system', logger=self.logger)
    else:
      print("Falcon sensor installation failed\n")
