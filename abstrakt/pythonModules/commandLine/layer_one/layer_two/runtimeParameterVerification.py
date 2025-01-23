import os


class BasicRuntimeParameterVerification:
  def __init__(self, config_file: str, install_falcon_sensor: bool, registry: str, repository: str, proxy_server: str,
               proxy_port: int, install_kac: bool, install_iar: bool, install_kpa: bool, falcon_client_id: str,
               falcon_client_secret: str, install_detections_container: bool, install_vulnerable_apps: bool,
               generate_misconfigs: bool, logger):
    self.config_file = config_file
    self.install_falcon_sensor = install_falcon_sensor
    self.registry = registry
    self.repository = repository
    self.proxy_server = proxy_server
    self.proxy_port = proxy_port
    self.install_kac = install_kac
    self.install_iar = install_iar
    self.install_kpa = install_kpa
    self.falcon_client_id = falcon_client_id
    self.falcon_client_secret = falcon_client_secret
    self.install_detections_container = install_detections_container
    self.install_vulnerable_apps = install_vulnerable_apps
    self.generate_misconfigs = generate_misconfigs
    self.logger = logger

  def verify_generic_parameters(self):

    if self.config_file:
      if not os.path.exists(self.config_file):
        print(f"The file '{self.config_file}' does not exist. Exiting the program.\n")
        exit()

    if self.registry and not any([self.install_falcon_sensor, self.install_kac, self.install_iar]):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --install-falcon-sensor | --install-kac | --install-iar --registry <registry>')
      exit()

    if self.repository and not self.registry:
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --install-falcon-sensor | --install-kac | --install-iar --registry <registry> --repository '
            '<repository>')
      exit()

    if any([self.proxy_server, self.proxy_port]) and not all([self.proxy_server, self.proxy_port]):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --proxy-server <server> --proxy-port <port>')
      exit()

    if all([self.proxy_server, self.proxy_port]) and not self.install_falcon_sensor:
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --install-falcon-sensor --proxy-server <server> --proxy-port <port>')
      exit()

    if self.install_kpa and not all([self.falcon_client_id, self.falcon_client_secret]):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --install-kpa --falcon-client-id <id> --falcon-client-secret <secret>')
      exit()

    if self.install_kac and not all([self.falcon_client_id, self.falcon_client_secret]):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --install-kac --falcon-client-id <id> --falcon-client-secret <secret>')
      exit()

    if self.install_iar and not all([self.falcon_client_id, self.falcon_client_secret]):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --install-iar --falcon-client-id <id> --falcon-client-secret <secret>')
      exit()

    if (any([self.install_detections_container, self.install_vulnerable_apps, self.generate_misconfigs]) and not
            self.install_falcon_sensor):
      print('Warning: Installing detections container, vulnerable apps, or generating misconfigurations without '
            'falcon sensor will not generate detections or misconfigurations')


class AWSRuntimeParameterVerification(BasicRuntimeParameterVerification):
  def __init__(self, config_file: str, install_falcon_sensor: bool, registry: str, repository: str, proxy_server: str,
               proxy_port: int, install_kac: bool, install_iar: bool, install_kpa: bool, falcon_client_id: str,
               falcon_client_secret: str, install_detections_container: bool, install_vulnerable_apps: bool,
               generate_misconfigs: bool, logger, cluster_name: str, vpc_name: str, region: str, asset_tags: str,
               kernel_mode: bool = None, ebpf_mode: bool = None
               ):
    super().__init__(config_file, install_falcon_sensor, registry, repository, proxy_server, proxy_port, install_kac,
                     install_iar, install_kpa, falcon_client_id, falcon_client_secret, install_detections_container,
                     install_vulnerable_apps, generate_misconfigs, logger)

    self.cluster_name = cluster_name
    self.vpc_name = vpc_name
    self.region = region
    self.asset_tags = asset_tags
    self.kernel_mode = kernel_mode
    self.ebpf_mode = ebpf_mode

  def verify_generic_aws_cluster_parameters(self):
    if (any([self.cluster_name, self.vpc_name, self.region, self.asset_tags]) and
            not all([self.cluster_name, self.vpc_name, self.region])):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print("Usage: --cluster-name <name> --vpc-name <name> --region <region> --asset-tags <tags>")
      exit()

  def verify_eks_managed_node_runtime_parameters(self):
    self.verify_generic_parameters()

    self.verify_generic_aws_cluster_parameters()

    if self.install_falcon_sensor:
      if not all([self.falcon_client_id, self.falcon_client_secret]):
        print('Error: One or more runtime parameters are missing or are used in incorrect combination')
        print('Usage: --install-falcon-sensor --falcon-client-id --falcon-client-secret')
        exit()

  def verify_eks_fargate_runtime_parameters(self):
    self.verify_generic_parameters()

    self.verify_generic_aws_cluster_parameters()

    if self.install_falcon_sensor and not all([self.falcon_client_id, self.falcon_client_secret]):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --install-falcon-sensor --falcon-client-id --falcon-client-secret')
      exit()


class AzureRuntimeParameterVerification(BasicRuntimeParameterVerification):
  def __init__(self, config_file: str, install_falcon_sensor: bool, registry: str, repository: str, proxy_server: str,
               proxy_port: int, install_kac: bool, install_iar: bool, install_kpa: bool, falcon_client_id: str,
               falcon_client_secret: str, install_detections_container: bool, install_vulnerable_apps: bool,
               generate_misconfigs: bool, logger, cluster_name: str, resource_group: str, location: str,
               asset_tags: str, kernel_mode: bool, ebpf_mode: bool, acr_resource_group: str, sp_name: str, sp_pass: str
               ):
    super().__init__(config_file, install_falcon_sensor, registry, repository, proxy_server, proxy_port, install_kac,
                     install_iar, install_kpa, falcon_client_id, falcon_client_secret, install_detections_container,
                     install_vulnerable_apps, generate_misconfigs, logger)

    self.cluster_name = cluster_name
    self.resource_group = resource_group
    self.location = location
    self.asset_tags = asset_tags
    self.kernel_mode = kernel_mode
    self.ebpf_mode = ebpf_mode
    self.acr_resource_group = acr_resource_group
    self.sp_name = sp_name
    self.sp_pass = sp_pass

  def verify_aks_runtime_parameters(self):
    self.verify_generic_parameters()

    if (any([self.cluster_name, self.resource_group, self.location, self.asset_tags]) and
      not all([self.cluster_name, self.resource_group, self.location])):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print("Usage: --cluster-name <name> --resource-group <name> --location <location> and --asset-tags <tags>")
      exit()

    if any([self.acr_resource_group]) and not all([self.acr_resource_group, self.sp_name]):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --acr-resource-group <name> --acr-sub-id <id> --sp-name <name>')
      exit()

    if any([self.acr_resource_group]) and not any([self.install_falcon_sensor, self.install_kac, self.install_iar]):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage:  --install-falcon-sensor | --install-kac | --install-iar --acr-resource-group <name> '
            '--acr-sub-id <id>')
      exit()

    if any([self.sp_name, self.sp_pass]) and not any([self.install_falcon_sensor, self.install_kac, self.install_iar]):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage:  --install-falcon-sensor | --install-kac | --install-iar --sp-name <name> --sp-pass <password>')
      exit()

    if any([self.sp_name, self.sp_pass]) and not any([self.acr_resource_group]):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage:  --acr-resource-group <name> --acr-sub-id <id> --sp-name <name> --sp-pass <password>')
      exit()

    if self.install_falcon_sensor:
      if not all([self.falcon_client_id, self.falcon_client_secret]):
        print('Error: One or more runtime parameters are missing or are used in incorrect combination')
        print('Usage: --install-falcon-sensor --falcon-client-id --falcon-client-secret')
        exit()


class GCPRuntimeParameterVerification(BasicRuntimeParameterVerification):
  def __init__(self, config_file: str, install_falcon_sensor: bool, registry: str, repository: str, proxy_server: str,
               proxy_port: int, install_kac: bool, install_iar: bool, install_kpa: bool, falcon_client_id: str,
               falcon_client_secret: str, install_detections_container: bool, install_vulnerable_apps: bool,
               generate_misconfigs: bool, logger, cluster_name: str, vpc_network: str, location: str,
               project_id: str, asset_tags: str, service_account: str):
    super().__init__(config_file, install_falcon_sensor, registry, repository, proxy_server, proxy_port, install_kac,
                     install_iar, install_kpa, falcon_client_id, falcon_client_secret, install_detections_container,
                     install_vulnerable_apps, generate_misconfigs, logger)

    self.cluster_name = cluster_name
    self.vpc_network = vpc_network
    self.location = location
    self.project_id = project_id
    self.asset_tags = asset_tags
    self.service_account = service_account

  def verify_generic_gcp_parameters(self):
    if self.install_falcon_sensor and not all([self.falcon_client_id, self.falcon_client_secret]):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --install-falcon-sensor --falcon-client-id <id> --falcon-client-secret <secret>')
      exit()

    if any([self.service_account, self.registry]) and not all([self.service_account, self.registry]):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --registry <registry> --service-account <name>')
      exit()

  def verify_gke_standard_runtime_parameters(self):
    self.verify_generic_parameters()

    self.verify_generic_gcp_parameters()

    if (any([self.cluster_name, self.vpc_network, self.location, self.project_id, self.asset_tags]) and
      not all([self.cluster_name, self.vpc_network, self.location, self.project_id])):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print("Usage: --cluster-name <name> --vpc-network <name> --location <location> --project-id <id> --asset-tags "
            "<tags>")
      exit()

  def verify_gke_autopilot_runtime_parameters(self):
    self.verify_generic_parameters()

    self.verify_generic_gcp_parameters()

    if (any([self.cluster_name, self.vpc_network, self.location, self.project_id]) and
            not all([self.cluster_name, self.vpc_network, self.location, self.project_id])):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print("Usage: --cluster-name <name> --vpc-network <name> --location <location> --project-id <id>")
      exit()


class SensorInstallRuntimeParameterVerification:
  def __init__(self, falcon_sensor: bool = None, kernel_mode: bool = None, ebpf_mode: bool = None,
               registry: str = None, repository: str = None, proxy_server: str = None,
               proxy_port: int = None, aws_cluster: str = None, aws_region: str = None,
               az_cluster: str = None, az_resource_group: str = None, az_location: str = None,
               az_acr_resource_group: str = None, az_sp_name: str = None,
               az_sp_pass: str = None, gcp_cluster: str = None, gcp_location: str = None,
               gcp_project_id: str = None, gcp_service_account: str = None, kac: bool = None,
               iar: bool = None, kpa: bool = None, falcon_client_id: str = None,
               falcon_client_secret: str = None, detections_container: bool = None,
               vulnerable_apps: bool = None, generate_misconfigs: bool = None):

    self.falcon_sensor = falcon_sensor
    self.kernel_mode = kernel_mode
    self.ebpf_mode = ebpf_mode
    self.registry = registry
    self.repository = repository
    self.proxy_server = proxy_server
    self.proxy_port = proxy_port
    self.aws_cluster = aws_cluster
    self.aws_region = aws_region
    self.az_cluster = az_cluster
    self.az_resource_group = az_resource_group
    self.az_location = az_location
    self.az_acr_resource_group = az_acr_resource_group
    self.az_sp_name = az_sp_name
    self.az_sp_pass = az_sp_pass
    self.gcp_cluster = gcp_cluster
    self.gcp_location = gcp_location
    self.gcp_project_id = gcp_project_id
    self.gcp_service_account = gcp_service_account
    self.kac = kac
    self.iar = iar
    self.kpa = kpa
    self.falcon_client_id = falcon_client_id
    self.falcon_client_secret = falcon_client_secret
    self.detections_container = detections_container
    self.vulnerable_apps = vulnerable_apps
    self.generate_misconfigs = generate_misconfigs

  def verify_sensor_install_parameters(self):
    if self.falcon_sensor and any([self.aws_cluster, self.aws_region]) and \
      (not all([self.falcon_client_id, self.falcon_client_secret]) or
       not all([self.aws_cluster, self.aws_region])):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --falcon-sensor --aws-cluster <name> --aws-region <region> '
            '--falcon-client-id <id> --falcon-client-secret <secret>')
      exit()
    elif self.falcon_sensor and any([self.az_cluster, self.az_location, self.az_resource_group]) and \
      (not all([self.falcon_client_id, self.falcon_client_secret]) or
       not all([self.az_cluster, self.az_location, self.az_resource_group])):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --falcon-sensor --az-cluster <name> --az-location <location> '
            '--az-resource-group <name> --falcon-client-id <id> --falcon-client-secret <secret>')
      exit()
    elif self.falcon_sensor and any([self.gcp_cluster, self.gcp_location, self.gcp_project_id]) and \
      (not all([self.falcon_client_id, self.falcon_client_secret]) or
       not all([self.gcp_cluster, self.gcp_location, self.gcp_project_id])):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --falcon-sensor --gcp-cluster <name> --gcp-location <location> '
            '--gcp-project-id <id> --falcon-client-id <id> --falcon-client-secret <secret>')
      exit()

    if self.kac and any([self.aws_cluster, self.aws_region]) and \
      (not all([self.falcon_client_id, self.falcon_client_secret]) or
       (not all([self.aws_cluster, self.aws_region]))):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --kac --aws-cluster <name> --aws-region <region> '
            '--falcon-client-id <id> --falcon-client-secret <secret>')
      exit()
    elif self.kac and any([self.az_cluster, self.az_location, self.az_resource_group]) and \
      (not all([self.falcon_client_id, self.falcon_client_secret]) or
       not all([self.az_cluster, self.az_location, self.az_resource_group])):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --kac --az-cluster <name> --az-location <location> '
            '--az-resource-group <name> --falcon-client-id <id> --falcon-client-secret <secret>')
      exit()
    elif self.kac and any([self.gcp_cluster, self.gcp_location, self.gcp_project_id]) and \
      (not all([self.falcon_client_id, self.falcon_client_secret]) or
       not all([self.gcp_cluster, self.gcp_location, self.gcp_project_id])):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --kac --gcp-cluster <name> --gcp-location <location> '
            '--gcp-project-id <id> --falcon-client-id <id> --falcon-client-secret <secret>')
      exit()

    if self.iar and any([self.aws_cluster, self.aws_region]) and \
      (not all([self.falcon_client_id, self.falcon_client_secret]) or
       (not all([self.aws_cluster, self.aws_region]))):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --iar --aws-cluster <name> --aws-region <region> '
            '--falcon-client-id <id> --falcon-client-secret <secret>')
      exit()
    elif self.iar and any([self.az_cluster, self.az_location, self.az_resource_group]) and \
      (not all([self.falcon_client_id, self.falcon_client_secret]) or
       not all([self.az_cluster, self.az_location, self.az_resource_group])):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --iar --az-cluster <name> --az-location <location> '
            '--az-resource-group <name> --falcon-client-id <id> --falcon-client-secret <secret>')
      exit()
    elif self.iar and any([self.gcp_cluster, self.gcp_location, self.gcp_project_id]) and \
      (not all([self.falcon_client_id, self.falcon_client_secret]) or
       not all([self.gcp_cluster, self.gcp_location, self.gcp_project_id])):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --iar --gcp-cluster <name> --gcp-location <location> '
            '--gcp-project-id <id> --falcon-client-id <id> --falcon-client-secret <secret>')
      exit()

    if any([self.aws_cluster, self.aws_region]) and not all([self.aws_cluster, self.aws_region]):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --aws-cluster <name> --aws-region <region>')
      exit()

    if (any([self.az_cluster, self.az_location, self.az_resource_group]) and
            not all([self.az_cluster, self.az_location, self.az_resource_group])):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --az-cluster <name> --az-location <location> --az-resource-group <name>')
      exit()

    if (any([self.gcp_cluster, self.gcp_location, self.gcp_project_id]) and
            not all([self.gcp_cluster, self.gcp_location, self.gcp_project_id])):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --gcp-cluster <name> --gcp-location <name> --gcp-project-id <id>')
      exit()

    if self.registry and not any([self.falcon_sensor, self.kac, self.iar]):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --install-falcon-sensor | --install-kac | --install-iar --registry <registry>')
      exit()

    if self.repository and not self.registry:
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --install-falcon-sensor | --install-kac | --install-iar --registry <registry> --repository '
            '<repository>')
      exit()

    if any([self.proxy_server, self.proxy_port]) and not all([self.proxy_server, self.proxy_port]):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --proxy-server <server> --proxy-port <port>')
      exit()

    if all([self.proxy_server, self.proxy_port]) and not self.falcon_sensor:
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --install-falcon-sensor --proxy-server <server> --proxy-port <port>')
      exit()

    if self.kpa and not all([self.falcon_client_id, self.falcon_client_secret]):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Error: --install-kpa --falcon-client-id <id> --falcon-client-secret <secret>')
      exit()

    if self.kac and not all([self.falcon_client_id, self.falcon_client_secret]):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --install-kac --falcon-client-id <id> --falcon-client-secret <secret>')
      exit()

    if self.iar and not all([self.falcon_client_id, self.falcon_client_secret]):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination')
      print('Usage: --install-iar --falcon-client-id <id> --falcon-client-secret <secret>')
      exit()

    if (any([self.detections_container, self.vulnerable_apps, self.generate_misconfigs]) and not
            self.falcon_sensor):
      print('Warning: Installing detections container, vulnerable apps, or generating misconfigurations without '
            'falcon sensor will not generate detections or misconfigurations')


class SensorUninstallRuntimeParameterVerification:
  def __init__(self, falcon_sensor: bool = None, aws_cluster: str = None, aws_region: str = None,
               az_cluster: str = None, az_resource_group: str = None, az_location: str = None,
               az_acr_resource_group: str = None, gcp_cluster: str = None, gcp_location: str = None,
               gcp_project_id: str = None, kac: bool = None, iar: bool = None, kpa: bool = None,
               detections_container: bool = None):

    self.falcon_sensor = falcon_sensor
    self.aws_cluster = aws_cluster
    self.aws_region = aws_region
    self.az_cluster = az_cluster
    self.az_resource_group = az_resource_group
    self.az_location = az_location
    self.az_acr_resource_group = az_acr_resource_group
    self.gcp_cluster = gcp_cluster
    self.gcp_location = gcp_location
    self.gcp_project_id = gcp_project_id
    self.kac = kac
    self.iar = iar
    self.kpa = kpa
    self.detections_container = detections_container

  def verify_sensor_uninstall_parameters(self):
    if (any([self.falcon_sensor, self.kac, self.iar, self.kpa, self.detections_container]) and
        (
          not all([self.aws_cluster, self.aws_region]) and
          not all([self.az_cluster, self.az_resource_group]) and
          not all([self.gcp_cluster, self.gcp_location, self.gcp_project_id])
          )):
      print('Error: One or more runtime parameters are missing or are used in incorrect combination\n')
      print('AWS Usage: --falcon-sensor | --kac | --iar | --kpa | --detection-containers --aws-cluster <name> '
            '--aws-region <region>')
      print('Azure Usage: --falcon-sensor | --kac | --iar | --kpa | --detection-containers --az-cluster <name> '
            '--az-resource-group <name>')
      print('GCP Usage: --falcon-sensor | --kac | --iar | --kpa | --detection-containers --gcp-cluster <name> '
            '--gcp-location <location> --gcp-project-id <id>')
      exit()


# TODO: Retire this class
class RuntimeParameterVerification:
  def __init__(self, logger):
    self.logger = logger

  # @staticmethod
  # def verify_eks_managed_node_runtime_parameters(config_file,
  #                                                cluster_name,
  #                                                vpc_name,
  #                                                region,
  #                                                asset_tags,
  #                                                install_falcon_sensor,
  #                                                kernel_mode,
  #                                                ebpf_mode,
  #                                                registry,
  #                                                repository,
  #                                                proxy_server,
  #                                                proxy_port,
  #                                                install_kac,
  #                                                install_iar,
  #                                                install_kpa,
  #                                                falcon_client_id,
  #                                                falcon_client_secret,
  #                                                install_detections_container,
  #                                                install_vulnerable_apps,
  #                                                generate_misconfigs):
  #   if config_file:
  #     if not os.path.exists(config_file):
  #       print(f"The file '{config_file}' does not exist. Exiting the program.\n")
  #       exit()
  #
  #   if any([cluster_name, vpc_name, region, asset_tags]) and not all([cluster_name, vpc_name, region, asset_tags]):
  #     print("Error: --cluster-name, --vpc-name, --region, and --asset-tags must be provided together")
  #     exit()
  #
  #   if install_falcon_sensor:
  #     if not any([kernel_mode, ebpf_mode]) and not all([falcon_client_id, falcon_client_secret]):
  #       print('Usage: --install-falcon-sensor --kernel-mode --falcon-client-id --falcon-client-secret')
  #       print('OR')
  #       print('Usage: --install-falcon-sensor --ebpf-mode --falcon-client-id --falcon-client-secret')
  #       exit()
  #     elif any([kernel_mode, ebpf_mode]) and not all([falcon_client_id, falcon_client_secret]):
  #       print('Usage: --install-falcon-sensor --kernel-mode --falcon-client-id --falcon-client-secret')
  #       print('OR')
  #       print('Usage: --install-falcon-sensor --ebpf-mode --falcon-client-id --falcon-client-secret')
  #       exit()
  #
  #   if any([kernel_mode, ebpf_mode]) and not install_falcon_sensor:
  #     print('Error: --kernel-mode and --ebpf-mode must be used with --install-falcon-sensor')
  #     exit()
  #
  #   if registry and not any([install_falcon_sensor, install_kac, install_iar]):
  #     print('Error: --registry must be used with --install-falcon-sensor, --install-kac, or --install-iar')
  #     exit()
  #
  #   if repository and not registry and not any([install_falcon_sensor, install_kac, install_iar]):
  #     print('Error: --repository must be used with --registry and --install-falcon-sensor, --install-kac, '
  #           'or --install-iar ')
  #     exit()
  #
  #   if any([proxy_server, proxy_port]) and not all([proxy_server, proxy_port]):
  #     print('Error: --proxy-server and --proxy-port must be used together')
  #     exit()
  #
  #   if all([proxy_server, proxy_port]) and not install_falcon_sensor:
  #     print('Error: --proxy-server and --proxy-port must be used with --install-falcon-sensor')
  #     exit()
  #
  #   if install_kpa and not all([falcon_client_id, falcon_client_secret]):
  #     print('Error: --install-kpa must be used with --falcon-client-id --falcon-client-secret')
  #     exit()
  #
  #   if install_kac and not all([falcon_client_id, falcon_client_secret]):
  #     print('Usage: --install-kac must be used with --falcon-client-id --falcon-client-secret')
  #     exit()
  #
  #   if install_iar and not all([falcon_client_id, falcon_client_secret]):
  #     print('Usage: --install-iar must be used with --falcon-client-id --falcon-client-secret')
  #     exit()
  #
  #   if any([install_detections_container, install_vulnerable_apps, generate_misconfigs]) and not install_falcon_sensor:
  #     print('Warning: Installing detections container, vulnerable apps, or generating misconfigurations without '
  #           'falcon sensor will not generate detections or misconfigurations')
  #
  # @staticmethod
  # def verify_eks_fargate_runtime_parameters(config_file,
  #                                           cluster_name,
  #                                           vpc_name,
  #                                           region,
  #                                           asset_tags,
  #                                           install_falcon_sensor,
  #                                           registry,
  #                                           repository,
  #                                           proxy_server,
  #                                           proxy_port,
  #                                           install_kac,
  #                                           install_iar,
  #                                           install_kpa,
  #                                           falcon_client_id,
  #                                           falcon_client_secret,
  #                                           install_detections_container,
  #                                           install_vulnerable_apps,
  #                                           generate_misconfigs):
  #   if config_file:
  #     if not os.path.exists(config_file):
  #       print(f"The file '{config_file}' does not exist. Exiting the program.\n")
  #       exit()
  #
  #   if any([cluster_name, vpc_name, region, asset_tags]) and not all([cluster_name, vpc_name, region, asset_tags]):
  #     print("Error: --cluster-name, --vpc-name, --region, and --asset-tags must be provided together")
  #     exit()
  #
  #   if install_falcon_sensor and not all([falcon_client_id, falcon_client_secret]):
  #     print('Usage: --install-falcon-sensor --kernel-mode --falcon-client-id --falcon-client-secret')
  #     print('OR')
  #     print('Usage: --install-falcon-sensor --ebpf-mode --falcon-client-id --falcon-client-secret')
  #     exit()
  #
  #   if registry and not any([install_falcon_sensor, install_kac, install_iar]):
  #     print('Error: --registry must be used with --install-falcon-sensor, --install-kac, or --install-iar')
  #     exit()
  #
  #   if repository and not registry and not any([install_falcon_sensor, install_kac, install_iar]):
  #     print('Error: --repository must be used with --registry and --install-falcon-sensor, --install-kac, '
  #           'or --install-iar ')
  #     exit()
  #
  #   if any([proxy_server, proxy_port]) and not all([proxy_server, proxy_port]):
  #     print('Error: --proxy-server and --proxy-port must be used together')
  #     exit()
  #
  #   if any([proxy_server, proxy_port]) and not install_falcon_sensor:
  #     print('Error: --proxy-server and --proxy-port must be used with --install-falcon-sensor')
  #     exit()
  #
  #   if install_kpa and not all([falcon_client_id, falcon_client_secret]):
  #     print('Error: --install-kpa must be used with --falcon-client-id --falcon-client-secret')
  #     exit()
  #
  #   if install_kac and not all([falcon_client_id, falcon_client_secret]):
  #     print('Usage: --install-kac must be used with --falcon-client-id --falcon-client-secret')
  #     exit()
  #
  #   if install_iar and not all([falcon_client_id, falcon_client_secret]):
  #     print('Usage: --install-iar must be used with --falcon-client-id --falcon-client-secret')
  #     exit()
  #
  #   if any([install_detections_container, install_vulnerable_apps, generate_misconfigs]) and not install_falcon_sensor:
  #     print('Warning: Installing detections container, vulnerable apps, or generating misconfigurations without '
  #           'falcon sensor will not generate detections or misconfigurations')
  #
  # @staticmethod
  # def verify_aks_runtime_parameters(config_file,
  #                                   cluster_name,
  #                                   resource_group,
  #                                   location,
  #                                   asset_tags,
  #                                   install_falcon_sensor,
  #                                   kernel_mode,
  #                                   ebpf_mode,
  #                                   registry,
  #                                   repository,
  #                                   proxy_server,
  #                                   proxy_port,
  #                                   acr_resource_group,
  #                                   sp_name,
  #                                   sp_pass,
  #                                   acr_sub_id,
  #                                   install_kac,
  #                                   install_iar,
  #                                   install_kpa,
  #                                   falcon_client_id,
  #                                   falcon_client_secret,
  #                                   install_detections_container,
  #                                   install_vulnerable_apps,
  #                                   generate_misconfigs):
  #   if config_file:
  #     if not os.path.exists(config_file):
  #       print(f"The file '{config_file}' does not exist. Exiting the program.\n")
  #       exit()
  #
  #   if (any([cluster_name, resource_group, location, asset_tags]) and
  #           not all([cluster_name, resource_group, location, asset_tags])):
  #     print("Error: --cluster-name, --resource-group, --location, and --asset-tags must be provided together")
  #     exit()
  #
  #   if any([acr_resource_group, acr_sub_id]) and not all([acr_resource_group, acr_sub_id]):
  #     print('Error: --acr-resource-group and --acr-sub-id must be used together')
  #     exit()
  #
  #   if any([acr_resource_group, acr_sub_id]) and not any([install_falcon_sensor, install_kac, install_iar]):
  #     print('Error: --acr-resource-group and --acr-sub-id must be used with either --install-falcon-sensor, '
  #           '--install-kac, or --install-iar')
  #     exit()
  #
  #   if any([sp_name, sp_pass]) and not any([install_falcon_sensor, install_kac, install_iar]):
  #     print('Error: --sp-name and --sp-pass must be used with either --install-falcon-sensor, '
  #           '--install-kac, or --install-iar')
  #     exit()
  #
  #   if any([sp_name, sp_pass]) and not any([acr_resource_group, acr_sub_id]):
  #     print('Error: --sp-name and --sp-pass must be used with --acr-resource-group and --acr-sub-id')
  #     exit()
  #
  #   if install_falcon_sensor:
  #     if not any([kernel_mode, ebpf_mode]) and not all([falcon_client_id, falcon_client_secret]):
  #       print('Usage: --install-falcon-sensor --kernel-mode --falcon-client-id --falcon-client-secret')
  #       print('OR')
  #       print('Usage: --install-falcon-sensor --ebpf-mode --falcon-client-id --falcon-client-secret')
  #       exit()
  #
  #   if any([kernel_mode, ebpf_mode]) and not install_falcon_sensor:
  #     print('Error: --kernel-mode and --ebpf-mode must be used with --install-falcon-sensor')
  #     exit()
  #
  #   if registry and not any([install_falcon_sensor, install_kac, install_iar]):
  #     print('Error: --registry must be used with --install-falcon-sensor, --install-kac, or --install-iar')
  #     exit()
  #
  #   if repository and not registry and not any([install_falcon_sensor, install_kac, install_iar]):
  #     print('Error: --repository must be used with --registry and --install-falcon-sensor, --install-kac, '
  #           'or --install-iar ')
  #     exit()
  #
  #   if any([proxy_server, proxy_port]) and not all([proxy_server, proxy_port]):
  #     print('Error: --proxy-server and --proxy-port must be used together')
  #     exit()
  #
  #   if any([proxy_server, proxy_port]) and not install_falcon_sensor:
  #     print('Error: --proxy-server and --proxy-port must be used with --install-falcon-sensor')
  #     exit()
  #
  #   if install_kpa and not all([falcon_client_id, falcon_client_secret]):
  #     print('Error: --install-kpa must be used with --falcon-client-id --falcon-client-secret')
  #     exit()
  #
  #   if install_kac and not all([falcon_client_id, falcon_client_secret]):
  #     print('Usage: --install-kac must be used with --falcon-client-id --falcon-client-secret')
  #     exit()
  #
  #   if install_iar and not all([falcon_client_id, falcon_client_secret]):
  #     print('Usage: --install-iar must be used with --falcon-client-id --falcon-client-secret')
  #     exit()
  #
  #   if any([install_detections_container, install_vulnerable_apps, generate_misconfigs]) and not install_falcon_sensor:
  #     print('Warning: Installing detections container, vulnerable apps, or generating misconfigurations without '
  #           'falcon sensor will not generate detections or misconfigurations')
  #
  # @staticmethod
  # def verify_gke_standard_runtime_parameters(config_file,
  #                                            cluster_name,
  #                                            vpc_network,
  #                                            location,
  #                                            project_id,
  #                                            asset_tags,
  #                                            install_falcon_sensor,
  #                                            registry,
  #                                            repository,
  #                                            proxy_server,
  #                                            proxy_port,
  #                                            service_account,
  #                                            install_kac,
  #                                            install_iar,
  #                                            install_kpa,
  #                                            falcon_client_id,
  #                                            falcon_client_secret,
  #                                            install_detections_container,
  #                                            install_vulnerable_apps,
  #                                            generate_misconfigs):
  #   if config_file:
  #     if not os.path.exists(config_file):
  #       print(f"The file '{config_file}' does not exist. Exiting the program.\n")
  #       exit()
  #
  #   if (any([cluster_name, vpc_network, location, project_id, asset_tags]) and
  #           not all([cluster_name, vpc_network, location, project_id, asset_tags])):
  #     print("Error: --cluster-name, --vpc-network, --location, --project-id, and --asset-tags must be provided "
  #           "together")
  #     exit()
  #
  #   if install_falcon_sensor and not all([falcon_client_id, falcon_client_secret]):
  #     print('Error: --install-falcon-sensor needs --falcon-client-id and --falcon-client-secret')
  #     exit()
  #
  #   if registry and not any([install_falcon_sensor, install_kac, install_iar]):
  #     print('Error: --registry must be used with --install-falcon-sensor, --install-kac, or --install-iar')
  #     exit()
  #
  #   if repository and not registry and not any([install_falcon_sensor, install_kac, install_iar]):
  #     print('Error: --repository must be used with --registry and --install-falcon-sensor, --install-kac, '
  #           'or --install-iar ')
  #     exit()
  #
  #   if any([proxy_server, proxy_port]) and not all([proxy_server, proxy_port]):
  #     print('Error: --proxy-server and --proxy-port must be used together')
  #     exit()
  #
  #   if any([proxy_server, proxy_port]) and not install_falcon_sensor:
  #     print('Error: --proxy-server and --proxy-port must be used with --install-falcon-sensor')
  #     exit()
  #
  #   if service_account and not registry:
  #     print('Error: --service-account must be used with --registry')
  #     exit()
  #
  #   if install_kpa and not all([falcon_client_id, falcon_client_secret]):
  #     print('Error: --install-kpa must be used with --falcon-client-id --falcon-client-secret')
  #     exit()
  #
  #   if install_kac and not all([falcon_client_id, falcon_client_secret]):
  #     print('Usage: --install-kac must be used with --falcon-client-id --falcon-client-secret')
  #     exit()
  #
  #   if install_iar and not all([falcon_client_id, falcon_client_secret]):
  #     print('Usage: --install-iar must be used with --falcon-client-id --falcon-client-secret')
  #     exit()
  #
  #   if any([install_detections_container, install_vulnerable_apps, generate_misconfigs]) and not install_falcon_sensor:
  #     print('Warning: Installing detections container, vulnerable apps, or generating misconfigurations without '
  #           'falcon sensor will not generate detections or misconfigurations')
  #
  # @staticmethod
  # def verify_gke_autopilot_runtime_parameters(config_file,
  #                                             cluster_name,
  #                                             vpc_network,
  #                                             location,
  #                                             project_id,
  #                                             install_falcon_sensor,
  #                                             registry,
  #                                             repository,
  #                                             proxy_server,
  #                                             proxy_port,
  #                                             service_account,
  #                                             install_kac,
  #                                             install_iar,
  #                                             install_kpa,
  #                                             falcon_client_id,
  #                                             falcon_client_secret,
  #                                             install_detections_container,
  #                                             install_vulnerable_apps,
  #                                             generate_misconfigs):
  #   if config_file:
  #     if not os.path.exists(config_file):
  #       print(f"The file '{config_file}' does not exist. Exiting the program.\n")
  #       exit()
  #
  #   if (any([cluster_name, vpc_network, location, project_id]) and not all([cluster_name, vpc_network, location,
  #                                                                           project_id])):
  #     print("Error: --cluster-name, --vpc-network, --location, --project-id, and --asset-tags must be provided "
  #           "together")
  #     exit()
  #
  #   if install_falcon_sensor and not all([falcon_client_id, falcon_client_secret]):
  #     print('Error: --install-falcon-sensor needs --falcon-client-id and --falcon-client-secret')
  #     exit()
  #
  #   if registry and not any([install_falcon_sensor, install_kac, install_iar]):
  #     print('Error: --registry must be used with --install-falcon-sensor, --install-kac, or --install-iar')
  #     exit()
  #
  #   if repository and not registry and not any([install_falcon_sensor, install_kac, install_iar]):
  #     print('Error: --repository must be used with --registry and --install-falcon-sensor, --install-kac, '
  #           'or --install-iar ')
  #     exit()
  #
  #   if any([proxy_server, proxy_port]) and not all([proxy_server, proxy_port]):
  #     print('Error: --proxy-server and --proxy-port must be used together')
  #     exit()
  #
  #   if any([proxy_server, proxy_port]) and not install_falcon_sensor:
  #     print('Error: --proxy-server and --proxy-port must be used with --install-falcon-sensor')
  #     exit()
  #
  #   if service_account and not registry:
  #     print('Error: --service-account must be used with --registry')
  #     exit()
  #
  #   if install_kpa and not all([falcon_client_id, falcon_client_secret]):
  #     print('Error: --install-kpa must be used with --falcon-client-id --falcon-client-secret')
  #     exit()
  #
  #   if install_kac and not all([falcon_client_id, falcon_client_secret]):
  #     print('Usage: --install-kac must be used with --falcon-client-id --falcon-client-secret')
  #     exit()
  #
  #   if install_iar and not all([falcon_client_id, falcon_client_secret]):
  #     print('Usage: --install-iar must be used with --falcon-client-id --falcon-client-secret')
  #     exit()
  #
  #   if any([install_detections_container, install_vulnerable_apps, generate_misconfigs]) and not install_falcon_sensor:
  #     print('Warning: Installing detections container, vulnerable apps, or generating misconfigurations without '
  #           'falcon sensor will not generate detections or misconfigurations')
  #
  # # @staticmethod
  # # def verify_csp_runtime_parameters(config_file=None,
  # #                                   cluster_name=None,
  # #                                   vpc_name=None,
  # #                                   region=None,
  # #                                   asset_tags=None,
  # #                                   install_falcon_sensor=None,
  # #                                   kernel_mode=None,
  # #                                   ebpf_mode=None,
  # #                                   registry=None,
  # #                                   repository=None,
  # #                                   sensor_image_tag=None,
  # #                                   proxy_server=None,
  # #                                   proxy_port=None,
  # #                                   sensor_tags=None,
  # #                                   install_kac=None,
  # #                                   kac_image_tag=None,
  # #                                   install_iar=None,
  # #                                   iar_image_tag=None,
  # #                                   install_kpa=None,
  # #                                   falcon_client_id=None,
  # #                                   falcon_client_secret=None,
  # #                                   install_detections_container=None,
  # #                                   install_vulnerable_apps=None,
  # #                                   generate_misconfigs=None,
  # #                                   monitor_namespaces=None,
  # #                                   exclude_namespaces=None,
  # #                                   deployment=None,
  # #                                   cloud_type=None,
  # #                                   cluster_type=None,
  # #                                   install_load_test_apps=None,
  # #                                   gcp_project_id=None):
  # #   if config_file:
  # #     if not os.path.exists(config_file):
  # #       print(f"The file '{config_file}' does not exist. Exiting the program.\n")
  # #       exit()
  # #
  # #   if (cloud_type == 'gcp' and cluster_type == 'gke-standard') and not gcp_project_id:
  # #     print('Error:')
  # #     print('Usage: create gcp gke-standard --gcp-project-id <project-name>')
  # #     exit()
  # #   elif (cloud_type == 'gcp' and cluster_type == 'gke-autopilot') and not gcp_project_id:
  # #     print('Error:')
  # #     print('Usage: create gcp gke-autopilot --gcp-project-id <project-name>')
  # #     exit()
  # #
  # #   if install_falcon_sensor and deployment == 'eks-managed-node':
  # #     if (not kernel_mode and not ebpf_mode) or (not falcon_client_id or not falcon_client_secret):
  # #       print('Error:')
  # #       print('Usage: --install-falcon-sensor --kernel-mode --falcon-client-id --falcon-client-secret')
  # #       print('OR')
  # #       print('Usage: --install-falcon-sensor --ebpf-mode --falcon-client-id --falcon-client-secret')
  # #       exit()
  # #   elif install_falcon_sensor and (cluster_type == 'gke-standard' or cluster_type == 'gke-autopilot'):
  # #     if not falcon_client_id or not falcon_client_secret:
  # #       print('Error:')
  # #       print('Usage: --install-falcon-sensor --ebpf-mode --falcon-client-id --falcon-client-secret')
  # #       exit()
  # #
  # #   if install_kpa:
  # #     if not falcon_client_id or not falcon_client_secret:
  # #       print('Error:')
  # #       print('Usage: --install-kpa --falcon-client-id --falcon-client-secret')
  # #       exit()
  # #
  # #   if install_kac:
  # #     if not falcon_client_id or not falcon_client_secret:
  # #       print('Error:')
  # #       print('Usage: --install-kac --falcon-client-id --falcon-client-secret')
  # #       exit()
  # #
  # #   if install_iar:
  # #     if not falcon_client_id or not falcon_client_secret:
  # #       print('Error:')
  # #       print('Usage: --install-iar --falcon-client-id --falcon-client-secret')
  # #       exit()

  @staticmethod
  def verify_crowdstrike_sensor_parameters(falcon_sensor=None,
                                           kernel_mode=None,
                                           ebpf_mode=None,
                                           monitor_namespaces=None,
                                           exclude_namespaces=None,
                                           falcon_image_repo=None,
                                           falcon_image_tag=None,
                                           proxy_server=None,
                                           proxy_port=None,
                                           falcon_sensor_tags=None,
                                           aws_region=None,
                                           aws_cluster_name=None,
                                           azure_resource_group_name=None,
                                           azure_cluster_name=None,
                                           gcp_region=None,
                                           gcp_cluster_name=None,
                                           gcp_project_id=None,
                                           kpa=None,
                                           kac=None,
                                           iar=None,
                                           detections_container=None,
                                           vulnerable_apps=None,
                                           falcon_client_id=None,
                                           falcon_client_secret=None,
                                           ecr_iam_policy_name=None,
                                           ecr_iam_role_name=None,
                                           logger=None,
                                           cluster_type=None):
    if cluster_type is None:
      if falcon_sensor or kpa or kac or iar or detections_container or vulnerable_apps:
        if aws_cluster_name and aws_region:
          return
        elif azure_cluster_name and azure_resource_group_name:
          return
        elif gcp_project_id and gcp_region and gcp_project_id:
          return
        else:
          print('Error:')
          print('Cluster name, region or other parameters are missing.')
          exit()
    else:
      if falcon_sensor:
        if cluster_type == 'eks-managed-node' or cluster_type == 'eks-self-managed-node':
          if (not kernel_mode and not ebpf_mode) or (not aws_cluster_name or not aws_region or not falcon_client_secret
                                                     or not falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --falcon-sensor --aws-cluster-name eks-cluster '
              '--aws-region eu-west-2 --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s')
            print('OR')
            print(
              'Usage: abstrakt install crowdstrike --falcon-sensor --aws-cluster-name eks-cluster '
              '--aws-region eu-west-2 --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s')
            exit()
        elif cluster_type == 'eks-fargate':
          if kernel_mode:
            print('Error:')
            print('--kernel-mode is not supported with EKS Fargate.')
            exit()

          if not aws_cluster_name or not aws_region or not falcon_client_secret or not falcon_client_id:
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --falcon-sensor --aws-cluster-name eks-cluster '
              '--aws-region eu-west-2 --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s')
            print('OR')
            print(
              'Usage: abstrakt install crowdstrike --falcon-sensor --aws-cluster-name eks-cluster '
              '--aws-region eu-west-2 --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s')
            exit()
        elif cluster_type == 'azure-aks':
          if (not kernel_mode and not ebpf_mode) or (not azure_cluster_name or not azure_resource_group_name or not
          falcon_client_secret or not falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --falcon-sensor --azure-cluster-name azure-cluster '
              '--azure-resource-group-name uksouth --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s')
            print('OR')
            print(
              'Usage: abstrakt install crowdstrike --falcon-sensor --azure-cluster-name azure-cluster '
              '--azure-resource-group-name uksouth --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s')
            exit()
        elif cluster_type == 'gke-standard' or cluster_type == 'gke-autopilot':
          if (not gcp_cluster_name or not gcp_region or not gcp_project_id or not falcon_client_secret or not
          falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --falcon-sensor --gcp-cluster-name gke-cluster --gcp-region '
              'us-central1-c --gcp-project-name xyz --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s')
            exit()
        else:
          print('Sensor/Error: Unsupported cluster type in use. Exiting the program.')
          exit()

      if kpa:
        if (falcon_image_repo or falcon_image_tag) and not falcon_sensor:
          print('Error:')
          print('Parameters falcon_image_repo and falcon_image_tag are supported for falcon sensor only.')
          exit()

        if (cluster_type == 'eks-managed-node' or cluster_type == 'eks-self-managed-node' or cluster_type ==
          'eks-fargate'):
          if not aws_cluster_name or not aws_region or not falcon_client_secret or not falcon_client_id:
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --kpa --aws-cluster-name random_eks_cluster --aws-region eu-west-2 '
              '--falcon-client-id 3af74117 --falcon-client-secret vlTpn372s ')
            exit()
        elif cluster_type == 'azure-aks':
          if (not azure_cluster_name or not azure_resource_group_name or not falcon_client_secret or not
          falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --kpa --azure-cluster-name random_eks_cluster '
              '--azure-resource-group-name azure-resource-group --falcon-client-id 3af74117 --falcon-client-secret '
              'vlTpn372s')
        elif cluster_type == 'gke-standard' or cluster_type == 'gke-autopilot':
          if (not gcp_cluster_name or not gcp_region or not gcp_project_id or not falcon_client_secret or not
          falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --kpa --gcp-cluster-name random_gke_cluster '
              '--gcp-region us-central1-c gcp-project-name xyz --falcon-client-id 3af74117 --falcon-client-secret '
              'vlTpn372s')
            exit()
        else:
          print('KPA/Error: use --help parameter to understand the right usage of interface.')
          exit()

      if kac:
        if (falcon_image_repo or falcon_image_tag) and not falcon_sensor:
          print('Error:')
          print('Parameters falcon_image_repo and falcon_image_tag are supported for falcon sensor only.')
          exit()

        if (cluster_type == 'eks-managed-node' or cluster_type == 'eks-self-managed-node' or cluster_type ==
          'eks-fargate'):
          if not aws_cluster_name or not aws_region or not falcon_client_secret or not falcon_client_id:
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --kac --aws-cluster-name random_eks_cluster --aws-region eu-west-2 '
              '--falcon-client-id 3af74117 --falcon-client-secret vlTpn372s ')
            exit()
        elif cluster_type == 'azure-aks':
          if (not azure_cluster_name or not azure_resource_group_name or not falcon_client_secret or not
          falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --kac --azure-cluster-name random_eks_cluster '
              '--azure-resource-group-name azure-resource-group --falcon-client-id 3af74117 --falcon-client-secret '
              'vlTpn372s')
        elif cluster_type == 'gke-standard' or cluster_type == 'gke-autopilot':
          if (not gcp_cluster_name or not gcp_region or not gcp_project_id or not falcon_client_secret or not
          falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --kac --gcp-cluster-name random_gke_cluster '
              '--gcp-region us-central1-c gcp-project-name xyz --falcon-client-id 3af74117 --falcon-client-secret '
              'vlTpn372s')
            exit()
        else:
          print('KAC/Error: use --help parameter to understand the right usage of interface.')
          exit()

      if iar:
        if (falcon_image_repo or falcon_image_tag) and not falcon_sensor:
          print('Error:')
          print('Parameters falcon_image_repo and falcon_image_tag are supported for falcon sensor only.')
          exit()

        if (cluster_type == 'eks-managed-node' or cluster_type == 'eks-self-managed-node' or cluster_type ==
          'eks-fargate'):
          if not aws_cluster_name or not aws_region or not falcon_client_secret or not falcon_client_id:
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --iar --aws-cluster-name random_eks_cluster --aws-region '
              'eu-west-2 --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s ')
            exit()
        elif cluster_type == 'azure-aks':
          if (not azure_cluster_name or not azure_resource_group_name or not falcon_client_secret or not
          falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --iar --azure-cluster-name random_eks_cluster '
              '--azure-resource-group-name azure-resource-group --falcon-client-id 3af74117 --falcon-client-secret '
              'vlTpn372s')
        elif cluster_type == 'gke-standard' or cluster_type == 'gke-autopilot':
          if (not gcp_cluster_name or not gcp_region or not gcp_project_id or not falcon_client_secret or not
          falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --iar --gcp-cluster-name random_gke_cluster '
              '--gcp-region us-central1-c gcp-project-name xyz --falcon-client-id 3af74117 --falcon-client-secret '
              'vlTpn372s')
            exit()
        else:
          print('IAR/Error: use --help parameter to understand the right usage of interface.')
          exit()

      if detections_container:
        if (cluster_type == 'eks-managed-node' or cluster_type == 'eks-self-managed-node' or cluster_type ==
          'eks-fargate'):
          if not aws_cluster_name or not aws_region or not falcon_client_secret or not falcon_client_id:
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --detections-container --aws-cluster-name random_eks_cluster '
              '--aws-region eu-west-2 --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s ')
            exit()
        elif cluster_type == 'azure-aks':
          if (not azure_cluster_name or not azure_resource_group_name or not falcon_client_secret or not
          falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --detections-container --azure-cluster-name random_eks_cluster '
              '--azure-resource-group-name azure-resource-group --falcon-client-id 3af74117 --falcon-client-secret '
              'vlTpn372s')
        elif cluster_type == 'gke-standard' or cluster_type == 'gke-autopilot':
          if (not gcp_cluster_name or not gcp_region or not gcp_project_id or not falcon_client_secret or not
          falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --detections-container --gcp-cluster-name random_gke_cluster '
              '--gcp-region us-central1-c gcp-project-name xyz --falcon-client-id 3af74117 --falcon-client-secret '
              'vlTpn372s')
            exit()
        else:
          print('DetectionsContainer/Error: use --help parameter to understand the right usage of interface.')
          exit()

      if vulnerable_apps:
        if (cluster_type == 'eks-managed-node' or cluster_type == 'eks-self-managed-node' or cluster_type ==
          'eks-fargate'):
          if not aws_cluster_name or not aws_region or not falcon_client_secret or not falcon_client_id:
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --vulnerable-apps --aws-cluster-name random_eks_cluster '
              '--aws-region eu-west-2 --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s ')
            exit()
        elif cluster_type == 'azure-aks':
          if (not azure_cluster_name or not azure_resource_group_name or not falcon_client_secret or not
          falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --vulnerable-apps --azure-cluster-name random_eks_cluster '
              '--azure-resource-group-name azure-resource-group --falcon-client-id 3af74117 --falcon-client-secret '
              'vlTpn372s')
        elif cluster_type == 'gke-standard' or cluster_type == 'gke-autopilot':
          if (not gcp_cluster_name or not gcp_region or not gcp_project_id or not falcon_client_secret or not
          falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --vulnerable-apps --gcp-cluster-name random_gke_cluster '
              '--gcp-region us-central1-c gcp-project-name xyz --falcon-client-id 3af74117 --falcon-client-secret '
              'vlTpn372s')
            exit()
        else:
          print('Vulnerable Apps/Error: use --help parameter to understand the right usage of interface.')
          exit()
