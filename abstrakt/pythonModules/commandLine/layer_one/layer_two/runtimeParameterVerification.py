import os

from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf


class RuntimeParameterVerification:
  def __init__(self, logger):
    self.logger = logger

  def verify_csp_runtime_parameters(self, config_file=None, install_falcon_sensor=None, kernel_mode=None,
                                    ebpf_mode=None, falcon_client_id=None, falcon_client_secret=None,
                                    proxy_server=None, proxy_port=None, falcon_sensor_tags=None,
                                    install_kpa=None, install_kac=None, install_detections_container=None,
                                    install_load_test_apps=None, cluster_type=None):
    if config_file:
      if not os.path.exists(config_file):
        print(f"The file '{config_file}' does not exist. Exiting the program.\n")
        exit()

    if cluster_type == ('eks-managed-node' or 'aks' or 'gke-cos'):
      if install_falcon_sensor and ((not kernel_mode and not ebpf_mode) or not falcon_client_id or not
                                    falcon_client_secret):
        printf('\nUsage: --kernel-mode OR --ebpf-mode, --falcon-client-id, --falcon-client-secret, --falcon-cid,',
               '--falcon-cloud-region, and --falcon-api are required to install falcon sensor. Exiting program.\n',
               logger=self.logger)
        exit()
      elif install_falcon_sensor and kernel_mode and ebpf_mode:
        printf('\nUsage: --kernel-mode and --ebpf-mode cannot be used together. Existing program.\n',
               logger=self.logger)
        exit()
      elif (install_falcon_sensor and (kernel_mode or ebpf_mode) and falcon_client_id and falcon_client_secret
            and ((proxy_server and not proxy_port) or (proxy_port and not proxy_server))):
        printf('\nUsage: --proxy-server and --proxy-port both are required together. Exiting program.\n',
               logger=self.logger)
        exit()
      elif (install_falcon_sensor and falcon_sensor_tags and ((not kernel_mode and not ebpf_mode)
                                                              or not falcon_client_id or not falcon_client_secret)):
        printf('\nUsage: --kernel-mode OR --ebpf-mode, --falcon-client-id, --falcon-client-secret, --falcon-cid,',
               '--falcon-cloud-region, and --falcon-api are required to install falcon sensor. Exiting program.\n',
               logger=self.logger)
        exit()
    else:
      if install_falcon_sensor and (not falcon_client_id or not falcon_client_secret):
        printf('\nUsage: --falcon-client-id, --falcon-client-secret, --falcon-cid, --falcon-cloud-region, '
               'and --falcon-api are required to install falcon sensor. Exiting program.\n',
               logger=self.logger)
        exit()

    if install_kpa:
      if not os.path.exists("./abstrakt/conf/crowdstrike/kpa/config_value.yaml"):
        print(f"The file ./abstrakt/conf/crowdstrike/kpa/config_value.yaml does not exist. Exiting the program.\n")
        exit()
    elif install_kac and (not falcon_client_id or not falcon_client_secret):
      printf('\nUsage: --falcon-client-id, --falcon-client-secret, --falcon-cid, and --falcon-cloud-region '
             'are required to install falcon kubernetes admission controller. Exiting program.\n',
             logger=self.logger)
      exit()
    elif install_detections_container:
      if not os.path.exists('./abstrakt/conf/crowdstrike/detections-container/detections_container.yaml'):
        print("The file ./abstrakt/conf/crowdstrike/detections-container/detections_container.yaml does not exist. "
              "Exiting the program.\n")
        exit()
    elif install_load_test_apps:
      yaml_files = [
        "./modules/vendors/generic/k8sLoadSimulator/definitions/metrics.yaml",
        "./modules/vendors/generic/k8sLoadSimulator/definitions/phpApache.yaml",
        "./modules/vendors/generic/k8sLoadSimulator/definitions/infiniteCalls.yaml"
      ]

      for file in yaml_files:
        if not os.path.exists(file):
          print(f'{file} does not exist to install load test app. Exiting the program.\n')
