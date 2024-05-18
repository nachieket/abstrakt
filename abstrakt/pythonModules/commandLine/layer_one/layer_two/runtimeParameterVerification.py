import os


class RuntimeParameterVerification:
  def __init__(self, logger):
    self.logger = logger

  @staticmethod
  def verify_csp_runtime_parameters(config_file=None, install_falcon_sensor=None, falcon_image_tag=None,
                                    kernel_mode=None, ebpf_mode=None, falcon_client_id=None, falcon_client_secret=None,
                                    monitor_namespaces=None, exclude_namespaces=None, proxy_server=None,
                                    proxy_port=None, falcon_sensor_tags=None, install_kpa=None, install_kac=None,
                                    install_iar=None, install_detections_container=None,
                                    install_vulnerable_apps=None, cloud_type=None, cluster_type=None,
                                    install_load_test_apps=None, gcp_project_id=None):
    if config_file:
      if not os.path.exists(config_file):
        print(f"The file '{config_file}' does not exist. Exiting the program.\n")
        exit()

    if (cloud_type == 'gcp' and cluster_type == 'gke-standard') and not gcp_project_id:
      print('Error:')
      print('Usage: create gcp gke-standard --gcp-project-id <project-name>')
      exit()
    elif (cloud_type == 'gcp' and cluster_type == 'gke-autopilot') and not gcp_project_id:
      print('Error:')
      print('Usage: create gcp gke-autopilot --gcp-project-id <project-name>')
      exit()

    if install_falcon_sensor and (cluster_type == 'eks-managed-node' or cluster_type == 'aks'):
      if (not kernel_mode and not ebpf_mode) or (not falcon_client_id or not falcon_client_secret):
        print('Error:')
        print('Usage: --install-falcon-sensor --kernel-mode --falcon-client-id --falcon-client-secret')
        print('OR')
        print('Usage: --install-falcon-sensor --ebpf-mode --falcon-client-id --falcon-client-secret')
        exit()
    elif install_falcon_sensor and (cluster_type == 'gke-standard' or cluster_type == 'gke-autopilot'):
      if (not ebpf_mode) or (not falcon_client_id or not falcon_client_secret):
        print('Error:')
        print('Usage: --install-falcon-sensor --ebpf-mode --falcon-client-id --falcon-client-secret')
        exit()

    if install_kpa:
      if not falcon_client_id or not falcon_client_secret:
        print('Error:')
        print('Usage: --install-kpa --falcon-client-id --falcon-client-secret')
        exit()

    if install_kac:
      if not falcon_client_id or not falcon_client_secret:
        print('Error:')
        print('Usage: --install-kac --falcon-client-id --falcon-client-secret')
        exit()

    if install_iar:
      if not falcon_client_id or not falcon_client_secret:
        print('Error:')
        print('Usage: --install-iar --falcon-client-id --falcon-client-secret')
        exit()
