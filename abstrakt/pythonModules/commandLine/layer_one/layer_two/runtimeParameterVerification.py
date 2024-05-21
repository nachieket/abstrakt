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

  @staticmethod
  def verify_crowdstrike_sensor_parameters(falcon_sensor, kernel_mode, ebpf_mode, monitor_namespaces,
                                           exclude_namespaces, falcon_image_tag, proxy_server, proxy_port,
                                           falcon_sensor_tags, kpa, kac, iar, cloud_provider,
                                           cluster_type, cluster_name, cloud_region, azure_resource_group_name,
                                           gcp_project_name, falcon_client_secret, falcon_client_id,
                                           detections_container, vulnerable_apps):
    if falcon_sensor:
      if cluster_type:
        if cluster_type == 'eks-managed-node' or cluster_type == 'eks-self-managed-node':
          if (not kernel_mode and not ebpf_mode) or (not cloud_provider or not cluster_type or not cluster_name or not
                                                     cloud_region or not falcon_client_secret or not
                                                     falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --falcon-sensor --kernel-mode --cloud-provider aws --cluster-type '
              'eks-managed-node --cluster-name random_eks_cluster --cloud-region eu-west-2 --falcon-client-id 3af74117 '
              '--falcon-client-secret vlTpn372s ')
            print('OR')
            print(
              'Usage: abstrakt install crowdstrike --falcon-sensor --ebpf-mode --cloud-provider aws --cluster-type '
              'eks-managed-node --cluster-name random_eks_cluster --cloud-region eu-west-2 --falcon-client-id 3af74117 '
              '--falcon-client-secret vlTpn372s ')
            exit()
        elif cluster_type == 'aks':
          if ((not kernel_mode and not ebpf_mode) or (not cloud_provider or not cluster_name or not
                                                     azure_resource_group_name or not falcon_client_secret or not
                                                     falcon_client_id)):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --falcon-sensor --kernel-mode --cloud-provider azure --cluster-type '
              'aks --cluster-name random_aks_cluster --azure-resource-group-name random_azure_rg --falcon-client-id '
              '3af74117 --falcon-client-secret vlTpn372s ')
            print('OR')
            print(
              'Usage: abstrakt install crowdstrike --falcon-sensor --ebpf-mode --cloud-provider azure --cluster-type '
              'aks --cluster-name random_aks_cluster --azure-resource-group-name random_azure_rg --falcon-client-id '
              '3af74117 --falcon-client-secret vlTpn372s ')
            exit()
        elif cluster_type == 'gke-standard' or cluster_type == 'gke-autopilot':
          if (not cloud_provider or not cluster_name or not cloud_region or not gcp_project_name or not
             falcon_client_secret or not falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --falcon-sensor --cloud-provider gcp --cluster-type '
              'gke-standard --cluster-name random_gke_cluster --cloud-region us-central1-c --gcp-project-name xyz'                  
              '--falcon-client-id 3af74117 --falcon-client-secret vlTpn372s')
            exit()
      else:
        print('Error: use --help parameter to understand the right usage of interface.')
        exit()

    if kpa:
      if cluster_type:
        if cluster_type == 'eks-managed-node' or cluster_type == 'eks-self-managed-node':
          if (not cloud_provider or not cluster_type or not cluster_name or not cloud_region or not
             falcon_client_secret or not falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --kpa --cloud-provider aws --cluster-type '
              'eks-managed-node --cluster-name random_eks_cluster --cloud-region eu-west-2 --falcon-client-id 3af74117 '
              '--falcon-client-secret vlTpn372s ')
            exit()
        elif cluster_type == 'aks':
          if (not cloud_provider or not cluster_type or not cluster_name or not cloud_region or not
             falcon_client_secret or not falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --kpa --cloud-provider azure --cluster-type '
              'aks --cluster-name random_aks_cluster --azure-resource-group-name random_azure_rg --falcon-client-id '
              '3af74117 --falcon-client-secret vlTpn372s ')
        elif cluster_type == 'gke-standard' or cluster_type == 'gke-autopilot':
          if (not cloud_provider or not cluster_name or not cloud_region or not gcp_project_name or not
             falcon_client_secret or not falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --kac gcp --cluster-type '
              'gke-standard --cluster-name random_gke_cluster --cloud-region us-central1-c --gcp-project-name xyz'
              '--falcon-client-id 3af74117 --falcon-client-secret vlTpn372s')
            exit()
      else:
        print('Error: use --help parameter to understand the right usage of interface.')
        exit()

    if kac:
      if cluster_type:
        if cluster_type == 'eks-managed-node' or cluster_type == 'eks-self-managed-node':
          if (not cloud_provider or not cluster_type or not cluster_name or not cloud_region or not
             falcon_client_secret or not falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --kac --cloud-provider aws --cluster-type '
              'eks-managed-node --cluster-name random_eks_cluster --cloud-region eu-west-2 --falcon-client-id 3af74117 '
              '--falcon-client-secret vlTpn372s ')
            exit()
        elif cluster_type == 'aks':
          if (not cloud_provider or not cluster_type or not cluster_name or not cloud_region or not
             falcon_client_secret or not falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --kac --cloud-provider azure --cluster-type '
              'aks --cluster-name random_aks_cluster --azure-resource-group-name random_azure_rg --falcon-client-id '
              '3af74117 --falcon-client-secret vlTpn372s ')
        elif cluster_type == 'gke-standard' or cluster_type == 'gke-autopilot':
          if (not cloud_provider or not cluster_name or not cloud_region or not gcp_project_name or not
             falcon_client_secret or not falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --kac gcp --cluster-type '
              'gke-standard --cluster-name random_gke_cluster --cloud-region us-central1-c --gcp-project-name xyz'
              '--falcon-client-id 3af74117 --falcon-client-secret vlTpn372s')
            exit()
      else:
        print('Error: use --help parameter to understand the right usage of interface.')
        exit()

    if iar:
      if cluster_type:
        if cluster_type == 'eks-managed-node' or cluster_type == 'eks-self-managed-node':
          if (not cloud_provider or not cluster_type or not cluster_name or not cloud_region or not
             falcon_client_secret or not falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --iar --cloud-provider aws --cluster-type '
              'eks-managed-node --cluster-name random_eks_cluster --cloud-region eu-west-2 --falcon-client-id 3af74117 '
              '--falcon-client-secret vlTpn372s ')
            exit()
        elif cluster_type == 'aks':
          if (not cloud_provider or not cluster_type or not cluster_name or not cloud_region or not
             falcon_client_secret or not falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --iar --cloud-provider azure --cluster-type '
              'aks --cluster-name random_aks_cluster --azure-resource-group-name random_azure_rg --falcon-client-id '
              '3af74117 --falcon-client-secret vlTpn372s ')
        elif cluster_type == 'gke-standard' or cluster_type == 'gke-autopilot':
          if (not cloud_provider or not cluster_name or not cloud_region or not gcp_project_name or not
             falcon_client_secret or not falcon_client_id):
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --iar gcp --cluster-type '
              'gke-standard --cluster-name random_gke_cluster --cloud-region us-central1-c --gcp-project-name xyz'
              '--falcon-client-id 3af74117 --falcon-client-secret vlTpn372s')
            exit()
      else:
        print('Error: use --help parameter to understand the right usage of interface.')
        exit()

    if detections_container:
      if cluster_type:
        if cluster_type == 'eks-managed-node' or cluster_type == 'eks-self-managed-node':
          if not cloud_provider or not cluster_type or not cluster_name or not cloud_region:
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --detections-container --cloud-provider aws --cluster-type '
              'eks-managed-node --cluster-name random_eks_cluster --cloud-region eu-west-2 ')
            exit()
        elif cluster_type == 'aks':
          if not cloud_provider or not cluster_type or not cluster_name or not azure_resource_group_name:
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --detections-container --cloud-provider azure --cluster-type '
              'aks --cluster-name random_aks_cluster --azure-resource-group-name random_azure_rg ')
        elif cluster_type == 'gke-standard' or cluster_type == 'gke-autopilot':
          if not cloud_provider or not cluster_name or not cloud_region or not gcp_project_name:
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --detections-container gcp --cluster-type '
              'gke-standard --cluster-name random_gke_cluster --cloud-region us-central1-c --gcp-project-name xyz')
            exit()
      else:
        print('Error: use --help parameter to understand the right usage of interface.')
        exit()

    if vulnerable_apps:
      if cluster_type:
        if cluster_type == 'eks-managed-node' or cluster_type == 'eks-self-managed-node':
          if not cloud_provider or not cluster_type or not cluster_name or not cloud_region:
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --vulnerable-apps --cloud-provider aws --cluster-type '
              'eks-managed-node --cluster-name random_eks_cluster --cloud-region eu-west-2 ')
            exit()
        elif cluster_type == 'aks':
          if not cloud_provider or not cluster_type or not cluster_name or not azure_resource_group_name:
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --vulnerable-apps --cloud-provider azure --cluster-type '
              'aks --cluster-name random_aks_cluster --azure-resource-group-name random_azure_rg ')
        elif cluster_type == 'gke-standard' or cluster_type == 'gke-autopilot':
          if not cloud_provider or not cluster_name or not cloud_region or not gcp_project_name:
            print('Error:')
            print(
              'Usage: abstrakt install crowdstrike --vulnerable-apps gcp --cluster-type '
              'gke-standard --cluster-name random_gke_cluster --cloud-region us-central1-c --gcp-project-name xyz')
            exit()
      else:
        print('Error: use --help parameter to understand the right usage of interface.')
        exit()
