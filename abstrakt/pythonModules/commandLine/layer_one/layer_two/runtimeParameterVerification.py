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

    if install_falcon_sensor and (cluster_type == 'eks-managed-node' or cluster_type == 'azure-aks'):
      if (not kernel_mode and not ebpf_mode) or (not falcon_client_id or not falcon_client_secret):
        print('Error:')
        print('Usage: --install-falcon-sensor --kernel-mode --falcon-client-id --falcon-client-secret')
        print('OR')
        print('Usage: --install-falcon-sensor --ebpf-mode --falcon-client-id --falcon-client-secret')
        exit()
    elif install_falcon_sensor and (cluster_type == 'gke-standard' or cluster_type == 'gke-autopilot'):
      if not falcon_client_id or not falcon_client_secret:
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
              'Usage: abstrakt install crowdstrike --falcon-sensor --kernel-mode --aws-cluster-name eks-cluster '
              '--aws-region eu-west-2 --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s')
            print('OR')
            print(
              'Usage: abstrakt install crowdstrike --falcon-sensor --ebpf-mode --aws-cluster-name eks-cluster '
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
              'Usage: abstrakt install crowdstrike --falcon-sensor --kernel-mode --azure-cluster-name azure-cluster '
              '--azure-resource-group-name uksouth --falcon-client-id 3af74117 --falcon-client-secret vlTpn372s')
            print('OR')
            print(
              'Usage: abstrakt install crowdstrike --falcon-sensor --ebpf-mode --azure-cluster-name azure-cluster '
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
