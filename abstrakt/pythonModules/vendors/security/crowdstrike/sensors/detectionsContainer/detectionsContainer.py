import subprocess

from abstrakt.pythonModules.kubernetesOps.kubectlOps import KubectlOps
from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading


class DetectionsContainer:
  def __init__(self, logger):
    self.logger = logger

  def execute_command(self, command):
    self.logger.info(f'Executing command: {command}')

    try:
      process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)

      if process.stdout:
        self.logger.info(process.stdout)

      if process.stderr:
        self.logger.info(process.stderr)
    except Exception as e:
      self.logger.error(f'Error {e} executing command {command}')

  def deploy_detections_containers(self, cluster_type, mode):
    print(f"\n{'+' * 33}\nCrowdStrike Detections Containers\n{'+' * 33}\n")

    print('Installing Detections Containers...')

    k8s = KubectlOps(logger=self.logger)

    if k8s.namespace_exists(namespace_name='crowdstrike-detections'):
      captured_pods, status = k8s.find_pods_with_status(pod_string='detections-container',
                                                        namespace='crowdstrike-detections')

      if (status is True) and (len(captured_pods['running']) > 0):
        print('Detections container found up and running in crowdstrike-detections namespace. Not proceeding with '
              'installation.')

        for pod in captured_pods['running']:
          print(pod)

        print()
        return

    path = './abstrakt/conf/crowdstrike/detections-container/'

    detections_containers = [f'{path}crowdstrike-detections.yaml', f'{path}detections-container.yaml',
                             f'{path}vulnerable-app.yaml', f'{path}generic-tools.yaml']

    try:
      def thread():
        for container_yaml in detections_containers:
          command = ['kubectl', 'apply', '-f', container_yaml]

          self.logger.info(f'Executing command: {command}')

          process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)

          if process.stdout:
            self.logger.info(process.stdout)

          if process.stderr:
            self.logger.info(process.stderr)

      with MultiThreading() as mt:
        mt.run_with_progress_indicator(thread, 1)

      printf('All Detections containers installation successful\n', logger=self.logger)

      container = ContainerOps(logger=self.logger)

      detections_containers = ['detections-container', 'vulnerable.example.com', 'generic-tools']
      pods: dict = {}

      for detections_container in detections_containers:
        pods[detections_container] = container.pod_checker(pod_name=detections_container,
                                                           namespace='crowdstrike-detections',
                                                           kubeconfig_path='~/.kube/config')
        print()

      print('Retrieving ip address of vulnerable app service object...\n')

      service_ip_address, service_port = container.get_service_ip_address(service_name='vulnerable-example-com',
                                                                          namespace='crowdstrike-detections')

      print('Generating artificial detections...')
      print('This may take a few minutes.')

      if pods['detections-container'][0] and pods['vulnerable.example.com'][0] and pods['generic-tools'][0]:
        with MultiThreading() as mt:
          mt.run_with_progress_indicator(self.generate_artificial_detections, 1, cluster_type, service_ip_address,
                                         service_port, pods['generic-tools'][0], pods['detections-container'][0], mode)

          print('Artificial detections generated successfully. Check them on your console in a few minutes.')

          if pods['detections-container'][0]:
            print('Detections container will randomly generate artificial detections until it is taken down.\n')
      else:
        if pods['detections-container'][0]:
          print("Vulnerable container not found, but detections container was found. Artificial detections will not "
                "immediately appear on the console, but will randomly appear later.\n")
        else:
          print('Neither vulnerable container nor detections container found. Artificial detections will not appear '
                'on the console.\n')
    except Exception as e:
      self.logger.error(f'Error: {e}')

  def generate_sh_detections(self, detections_container):
    sh_commands: list = [
      "sh /home/eval/bin/Collection_via_Automated_Collection.sh",
      "sh /home/eval/bin/Command_Control_via_Remote_Access-obfuscated.sh",
      "sh /home/eval/bin/Command_Control_via_Remote_Access.sh",
      "sh /home/eval/bin/ContainerDrift_Via_File_Creation_and_Execution.sh",
      "sh /home/eval/bin/Credential_Access_via_Credential_Dumping.sh",
      "sh /home/eval/bin/Defense_Evasion_via_Masquerading.sh",
      "sh /home/eval/bin/Defense_Evasion_via_Rootkit.sh",
      "sh /home/eval/bin/Execution_via_Command-Line_Interface.sh",
      "sh /home/eval/bin/Exfiltration_via_Exfiltration_Over_Alternative_Protocol.sh",
      "sh /home/eval/bin/Persistence_via_External_Remote_Services.sh",
      "sh /home/eval/bin/Reverse_Shell_Trojan.sh",
      "sh /home/eval/bin/Webserver_Bash_Reverse_Shell.sh",
      "sh /home/eval/bin/Webserver_Suspicious_Terminal_Spawn.sh",
      "sh /home/eval/bin/Webserver_Unexpected_Child_of_Web_Service.sh",
      "sh /home/eval/bin/mimipenguin/mimipenguin.sh"
    ]

    for command in sh_commands:
      shell, script = command.split(' ')

      kubectl_command: list = ["kubectl", "exec", "-it", detections_container, "-n", "crowdstrike-detections",
                               "--", shell, script]

      self.execute_command(command=kubectl_command)

  def generate_curl_detections(self, service_ip_address, service_port, execution_container, mode):
    curl_commands: list = [
      f'curl http://{service_ip_address}:{service_port}/ps',
      f'curl http://{service_ip_address}:{service_port}/rootkit',
      f'curl http://{service_ip_address}:{service_port}/masquerading',
      f'curl http://{service_ip_address}:{service_port}/data_exfiltration',
      f'curl http://{service_ip_address}:{service_port}/deploy_malware',
      f'curl http://{service_ip_address}:{service_port}/reverse_shell',
      f'curl http://{service_ip_address}:{service_port}/reverse_shell-obfuscated',
      f'curl http://{service_ip_address}:{service_port}/credentials_dumping',
      f'curl http://{service_ip_address}:{service_port}/credentials_dumping_collection',
      f'curl http://{service_ip_address}:{service_port}/suspicious_commands',
      f'curl http://{service_ip_address}:{service_port}/container_drift'
    ]

    for command in curl_commands:
      shell, script = command.split(' ')

      if mode == 'sidecar':
        kubectl_command: list = ["kubectl", "exec", "-it", execution_container, "-c", "generic-tools", "-n",
                                 "crowdstrike-detections", "--", shell, script]
      else:
        kubectl_command: list = ["kubectl", "exec", "-it", execution_container, "-n", "crowdstrike-detections",
                                 "--", shell, script]

      self.execute_command(command=kubectl_command)

  def generate_artificial_detections(self, cluster_type, service_ip_address, service_port, execution_container,
                                     detections_container, mode):
    if cluster_type == 'eks-fargate':
      self.generate_curl_detections(service_ip_address=service_ip_address, service_port=service_port,
                                    execution_container=execution_container, mode=mode)
    else:
      self.generate_curl_detections(service_ip_address=service_ip_address, service_port=service_port,
                                    execution_container=execution_container, mode=mode)
      self.generate_sh_detections(detections_container=detections_container)
