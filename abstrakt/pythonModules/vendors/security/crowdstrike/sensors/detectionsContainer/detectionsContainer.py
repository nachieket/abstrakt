import subprocess
from time import sleep

from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf
from abstrakt.pythonModules.kubernetesOps.containerOps import ContainerOps
from abstrakt.pythonModules.multiThread.multithreading import MultiThreading


class DetectionsContainer:
  def __init__(self, logger):
    self.logger = logger

  def deploy_detections_container(self, mode):
    printf(f"\n{'+' * 33}\nCrowdStrike Detections Container\n{'+' * 33}\n", logger=self.logger)

    printf('Installing Detections Container...', logger=self.logger)

    yaml_file = './abstrakt/conf/crowdstrike/detections-container/detections_container.yaml'
    kubectl_command: list = ["kubectl", "apply", "-f", yaml_file]

    self.logger.info(f'Executing command: {kubectl_command}')

    try:
      def thread():
        process = subprocess.run(kubectl_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)

        if process.stdout:
          self.logger.info(process.stdout)

        if process.stderr:
          self.logger.info(process.stderr)

      with MultiThreading() as mt:
        mt.run_with_progress_indicator(thread, 1)

      printf('Detections container installation successful\n', logger=self.logger)

      # print('Waiting for detections container pod to come up...')
      #
      # with MultiThreading() as mt:
      #   mt.run_with_progress_indicator(sleep, 1, 10)

      container = ContainerOps(logger=self.logger)

      if pod := container.pod_checker(pod_name='detections-container', namespace='crowdstrike-detections',
                                      kubeconfig_path='~/.kube/config'):
        printf('\nGenerating artificial detections...', logger=self.logger)
        printf('This may take a few minutes (normally, not more than five).', logger=self.logger)

        with MultiThreading() as mt:
          if mt.run_with_progress_indicator(self.generate_artificial_detections, 1, pod[0], mode):
            printf('Artificial detections generated successfully. Check them on your console in a few minutes.\n',
                   logger=self.logger)
        # if self.generate_artificial_detections(pod[0], mode):
        #   printf('Artificial detections generated successfully. Check them on your console in a few minutes.\n',
        #          logger=self.logger)
      else:
        print("Detections container not found. Artificial detections won't appear on your console.\n")
    except Exception as e:
      printf(f"Error deploying YAML from {yaml_file}: {e}", logger=self.logger)

  def generate_artificial_detections(self, detections_container, mode):
    for _ in range(0, 1):
      commands: list = [
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

      for command in commands:
        shell, script = command.split(' ')

        if mode == 'sidecar':
          kubectl_command: list = ["kubectl", "exec", "-it", detections_container, "-c", "detections-container", "-n",
                                   "crowdstrike-detections", "--", shell, script]

          self.logger.info(f'Executing command: {kubectl_command}')
        else:
          kubectl_command: list = ["kubectl", "exec", "-it", detections_container, "-n", "crowdstrike-detections",
                                   "--", shell, script]

          self.logger.info(f'Executing command: {kubectl_command}')

        try:
          # execute the kubectl exec command
          process = subprocess.run(kubectl_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                                   text=True)

          if process.stdout:
            self.logger.info(process.stdout)

          if process.stderr:
            self.logger.info(process.stderr)

          sleep(1)
        except Exception as e:
          self.logger.info(f"Error executing command {command}: {str(e)}")
      else:
        try:
          if mode == 'sidecar':
            kubectl_command: list = ["kubectl", "exec", "-it", detections_container, "-c", "detections-container", "-n",
                                     "crowdstrike-detections", "--", "/home/eval/bin/evil/Linux_Malware_High"]

            self.logger.info(f'Executing command: {kubectl_command}')
          else:
            kubectl_command: list = ["kubectl", "exec", "-it", detections_container, "-n", "crowdstrike-detections",
                                     "--", "/home/eval/bin/evil/Linux_Malware_High"]

            self.logger.info(f'Executing command: {kubectl_command}')

          process = subprocess.run(kubectl_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                                   text=True)

          if process.stdout:
            self.logger.info(process.stdout)

          if process.stderr:
            self.logger.info(process.stderr)

          sleep(1)
        except Exception as e:
          self.logger.info(f"Error executing command /home/eval/bin/evil/Linux_Malware_High: {str(e)}")
    else:
      return True

  # @staticmethod
  # def get_detections_container_name() -> str:
  #   # Define the kubectl command as a list of arguments
  #   kubectl_command: list = ["kubectl", "get", "pods", "-n", "crowdstrike-detections"]
  #
  #   # Run the kubectl command and capture its output
  #   try:
  #     process = subprocess.run(kubectl_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
  #
  #     # Check if the command was successful
  #     if process.returncode == 0:
  #       # Convert the stdout bytes to a string
  #       output: str = process.stdout.decode("utf-8")
  #
  #       # Split the lines of output
  #       lines: list = output.split("\n")
  #
  #       # Filter lines that start with "vulnerable.example.com"
  #       filtered_lines: list = [line for line in lines if line.startswith("detections-container")]
  #
  #       # Join the filtered lines back into a single string
  #       filtered_output: str = "\n".join(filtered_lines)
  #
  #       # print(filtered_output.split(' ')[0])
  #       return filtered_output.split(' ')[0]
  #     else:
  #       print(f"Error: {process.stderr.decode('utf-8')}")
  #       return 'None'
  #   except Exception as e:
  #     print(f"An error occurred: {str(e)}")
  #     return 'None'

  # def get_running_container_name(self, container_name, container_namespace):
  #   try:
  #     sensors = []
  #
  #     # Run the kubectl command to get pod names in the specified namespace
  #     cmd = (f"kubectl get pods -n {container_namespace} -o custom-columns=NAME:.metadata.name,"
  #            f"CONTAINERS:.spec.containers[*].name,STATUS:.status.phase --no-headers=true")
  #
  #     self.logger.info(f'Executing command: {cmd}')
  #
  #     output = subprocess.check_output(cmd, shell=True, stderr=subprocess.PIPE, text=True)
  #
  #     # Split the output into lines
  #     lines = output.strip().split('\n')
  #
  #     # Iterate through the lines and find the running container with a name
  #     for line in lines:
  #       parts = line.split()
  #       pod_name = parts[0]
  #
  #       cmd = (f"kubectl get pod {pod_name} -n {container_namespace} -o custom-columns=NAME:.metadata.name,"
  #              f"CONTAINERS:.spec.containers[*].name,STATUS:.status.phase --no-headers=true")
  #
  #       self.logger.info(f'Executing command: {cmd}')
  #
  #       counter = 0
  #
  #       while counter < 60:
  #         output = subprocess.check_output(cmd, shell=True, stderr=subprocess.PIPE, text=True).split()
  #
  #         self.logger.info(output)
  #
  #         if output[-1] == 'Running':
  #           sensors.append(output[0])
  #           break
  #         else:
  #           counter += 1
  #           sleep(5)
  #     else:
  #       return sensors if sensors else 'None'
  #   except subprocess.CalledProcessError as e:
  #     # Handle any errors that occur when running the kubectl command
  #     printf(f"Error running kubectl: {e}", logger=self.logger)
  #     return 'None'

  # def deploy_detections_container(self, mode='daemonset'):
  #   print('+' * 33, '\n', 'CrowdStrike Detections Container', '+' * 33, '\n')
  #
  #   printf('Installing Detections Container...\n', logger=self.logger)
  #
  #   yaml_file = './abstrakt/conf/crowdstrike/detections-container/detections_container.yaml'
  #   kubectl_command: list = ["kubectl", "apply", "-f", yaml_file]
  #
  #   self.logger.info(f'Executing command: {kubectl_command}')
  #
  #   try:
  #     process = subprocess.run(kubectl_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)
  #
  #     if process.stdout:
  #       self.logger.info(process.stdout)
  #
  #     if process.stderr:
  #       self.logger.info(process.stderr)
  #
  #     print('Checking detections container status...')
  #     container = ContainerOps(logger=self.logger)
  #     if pod := container.pod_checker(pod_name='detections-container', namespace='crowdstrike-detections',
  #                                     kubeconfig_path='~/.kube/config'):
  #       printf('Generating artificial detections...\n', logger=self.logger)
  #       printf('This may take a few minutes (normally, not more than five).\n', logger=self.logger)
  #
  #       if self.generate_artificial_detections(pod[0], mode):
  #         printf('Artificial detections generated successfully. Check them on your console in a few minutes.\n',
  #                logger=self.logger)
  #     else:
  #       print("Detections container not found. Artificial detections won't appear on your console.\n")
  #
  #     # printf('Trying to retrieve detections container name.\n', logger=self.logger)
  #     #
  #     # container = ContainerOps(logger=self.logger)
  #     # name = container.get_running_container_name('detections-container', 'crowdstrike-detections')[0]
  #     #
  #     # printf(f'Detections container name: {name}\n', logger=self.logger)
  #     #
  #     # if name != 'None':
  #     #   printf('Generating artificial detections...\n', logger=self.logger)
  #     #   printf('This may take a few minutes (normally, not more than five).\n', logger=self.logger)
  #     #
  #     #   if self.generate_artificial_detections(name, mode):
  #     #     printf('Artificial detections generated successfully. Check them on your console in a few minutes.\n',
  #     #            logger=self.logger)
  #     # else:
  #     #   printf("Detections container not found. Artificial detections won't appear on your console.\n",
  #     #          logger=self.logger)
  #   except Exception as e:
  #     printf(f"Error deploying YAML from {yaml_file}: {e}", logger=self.logger)
