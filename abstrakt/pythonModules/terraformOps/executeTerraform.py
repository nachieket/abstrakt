import subprocess
import threading
import re

from abstrakt.pythonModules.multiThread.multithreading import MultiThreading
from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf


class ExecuteTerraform:
  def __init__(self, logger):
    self.logger = logger

  @staticmethod
  def read_stream(stream, logger):
    ansi_escape_pattern = re.compile(r'\^\[\[[0-9;]*[m]')

    while True:
      line = stream.readline()
      if not line:
        break
      cleaned_line = re.sub(ansi_escape_pattern, '', line)
      logger.info(cleaned_line)

  def terraform_process_execution(self, command, path):
    try:
      process = subprocess.Popen(
        command,
        cwd=path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
      )

      # Create threads to read and log stdout and stderr in real-time
      stdout_thread = threading.Thread(target=self.read_stream, args=(process.stdout, self.logger))
      stderr_thread = threading.Thread(target=self.read_stream, args=(process.stderr, self.logger))

      stdout_thread.start()
      stderr_thread.start()

      # Wait for the command to complete
      process.wait()

      # Wait for the threads to finish
      stdout_thread.join()
      stderr_thread.join()

      if process.returncode == 0:
        return True
      else:
        return False
    except (subprocess.SubprocessError, Exception) as e:
      self.logger.info(e)
      return False

  def check_for_changes(self, command, path):
    try:
      # Run 'terraform plan' and capture the output
      process = subprocess.run(
        command,
        cwd=path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
      )

      # Log stdout and stderr
      if process.stdout:
        self.logger.info(process.stdout)
      if process.stderr:
        self.logger.info(process.stderr)

      # Check if 'terraform plan' failed
      if process.returncode != 0:
        printf("\nCommand 'terraform plan' failed\n", logger=self.logger)
        return 0

      # Search for 'No changes.' in the output
      if "No changes." in process.stdout:
        print('\nNo changes detected. Skipping apply', end='')
        return 2

      # Find the line containing "Plan:"
      plan_line = [line for line in process.stdout.split('\n') if "Plan:" in line]

      if plan_line:
        # Extract numbers from the plan_line
        to_add, to_change, to_destroy = [int(num) for num in plan_line[0].split() if num.isdigit()]
        self.logger.info(f'Terraform Plan - To Add: {to_add}, To Change: {to_change}, To Destroy: {to_destroy}')

        if to_add > 0 or to_change > 0 or to_destroy > 0:
          self.logger.info("Changes detected. Applying changes.")
          return 1

      self.logger.info('\nNo changes detected. Skipping apply')
      return 2
    except Exception as e:
      self.logger.error(f"An error occurred: {e}")
      return 0

  def execute_multi_thread(self, command, path):
    terraform_command = " ".join(command)

    with MultiThreading() as mt:
      printf(f'Executing {terraform_command}', logger=self.logger)

      if command[1] == 'plan':
        status = mt.run_with_progress_indicator(self.check_for_changes, 1, 1800, command, path)

        if status == 0:
          printf(f'{terraform_command} execution failed\n', logger=self.logger)
        else:
          printf(f'{terraform_command} successfully executed\n', logger=self.logger)

        return status
      else:
        if mt.run_with_progress_indicator(self.terraform_process_execution, 1, 1800, command, path):
          printf(f'{terraform_command} successfully executed\n', logger=self.logger)
          return True
        else:
          printf(f'{terraform_command} execution failed\n', logger=self.logger)
          return False

  def execute_terraform_get(self, path):
    command = ['terraform', 'get']

    return True if self.execute_multi_thread(command=command, path=path) else False

  def execute_terraform_init(self, path):
    command = ['terraform', 'init', '-input=false']

    return True if self.execute_multi_thread(command=command, path=path) else False

  def execute_terraform_plan(self, path):
    command = ['terraform', 'plan', '-var-file=variables.tfvars']

    return self.execute_multi_thread(command=command, path=path)

  def execute_terraform_apply(self, path):
    command = ['terraform', 'apply', '-var-file=variables.tfvars', '-auto-approve']

    return True if self.execute_multi_thread(command=command, path=path) else False

  def execute_terraform_destroy(self, path):
    command = ['terraform', 'destroy', '-var-file=variables.tfvars', '-auto-approve']

    return True if self.execute_multi_thread(command=command, path=path) else False
