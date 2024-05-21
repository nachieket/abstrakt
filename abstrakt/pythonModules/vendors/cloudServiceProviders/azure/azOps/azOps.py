import subprocess
import threading

from abstrakt.pythonModules.pythonOps.customPrint.customPrint import printf


class AZOps:
  def __init__(self, logger):
    self.logger = logger

  @staticmethod
  def handle_device_azure_login():
    """Starts the device code login process and waits for completion."""

    process = subprocess.Popen(["az", "login", "--use-device-code"], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True)

    def monitor_output():
      while True:
        line = process.stdout.readline()
        if not line:
          break
        print(line.strip())  # Print instructions for user
        if "To sign in, use a web browser" in line:
          break

    threading.Thread(target=monitor_output).start()

    process.wait()  # Wait for the login process to complete

  def check_azure_login(self):
    """Checks if the user is logged in with 'az login'."""

    try:
      printf('Checking Azure login...\n')
      result = subprocess.run(["az", "account", "show"], capture_output=True, text=True)
      result.check_returncode()  # Raise an exception if the command fails
      printf('Azure is logged in\n')

      return
    except subprocess.CalledProcessError:
      try:
        printf('Azure is not logged in. Attempting login...\n')
        self.handle_device_azure_login()

        result = subprocess.run(["az", "account", "show"], capture_output=True, text=True)
        result.check_returncode()  # Raise an exception if the command fails
        printf('\nSuccessfully logged in to Azure CLI\n', logger=self.logger)
        return
      except Exception as e:
        print(f"Failed to login to Azure. Login manually with 'az login' and try again.{e}")
        exit()
