import subprocess


class GCPOps:
  def __init__(self, logger):
    self.logger = logger

  def check_gcloud_login(self) -> bool:
    """Checks if gcloud is logged in and prompts for login if needed."""
    print('Checking GCP login...\n')

    try:
      # Attempt to retrieve account information
      account = subprocess.check_output(["gcloud", "config", "get-value", "account"],
                                        stderr=subprocess.PIPE, text=True)
      if not account:
        print('You are not logged in to gcloud. Logging in...')
        subprocess.call(["gcloud", "auth", "login"])
      else:
        print(f"You are currently logged in to gcloud as: {account}")

      return True
    except subprocess.CalledProcessError as e:
      self.logger.error(e)
      return False
