import os
import re
import logging

log_dirs = ['/var/log/',
            '/var/log/crowdstrike',
            '/var/log/crowdstrike/aws',
            '/var/log/crowdstrike/aws/',
            '/var/log/crowdstrike/aws/',
            '/var/log/crowdstrike/azure',
            '/var/log/crowdstrike/gcp/',
            '/var/log/crowdstrike/sensors']

for log_dir in log_dirs:
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)


class AnsiEscapeFilter(logging.Filter):
  def filter(self, record):
    record.msg = re.sub(r'\x1B\[[0-9;]*[mK]', '', str(record.msg))
    return True


class CustomLogger:
  def __init__(self, logger_name, log_file, level=logging.INFO):
    self.logger = logging.getLogger(logger_name)

    # Check if handlers are already added
    if not self.logger.handlers:
      self.logger.setLevel(level)

      formatter = logging.Formatter('%(asctime)s [%(levelname)s]: %(message)s', datefmt='%d-%m-%Y %H:%M:%S')

      file_handler = logging.FileHandler(log_file)
      file_handler.setFormatter(formatter)

      # Add the ANSI escape code filter to remove them
      ansi_escape_filter = AnsiEscapeFilter()
      file_handler.addFilter(ansi_escape_filter)

      self.logger.addHandler(file_handler)

  def get_logger(self):
    return self.logger
