import re
import sys
import time
import signal
import multiprocessing
import logging
from multiprocessing import Pool, Queue


class AnsiEscapeFilter(logging.Filter):
  def filter(self, record):
    record.msg = re.sub(r'\x1B\[[0-9;]*[mK]', '', str(record.msg))
    return True


class LoggerSetup:
  @staticmethod
  def get_logger(name, log_file, level=logging.INFO):
    logger = logging.getLogger(name)
    if not logger.handlers:
      logger.setLevel(level)

      handler = logging.FileHandler(log_file)
      formatter = logging.Formatter('%(asctime)s [%(levelname)s]: %(message)s', datefmt='%d-%m-%Y %H:%M:%S')
      handler.setFormatter(formatter)

      # Add the ANSI escape code filter to remove them
      ansi_escape_filter = AnsiEscapeFilter()
      handler.addFilter(ansi_escape_filter)

      logger.addHandler(handler)
    return logger


class LoggerContext:
  def __init__(self, name, log_file):
    self.name = name
    self.log_file = log_file
    self.logger = None

  def __enter__(self):
    self.logger = LoggerSetup.get_logger(self.name, self.log_file)
    return self.logger

  def __exit__(self, exc_type, exc_val, exc_tb):
    for handler in self.logger.handlers:
      handler.close()
      self.logger.removeHandler(handler)


def progress_indicator(hold):
  while True:
    sys.stdout.write('#')
    sys.stdout.flush()
    time.sleep(hold)


class TimeoutError(Exception):
  pass


def timeout_handler(signum, frame):
  raise TimeoutError("Function call timed out")


def wrapper_func(queue, func, logger_name, log_file, *args):
  with LoggerContext(logger_name, log_file) as logger:
    try:
      result = func(*args, logger)
      queue.put(('success', result))
    except Exception as e:
      logger.error(f"Error in child process: {str(e)}")
      queue.put(('error', str(e)))


class MultiProcessing:
  def __init__(self):
    self.pool = None

  def __enter__(self):
    self.pool = Pool(processes=1)
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    if self.pool:
      self.pool.terminate()
      self.pool.join()

  @staticmethod
  def get_logger_info(logger):
    logger_name = logger.name
    log_file = None

    for handler in logger.handlers:
      if isinstance(handler, logging.FileHandler):
        log_file = handler.baseFilename
        break

    return logger_name, log_file

  def execute_with_progress_indicator(self, func, logger, hold: float = 0.5, timeout=None, *args):
    logger_name, log_file = self.get_logger_info(logger)

    queue = Queue()
    indicator_process = multiprocessing.Process(target=progress_indicator, args=(hold,))
    process = multiprocessing.Process(target=wrapper_func, args=(queue, func, logger_name, log_file) + args)

    indicator_process.start()
    process.start()

    try:
      signal.signal(signal.SIGALRM, timeout_handler)
      signal.alarm(int(timeout) if timeout else 0)

      process.join()
      signal.alarm(0)  # Cancel the alarm

      if process.exitcode == 0:
        if not queue.empty():
          status, result = queue.get()
          if status == 'success':
            return result
          else:
            return f"Task failed with error: {result}"
        else:
          return "Task completed successfully but returned no result"
      else:
        return f"Task failed with exit code {process.exitcode}"

    except TimeoutError:
      with LoggerContext(logger_name, log_file) as logger:
        logger.error(' Timeout!')
      return "Timeout"
    finally:
      if process.is_alive():
        process.terminate()
        process.join(timeout=1)
        if process.is_alive():
          process.kill()
          process.join()

      indicator_process.terminate()
      indicator_process.join()
      print()  # New line after indicators

  @staticmethod
  def console(message):
    print(message, file=sys.__stdout__)
