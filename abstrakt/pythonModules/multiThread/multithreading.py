# import time
# import logging
# import multiprocessing
# from typing import Callable, Any
# from logging.handlers import QueueHandler
# from concurrent.futures import ThreadPoolExecutor, wait
#
#
# class MultiThreading:
#   def __init__(self):
#     self.pool = ThreadPoolExecutor(1)
#
#   def __enter__(self):
#     return self
#
#   def __exit__(self, exc_type, exc_value, traceback):
#     self.pool.shutdown(wait=True)
#
#   def run_with_progress_indicator(self, func: Callable, hold: int = 1, *args) -> Any:
#     future = self.pool.submit(func, *args)
#     try:
#       while not future.done():
#         print('#', end='', flush=True)
#         time.sleep(hold)
#       print(' ')
#       return future.result()
#     except Exception as e:
#       print(e)
#     finally:
#       # Ensure the future is done and any exceptions are raised
#       wait([future])
#
#   # @staticmethod
#   # def process_the_task(task: Callable, timeout: int, *args) -> bool:
#   #   process = multiprocessing.Process(target=task, args=(*args, ))
#   #   process.start()
#   #
#   #   try:
#   #     process.join(timeout=timeout)
#   #     if process.is_alive():
#   #       process.terminate()
#   #       process.join()
#   #       result = "Task timed out"
#   #     else:
#   #       result = "Task completed within timeout"
#   #   except Exception as e:
#   #     result = f"Error occurred: {str(e)}"
#   #
#   #   return True if result == "Task completed within timeout" else False
#
#   @staticmethod
#   def process_the_task(task: Callable, timeout: int, *args) -> Any:
#     def wrapper():
#       return task(*args)
#
#     process = multiprocessing.Process(target=wrapper)
#     process.start()
#     process.join(timeout=timeout)
#
#     if process.is_alive():
#       process.terminate()
#       process.join()
#       return None  # or some indicator of timeout
#
#     return process.exitcode == 0  # True if completed successfully

# import time
# import multiprocessing
# from typing import Callable, Any
# from concurrent.futures import ThreadPoolExecutor, wait
#
#
# class MultiThreading:
#     def __init__(self):
#         self.pool = multiprocessing.Pool(1)
#
#     def __enter__(self):
#         return self
#
#     def __exit__(self, exc_type, exc_value, traceback):
#         self.pool.close()
#         self.pool.join()
#
#     def run_with_progress_indicator(self, func: Callable, hold: int = 1, *args) -> Any:
#         async_result = self.pool.apply_async(func, args)
#         try:
#             while not async_result.ready():
#                 print('#', end='', flush=True)
#                 time.sleep(hold)
#             print(' ')
#             return async_result.get(timeout=1)  # Short timeout to check for exceptions
#         except Exception as e:
#             print(f"Error: {e}")
#             return None
#
#     @staticmethod
#     def process_the_task(task: Callable, timeout: int, *args) -> bool:
#         try:
#             with ThreadPoolExecutor(1) as executor:
#                 future = executor.submit(task, *args)
#                 result = future.result(timeout=timeout)
#             return True
#         except TimeoutError:
#             print("Task timed out")
#             return False
#         except Exception as e:
#             print(f"Error occurred: {str(e)}")
#             return False
#
# import time
# from typing import Callable, Any
# from concurrent.futures import ThreadPoolExecutor
#
#
# class MultiThreading:
#     def __init__(self):
#         self.pool = ThreadPoolExecutor(1)
#
#     def __enter__(self):
#         return self
#
#     def __exit__(self, exc_type, exc_value, traceback):
#         self.pool.shutdown(wait=True)
#
#     def run_with_progress_indicator(self, func: Callable, hold: int = 1, *args) -> Any:
#         future = self.pool.submit(func, *args)
#         try:
#             while not future.done():
#                 print('#', end='', flush=True)
#                 time.sleep(hold)
#             print(' ')
#             return future.result()
#         except Exception as e:
#             print(f"Error: {e}")
#             return None
#
#     @staticmethod
#     def process_the_task(task: Callable, timeout: int, *args) -> Any:
#         try:
#             with ThreadPoolExecutor(1) as executor:
#                 future = executor.submit(task, *args)
#                 return future.result(timeout=timeout)
#         except TimeoutError:
#             print("Task timed out")
#             return None
#         except Exception as e:
#             print(f"Error occurred: {str(e)}")
#             return None

# Original ##

from concurrent.futures import ThreadPoolExecutor
from time import sleep


class MultiThreading:
  """
  MultiThreading Class
  """

  def __init__(self):
    self.pool = ThreadPoolExecutor(1)

  def __enter__(self):
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    self.pool.shutdown(wait=True)

  def run_with_progress_indicator(self, func, hold=1, *args):
    """
    Method to display # while the method or function is running
    """

    future = self.pool.submit(func, *args)

    while not future.done():
      print('#', end='', flush=True)
      sleep(hold)
    else:
      print(' ')
      result = future.result()

    return result
