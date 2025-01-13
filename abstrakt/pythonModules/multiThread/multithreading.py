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

    def run_with_progress_indicator(self, func, hold=1, timeout=1800, *args):
        """
        Method to display # while the method or function is running
        """

        counter = 0
        future = self.pool.submit(func, *args)

        while not future.done() and counter < timeout:
            print('#', end='', flush=True)
            counter += 1
            sleep(hold)
        else:
            print(' ')
            result = future.result()

        return result
