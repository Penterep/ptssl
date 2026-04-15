import sys
import threading

class ThreadLocalStdout:
    """
    A thread-local proxy for sys.stdout.

    This class wraps the real stdout and redirects write and flush calls
    to a thread-local buffer if set. Otherwise, it writes to the original stdout.

    Each thread can set its own buffer (e.g. io.StringIO) to capture output
    separately, allowing concurrent threads to redirect their print output
    without interfering with each other.

    Usage:
        1. Replace sys.stdout with an instance of this class.
        2. In each thread, call `set_thread_buffer(buffer)` before running code
           whose output you want to capture.
        3. After running, call `clear_thread_buffer()` to restore normal output.
        4. Access the captured output from the buffer.
    """

    def __init__(self, real_stdout):
        """
        Initialize with the real stdout stream.

        Args:
            real_stdout: The original sys.stdout to fall back to.
        """
        self.real_stdout = real_stdout
        self.local = threading.local()

    def activate(self):
        sys.stdout = self

    def set_thread_buffer(self, buffer):
        """
        Assign a buffer to capture output for the current thread.

        Args:
            buffer: A file-like object (e.g., io.StringIO) to redirect output into.
        """
        self.local.buffer = buffer

    def clear_thread_buffer(self):
        """
        Clear the thread-local buffer, restoring output to the original stdout.
        """
        self.local.buffer = None

    def write(self, data):
        """
        Write data to the thread-local buffer if set; otherwise write to real stdout.

        Args:
            data (str): Text to write.
        """
        if hasattr(self.local, "buffer") and self.local.buffer is not None:
            self.local.buffer.write(data)
        else:
            self.real_stdout.write(data)

    def flush(self):
        """
        Flush the thread-local buffer if set; otherwise flush the real stdout.
        """
        if hasattr(self.local, "buffer") and self.local.buffer is not None:
            self.local.buffer.flush()
        else:
            self.real_stdout.flush()
