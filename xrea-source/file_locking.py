"""Process-wide advisory file locking on Linux and Windows.

Linux deployments use the native flock implementation unchanged. Windows uses
an actual OS byte-range lock on a dedicated lock file, not a no-op shim.
"""
import errno
import os
import time

try:
    import fcntl as fcntl
except ImportError:
    if os.name != 'nt':
        raise
    import msvcrt

    class _WindowsFcntl:
        LOCK_SH=1
        LOCK_EX=2
        LOCK_NB=4
        LOCK_UN=8

        @staticmethod
        def flock(file, operation):
            fd=file.fileno() if hasattr(file,'fileno') else int(file)
            position=os.lseek(fd,0,os.SEEK_CUR)
            try:
                os.lseek(fd,0,os.SEEK_SET)
                if operation & _WindowsFcntl.LOCK_UN:
                    try:
                        msvcrt.locking(fd,msvcrt.LK_UNLCK,1)
                    except OSError as error:
                        if error.errno not in (errno.EACCES,errno.EINVAL):
                            raise
                    return
                mode=msvcrt.LK_NBLCK if operation & _WindowsFcntl.LOCK_EX else msvcrt.LK_NBRLCK
                while True:
                    try:
                        msvcrt.locking(fd,mode,1)
                        return
                    except OSError as error:
                        if error.errno not in (errno.EACCES,errno.EAGAIN,errno.EDEADLK):
                            raise
                        if operation & _WindowsFcntl.LOCK_NB:
                            raise BlockingIOError(errno.EAGAIN,'Resource temporarily unavailable') from error
                        time.sleep(.05)
            finally:
                os.lseek(fd,position,os.SEEK_SET)

    fcntl=_WindowsFcntl()
