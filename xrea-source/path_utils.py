"""Path helpers compatible with the Python 3.6 CGI runtime on XREA."""
import errno
from pathlib import Path


def is_relative_to(path, parent):
    """Return whether *path* is equal to or below *parent*."""
    try:
        Path(path).relative_to(Path(parent))
        return True
    except ValueError:
        return False


def unlink_missing_ok(path):
    """Unlink a path, matching Path.unlink(missing_ok=True) on Python 3.6."""
    try:
        Path(path).unlink()
    except OSError as error:
        if error.errno != errno.ENOENT:
            raise
