"""Linux process hardening and secret-buffer page protection."""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import resource
import signal
import threading


_PR_SET_DUMPABLE = 4
_PR_GET_DUMPABLE = 3
_MADV_DONTDUMP = 16
_LOCK = threading.RLock()
_ENABLED = False
_ORIGINAL_DUMPABLE: int | None = None
_ORIGINAL_CORE_LIMIT: tuple[int, int] | None = None
_WATCH_STOP: threading.Event | None = None
_WATCH_THREAD: threading.Thread | None = None
_LOCKED_BUFFERS: dict[int, tuple[bytearray, tuple[int, ...]]] = {}
_LOCKED_PAGES: dict[int, int] = {}
_LIBC = ctypes.CDLL(None, use_errno=True)
try:
    _EXPLICIT_BZERO = _LIBC.explicit_bzero
except AttributeError:
    _EXPLICIT_BZERO = None
else:
    _EXPLICIT_BZERO.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
    _EXPLICIT_BZERO.restype = None
if platform.system() == "Linux":
    _LIBC.prctl.argtypes = (
        ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong,
    )
    _LIBC.prctl.restype = ctypes.c_int
    _LIBC.mlock.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
    _LIBC.mlock.restype = ctypes.c_int
    _LIBC.munlock.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
    _LIBC.munlock.restype = ctypes.c_int
    _LIBC.madvise.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)
    _LIBC.madvise.restype = ctypes.c_int


def _check_linux() -> None:
    if platform.system() != "Linux":
        raise OSError(errno.ENOTSUP, "Memory guard is supported on Linux only")


def _prctl(option: int, argument: int = 0) -> int:
    result = _LIBC.prctl(option, argument, 0, 0, 0)
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def _tracer_pid() -> int:
    try:
        with open("/proc/self/status", "r", encoding="ascii") as status:
            for line in status:
                if line.startswith("TracerPid:"):
                    return int(line.split(":", 1)[1].strip())
    except (OSError, ValueError) as exc:
        raise OSError(errno.EIO, "Unable to inspect Linux TracerPid") from exc
    raise OSError(errno.EIO, "TracerPid is missing from /proc/self/status")


def _watch_for_tracer(stop_event: threading.Event) -> None:
    while not stop_event.wait(0.1):
        with _LOCK:
            if not _ENABLED:
                return
            try:
                attached_pid = _tracer_pid()
            except OSError:
                attached_pid = -1
            if attached_pid != 0:
                os.kill(os.getpid(), signal.SIGKILL)
                return


def set_enabled(enabled: bool) -> None:
    """Toggle dump/ptrace hardening and tracer monitoring for this process."""
    if not isinstance(enabled, bool):
        raise ValueError("Memory guard state must be a boolean")
    global _ENABLED, _ORIGINAL_CORE_LIMIT, _ORIGINAL_DUMPABLE
    global _WATCH_STOP, _WATCH_THREAD
    if not enabled and platform.system() != "Linux":
        return
    _check_linux()
    if enabled:
        with _LOCK:
            if _ENABLED:
                _prctl(_PR_SET_DUMPABLE, 0)
                current_limit = resource.getrlimit(resource.RLIMIT_CORE)
                resource.setrlimit(resource.RLIMIT_CORE, (0, current_limit[1]))
                return
            original_dumpable = _prctl(_PR_GET_DUMPABLE)
            original_core_limit = resource.getrlimit(resource.RLIMIT_CORE)
            resource.setrlimit(resource.RLIMIT_CORE, (0, original_core_limit[1]))
            try:
                _prctl(_PR_SET_DUMPABLE, 0)
            except OSError:
                try:
                    resource.setrlimit(resource.RLIMIT_CORE, original_core_limit)
                except (OSError, ValueError):
                    os.kill(os.getpid(), signal.SIGKILL)
                raise
            _ORIGINAL_DUMPABLE = original_dumpable
            _ORIGINAL_CORE_LIMIT = original_core_limit
            _ENABLED = True
            _WATCH_STOP = threading.Event()
            _WATCH_THREAD = threading.Thread(
                target=_watch_for_tracer,
                args=(_WATCH_STOP,),
                name="mk1-memory-guard",
                daemon=True,
            )
            try:
                _WATCH_THREAD.start()
            except RuntimeError:
                _ENABLED = False
                _WATCH_STOP = None
                _WATCH_THREAD = None
                try:
                    _prctl(_PR_SET_DUMPABLE, original_dumpable)
                    resource.setrlimit(resource.RLIMIT_CORE, original_core_limit)
                except (OSError, ValueError):
                    try:
                        resource.setrlimit(
                            resource.RLIMIT_CORE, (0, original_core_limit[1]),
                        )
                        _prctl(_PR_SET_DUMPABLE, 0)
                    except (OSError, ValueError):
                        os.kill(os.getpid(), signal.SIGKILL)
                raise
        return

    with _LOCK:
        if not _ENABLED:
            return
        try:
            if _ORIGINAL_DUMPABLE is not None:
                _prctl(_PR_SET_DUMPABLE, _ORIGINAL_DUMPABLE)
            if _ORIGINAL_CORE_LIMIT is not None:
                resource.setrlimit(resource.RLIMIT_CORE, _ORIGINAL_CORE_LIMIT)
        except (OSError, ValueError):
            try:
                current_limit = resource.getrlimit(resource.RLIMIT_CORE)
                resource.setrlimit(resource.RLIMIT_CORE, (0, current_limit[1]))
                _prctl(_PR_SET_DUMPABLE, 0)
            except (OSError, ValueError):
                os.kill(os.getpid(), signal.SIGKILL)
            raise
        _ENABLED = False
        stop_event, _WATCH_STOP = _WATCH_STOP, None
        thread, _WATCH_THREAD = _WATCH_THREAD, None
        _ORIGINAL_DUMPABLE = None
        _ORIGINAL_CORE_LIMIT = None
    if stop_event is not None:
        stop_event.set()
    if thread is not None and thread is not threading.current_thread():
        thread.join(timeout=1.0)
        if thread.is_alive():
            raise RuntimeError("Memory guard tracer monitor did not stop")


def is_enabled() -> bool:
    with _LOCK:
        return _ENABLED


def _buffer_pages(buffer: bytearray) -> tuple[int, ...]:
    if not buffer:
        return ()
    page_size = os.sysconf("SC_PAGE_SIZE")
    address = ctypes.addressof(ctypes.c_ubyte.from_buffer(buffer))
    start = address - address % page_size
    end = ((address + len(buffer) + page_size - 1) // page_size) * page_size
    return tuple(range(start, end, page_size))


def lock_buffer(buffer: bytearray) -> None:
    """Pin secret pages and exclude them from core dumps while the guard is on."""
    if not isinstance(buffer, bytearray):
        raise TypeError("Only mutable bytearray buffers can be locked")
    with _LOCK:
        if not _ENABLED or not buffer:
            return
        identity = id(buffer)
        if identity in _LOCKED_BUFFERS:
            return
        pages = _buffer_pages(buffer)
        for page in pages:
            references = _LOCKED_PAGES.get(page, 0)
            if references == 0:
                if _LIBC.mlock(page, os.sysconf("SC_PAGE_SIZE")) != 0:
                    error = ctypes.get_errno()
                    _release_pages(pages[:pages.index(page)])
                    raise OSError(error, os.strerror(error))
                if _LIBC.madvise(
                    page, os.sysconf("SC_PAGE_SIZE"), _MADV_DONTDUMP,
                ) != 0:
                    error = ctypes.get_errno()
                    unlock_error = 0
                    if _LIBC.munlock(page, os.sysconf("SC_PAGE_SIZE")) != 0:
                        unlock_error = ctypes.get_errno()
                    _release_pages(pages[:pages.index(page)])
                    if unlock_error:
                        raise OSError(unlock_error, os.strerror(unlock_error))
                    raise OSError(error, os.strerror(error))
            _LOCKED_PAGES[page] = references + 1
        _LOCKED_BUFFERS[identity] = (buffer, pages)


def _release_pages(pages: tuple[int, ...]) -> None:
    page_size = os.sysconf("SC_PAGE_SIZE")
    for page in pages:
        references = _LOCKED_PAGES.get(page, 0)
        if references <= 1:
            if _LIBC.munlock(page, page_size) != 0:
                error = ctypes.get_errno()
                raise OSError(error, os.strerror(error))
            _LOCKED_PAGES.pop(page, None)
        else:
            _LOCKED_PAGES[page] = references - 1


def unlock_buffer(buffer: bytearray) -> None:
    with _LOCK:
        locked = _LOCKED_BUFFERS.get(id(buffer))
        if locked is not None and locked[0] is buffer:
            _release_pages(locked[1])
            _LOCKED_BUFFERS.pop(id(buffer), None)


def wipe_buffer(buffer: bytearray) -> None:
    if not buffer:
        unlock_buffer(buffer)
        return
    try:
        if _EXPLICIT_BZERO is None:
            raise OSError(errno.ENOTSUP, "libc explicit_bzero is unavailable")
        address = ctypes.addressof(ctypes.c_ubyte.from_buffer(buffer))
        _EXPLICIT_BZERO(address, len(buffer))
    finally:
        unlock_buffer(buffer)


def protect_active_secret_buffers(buffers: tuple[bytearray, ...]) -> None:
    for buffer in buffers:
        lock_buffer(buffer)
