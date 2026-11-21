"""Isolated worker pool for parsing untrusted files.

Each worker is a long-lived child process. Per task the parent enforces a wall-clock
timeout; a worker that overruns is killed and replaced. On Windows every worker is placed
in a Job Object with a per-process memory limit (and kill-on-close), so a pathological file
that tries to exhaust memory is terminated by the OS. A crash or kill never affects the
parent (the UI server / scan service): the caller receives an ExtractionFailure instead.

Only static parsing runs in workers. Nothing is ever executed from the inspected file.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import queue
import sys
import threading
import time
from dataclasses import dataclass
from multiprocessing.connection import Connection
from typing import Any, Callable, Dict, List, Optional

DEFAULT_TIMEOUT_S = 15.0
DEFAULT_MEMORY_LIMIT_MB = 1024
RECYCLE_AFTER_TASKS = 500


@dataclass
class ExtractionFailure:
    """Returned instead of a result when isolation stopped the task."""
    reason: str          # "timeout" | "crashed" | "memory_limit" | "error"
    detail: str


# ------------------------------------------------------------------ tasks (run in the child)

def _task_legacy_features(path: str):
    from threatweaver.scanner.feature_extractor import FeatureExtractor
    return FeatureExtractor().extract_from_file(path)


def _task_ember_v3_vector(path: str):
    from threatweaver.scanner.ember_v3 import get_extractor
    return get_extractor().vector_from_file(path)


def _task_v3_with_indicators(path: str):
    """One parse for the v2 path: thrember raw features -> (EMBER v3 vector, static indicators)."""
    from threatweaver.detectors.indicators import as_dicts, indicators_from_raw
    from threatweaver.scanner.ember_v3 import get_extractor

    ext = get_extractor()
    try:
        bytez = ext.read_bytes(path)
    except ValueError as e:  # size limit
        return {"is_pe": False, "error": str(e), "indicators": [], "vector": None}
    if bytez[:2] != b"MZ":
        return {"is_pe": False, "error": "missing MZ header", "indicators": [], "vector": None}
    raw = ext.raw_from_bytes(bytez)
    if not (raw.get("general") or {}).get("is_pe"):
        return {"is_pe": False, "error": "PE headers could not be parsed", "indicators": [], "vector": None}
    return {"is_pe": True, "error": None, "vector": ext.vector_from_raw(raw),
            "indicators": as_dicts(indicators_from_raw(raw))}


def _diag_sleep(seconds: str):
    time.sleep(float(seconds))
    return "slept"


def _diag_crash(_: str):
    os._exit(3)


def _diag_alloc(megabytes: str):
    blocks = [bytearray(1024 * 1024) for _ in range(int(megabytes))]
    return len(blocks)


TASKS: Dict[str, Callable[[str], Any]] = {
    "legacy_features": _task_legacy_features,
    "ember_v3_vector": _task_ember_v3_vector,
    "v3_with_indicators": _task_v3_with_indicators,
}
DIAGNOSTIC_TASKS: Dict[str, Callable[[str], Any]] = {
    "_sleep": _diag_sleep,
    "_crash": _diag_crash,
    "_alloc": _diag_alloc,
}


def _worker_main(conn: Connection, allow_diagnostics: bool) -> None:
    registry = dict(TASKS)
    if allow_diagnostics:
        registry.update(DIAGNOSTIC_TASKS)
    while True:
        try:
            msg = conn.recv()
        except (EOFError, OSError):
            return
        if msg is None:
            return
        name, arg = msg
        try:
            fn = registry[name]
            conn.send(("ok", fn(arg)))
        except MemoryError:
            conn.send(("memory_limit", "MemoryError while parsing"))
        except BaseException as e:  # noqa: BLE001 - report every failure to the parent
            conn.send(("error", f"{type(e).__name__}: {e}"))


# ------------------------------------------------------------------ Windows Job Object

def _apply_job_limits(pid: int, memory_limit_mb: int):
    """Places a process in a Job Object with a per-process memory cap. Returns the job handle."""
    if sys.platform != "win32" or memory_limit_mb <= 0:
        return None
    import ctypes
    from ctypes import wintypes

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class BASIC_LIMIT(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD),
        ]

    class EXTENDED_LIMIT(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BASIC_LIMIT), ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x100
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    JobObjectExtendedLimitInformation = 9
    PROCESS_SET_QUOTA, PROCESS_TERMINATE = 0x0100, 0x0001

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.OpenProcess.restype = wintypes.HANDLE
    job = k32.CreateJobObjectW(None, None)
    if not job:
        return None
    info = EXTENDED_LIMIT()
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    info.ProcessMemoryLimit = memory_limit_mb * 1024 * 1024
    if not k32.SetInformationJobObject(wintypes.HANDLE(job), JobObjectExtendedLimitInformation,
                                       ctypes.byref(info), ctypes.sizeof(info)):
        k32.CloseHandle(wintypes.HANDLE(job))
        return None
    hproc = k32.OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, pid)
    if hproc:
        k32.AssignProcessToJobObject(wintypes.HANDLE(job), wintypes.HANDLE(hproc))
        k32.CloseHandle(wintypes.HANDLE(hproc))
    return job


def _close_job(job) -> None:
    if job is None or sys.platform != "win32":
        return
    import ctypes
    from ctypes import wintypes
    ctypes.WinDLL("kernel32").CloseHandle(wintypes.HANDLE(job))


# ------------------------------------------------------------------ parent side

# Workers run single-threaded: parallelism comes from the pool, and BLAS/OpenMP thread pools
# would otherwise reserve per-core buffers at import time (enough to exceed the memory cap).
WORKER_ENV = {
    "OPENBLAS_NUM_THREADS": "1",
    "OMP_NUM_THREADS": "1",
    "MKL_NUM_THREADS": "1",
    "NUMEXPR_NUM_THREADS": "1",
}
_env_lock = threading.Lock()


class _Worker:
    def __init__(self, ctx, memory_limit_mb: int, allow_diagnostics: bool):
        parent, child = ctx.Pipe(duplex=True)
        self.proc = ctx.Process(target=_worker_main, args=(child, allow_diagnostics), daemon=True)
        with _env_lock:  # the child inherits the environment at creation time
            saved = {k: os.environ.get(k) for k in WORKER_ENV}
            os.environ.update(WORKER_ENV)
            try:
                self.proc.start()
            finally:
                for k, v in saved.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
        child.close()
        self.conn = parent
        self.tasks_done = 0
        self.job = _apply_job_limits(self.proc.pid, memory_limit_mb)

    def kill(self) -> None:
        try:
            if self.proc.is_alive():
                self.proc.kill()
            self.proc.join(timeout=5)
        finally:
            try:
                self.conn.close()
            except OSError:
                pass
            _close_job(self.job)

    def stop(self) -> None:
        try:
            self.conn.send(None)
            self.proc.join(timeout=2)
        except (OSError, BrokenPipeError):
            pass
        self.kill()


class ExtractionPool:
    """Thread-safe pool of isolated parsing workers (lazy start)."""

    def __init__(
        self,
        workers: int = 2,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        memory_limit_mb: int = DEFAULT_MEMORY_LIMIT_MB,
        allow_diagnostics: bool = False,
    ):
        self.size = max(1, workers)
        self.timeout_s = timeout_s
        self.memory_limit_mb = memory_limit_mb
        self.allow_diagnostics = allow_diagnostics
        self._ctx = mp.get_context("spawn")
        self._idle: "queue.Queue[_Worker]" = queue.Queue()
        self._all: List[_Worker] = []
        self._lock = threading.Lock()
        self._started = False
        self._closed = False
        self.stats = {"tasks": 0, "timeouts": 0, "crashes": 0, "memory_kills": 0, "errors": 0}

    def _spawn(self) -> _Worker:
        w = _Worker(self._ctx, self.memory_limit_mb, self.allow_diagnostics)
        with self._lock:
            self._all.append(w)
        return w

    def _ensure_started(self) -> None:
        with self._lock:
            if self._started:
                return
            if self._closed:
                raise RuntimeError("ExtractionPool is closed")
            self._started = True
        for _ in range(self.size):
            self._idle.put(self._spawn())

    def _replace(self, w: _Worker) -> None:
        w.kill()
        with self._lock:
            if w in self._all:
                self._all.remove(w)
        if not self._closed:
            self._idle.put(self._spawn())

    def run(self, task: str, arg: str, timeout_s: Optional[float] = None) -> Any:
        """Runs a named task in an isolated worker. Returns its result or an ExtractionFailure."""
        self._ensure_started()
        timeout = self.timeout_s if timeout_s is None else timeout_s
        w = self._idle.get()
        self.stats["tasks"] += 1
        try:
            w.conn.send((task, arg))
            if not w.conn.poll(timeout):
                self.stats["timeouts"] += 1
                self._replace(w)
                return ExtractionFailure("timeout", f"Parsing exceeded {timeout:.0f}s and was stopped")
            status, payload = w.conn.recv()
        except (EOFError, OSError, BrokenPipeError):
            code = w.proc.exitcode
            w.proc.join(timeout=2)
            code = w.proc.exitcode if code is None else code
            mem_kill = sys.platform == "win32" and self.memory_limit_mb > 0 and code not in (None, 3)
            self.stats["memory_kills" if mem_kill else "crashes"] += 1
            self._replace(w)
            if mem_kill:
                return ExtractionFailure("memory_limit",
                                         f"Worker stopped by the {self.memory_limit_mb} MB memory limit (exit code {code})")
            return ExtractionFailure("crashed", f"Parsing worker exited unexpectedly (exit code {code})")

        w.tasks_done += 1
        if w.tasks_done >= RECYCLE_AFTER_TASKS:
            self._replace(w)
        else:
            self._idle.put(w)
        if status == "ok":
            return payload
        self.stats["memory_kills" if status == "memory_limit" else "errors"] += 1
        return ExtractionFailure(status, str(payload))

    def close(self) -> None:
        with self._lock:
            self._closed = True
            workers = list(self._all)
            self._all.clear()
        for w in workers:
            w.stop()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
