#!/usr/bin/env python3
"""Exercise the numeric launcher through a real pseudo-terminal."""

from __future__ import annotations

import errno
import fcntl
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import tempfile
import time
from pathlib import Path


TIMEOUT_SECONDS = 12.0


def _tail(data: bytearray, limit: int = 8000) -> str:
    return bytes(data[-limit:]).decode("utf-8", "backslashreplace")


def run_cli_case(
    name: str,
    binary: Path,
    arguments: tuple[str, ...],
    expected_code: int,
    stdout_contains: bytes = b"",
    stderr_contains: bytes = b"",
) -> None:
    result = subprocess.run(
        [str(binary), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5.0,
        check=False,
    )
    if result.returncode != expected_code:
        raise AssertionError(
            f"{name}: exit {result.returncode}, expected {expected_code}\n"
            f"stdout={result.stdout[-2000:]!r}\nstderr={result.stderr[-2000:]!r}"
        )
    if stdout_contains and stdout_contains not in result.stdout:
        raise AssertionError(f"{name}: stdout lacks {stdout_contains!r}")
    if stderr_contains and stderr_contains not in result.stderr:
        raise AssertionError(f"{name}: stderr lacks {stderr_contains!r}")


def run_case(
    name: str,
    binary: Path,
    steps: list[tuple[bytes, bytes | list[bytes] | tuple[int, int] | None]],
    allowed_codes: set[int] = {0},
    arguments: tuple[str, ...] = (),
    timeout_seconds: float = TIMEOUT_SECONDS,
) -> None:
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
    env = os.environ.copy()
    env.update({"TERM": "xterm-256color", "COLORTERM": "truecolor", "LANG": "C.UTF-8"})
    proc = subprocess.Popen(
        [str(binary), *arguments],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=env,
        close_fds=True,
        start_new_session=True,
    )
    os.close(slave)

    transcript = bytearray()
    cursor = 0
    deadline = time.monotonic() + timeout_seconds
    try:
        for needle, response in steps:
            while True:
                found = transcript.find(needle, cursor)
                if found >= 0:
                    cursor = found + len(needle)
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError(f"{name}: timed out waiting for {needle!r}")
                ready, _, _ = select.select([master], [], [], min(remaining, 0.25))
                if not ready:
                    if proc.poll() is not None:
                        raise AssertionError(
                            f"{name}: exited with {proc.returncode} before {needle!r}"
                        )
                    continue
                try:
                    chunk = os.read(master, 4096)
                except OSError as exc:
                    if exc.errno == errno.EIO and proc.poll() is not None:
                        raise AssertionError(
                            f"{name}: terminal closed before {needle!r}"
                        ) from exc
                    raise
                if not chunk:
                    raise AssertionError(f"{name}: terminal reached EOF before {needle!r}")
                transcript.extend(chunk)
            if response is not None:
                if isinstance(response, tuple):
                    rows, columns = response
                    fcntl.ioctl(
                        master,
                        termios.TIOCSWINSZ,
                        struct.pack("HHHH", rows, columns, 0, 0),
                    )
                    os.kill(proc.pid, signal.SIGWINCH)
                elif isinstance(response, list):
                    for fragment in response:
                        os.write(master, fragment)
                        time.sleep(0.005)
                else:
                    os.write(master, response)

        remaining = max(0.0, deadline - time.monotonic())
        try:
            code = proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise AssertionError(f"{name}: process did not exit after the scripted input") from exc
        if code not in allowed_codes:
            raise AssertionError(f"{name}: unexpected exit code {code}, expected {allowed_codes}")
    except Exception as exc:
        raise AssertionError(f"{exc}\n--- {name} transcript tail ---\n{_tail(transcript)}") from exc
    finally:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        os.close(master)


def main() -> int:
    live_scenario = len(sys.argv) >= 4 and sys.argv[1] == "--live-cf"
    binary_arg = sys.argv[2] if live_scenario else (sys.argv[1] if len(sys.argv) == 2 else "")
    if not binary_arg:
        print(
            f"usage: {Path(sys.argv[0]).name} /path/to/qanat\n"
            f"       {Path(sys.argv[0]).name} --live-cf /path/to/qanat [cf options]",
            file=sys.stderr,
        )
        return 2
    binary = Path(binary_arg).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        print(f"not an executable file: {binary}", file=sys.stderr)
        return 2

    if live_scenario:
        run_case(
            "live CF TUI verification and evidence pane",
            binary,
            [
                (b"\x1b[?1049h", None),
                (b"scan complete", b"\r"),
                (b"verified evidence", b"\rq"),
                (b"\x1b[?1049l", None),
            ],
            {0},
            tuple(sys.argv[3:]),
            60.0,
        )
        print("live CF TUI PTY test: ok")
        return 0

    run_cli_case("help", binary, ("--help",), 0, b"--export <fmt>")
    run_cli_case(
        "fingerprint diff preserves requested random profile",
        binary,
        ("fingerprint", "diff", "chrome", "random", "--seed", "7", "--sni", "example.com"),
        0,
        stdout_contains=b"right=random\n",
    )
    run_cli_case(
        "no launcher on redirected streams",
        binary,
        (),
        2,
        stderr_contains=b"USAGE",
    )
    run_cli_case(
        "mode-specific option rejection",
        binary,
        ("--ports", "127.0.0.1", "--ranges", "ranges.txt"),
        2,
        stderr_contains=b"Cloudflare-only option",
    )
    run_cli_case(
        "engine option rejection",
        binary,
        ("--net", "--workers", "1"),
        2,
        stderr_contains=b"scan-engine options",
    )
    run_cli_case(
        "orphan export path rejection",
        binary,
        ("--cf", "--export-file", "template.json"),
        2,
        stderr_contains=b"requires --export",
    )
    run_cli_case(
        "invalid SNI rejection",
        binary,
        ("--cf", "--sni", "bad..hostname"),
        2,
        stderr_contains=b"--sni must be",
    )
    run_cli_case(
        "colliding output rejection",
        binary,
        ("--cf", "--json", "same.out", "--csv", "same.out"),
        2,
        stderr_contains=b"paths must be distinct",
    )
    run_cli_case(
        "legacy and new scan scope conflict",
        binary,
        (
            "--cf",
            "--limit",
            "10",
            "--scan-mode",
            "reachable",
            "--reachable-target",
            "10",
        ),
        2,
        stderr_contains=b"--limit cannot be combined",
    )
    run_cli_case(
        "range overwrite rejection",
        binary,
        ("--cf", "--ranges", "same.out", "--json", "same.out"),
        2,
        stderr_contains=b"must not overwrite --ranges",
    )
    with tempfile.TemporaryDirectory(prefix="qanat-path-alias-") as temp_dir:
        first = Path(temp_dir, "first.out")
        second = Path(temp_dir, "second.out")
        first.write_text("existing\n", encoding="ascii")
        os.link(first, second)
        run_cli_case(
            "hard-linked output rejection",
            binary,
            (
                "--ports",
                "127.0.0.1",
                "-p",
                "1",
                "--json",
                str(first),
                "--csv",
                str(second),
            ),
            2,
            stderr_contains=b"paths must be distinct",
        )
        nested = Path(temp_dir, "nested")
        nested.mkdir()
        lexical = Path(temp_dir, "result.out")
        lexical_alias = nested / ".." / "result.out"
        run_cli_case(
            "nonexistent lexical output alias rejection",
            binary,
            (
                "--ports",
                "127.0.0.1",
                "-p",
                "1",
                "--json",
                str(lexical),
                "--csv",
                str(lexical_alias),
            ),
            2,
            stderr_contains=b"paths must be distinct",
        )

    run_case(
        "safe CDN defaults",
        binary,
        [
            (b"Select mode: ", b"1\n"),
            (b"Select action: ", b"2\n"),
            (b"Scan Plan settings", b"2\n"),
            (b"Preset                quick", None),
            (b"Percentage            1.0000%", None),
            (b"Finalist Count        64", b"0\n"),
            (b"Select setting: ", b"0\n"),
            (b"Select action: ", b"0\n"),
            (b"Select mode: ", b"0\n"),
        ],
    )
    run_case(
        "full sweep confirmation",
        binary,
        [
            (b"Select mode: ", b"1\n"),
            (b"Select action: ", b"2\n"),
            (b"Scan Plan settings", b"2\n"),
            (b"Select Scan Plan setting: ", b"1\n"),
            (b"Choice [1]: ", b"4\n"),
            (b"Scan Scope            full", b"0\n"),
            (b"Select setting: ", b"0\n"),
            (b"Select action: ", b"1\n"),
            (b"Full sweep is enabled.", None),
            (b"Enter 1 to continue or 0 to cancel: ", b"0\n"),
            (b"Select action: ", b"0\n"),
            (b"Select mode: ", b"0\n"),
        ],
    )
    run_case(
        "CDN protocol settings",
        binary,
        [
            (b"Select mode: ", b"1\n"),
            (b"Select action: ", b"2\n"),
            (b"Fingerprint           chrome", b"6\n"),
            (b"Choice [1]: ", b"2\n"),
            (b"Fingerprint           firefox", b"8\n"),
            (b"Idle hold (ms, 0 = off) [5000]: ", b"0\n"),
            (b"Idle hold             0 ms (off)", b"0\n"),
            (b"Select action: ", b"0\n"),
            (b"Select mode: ", b"0\n"),
        ],
    )
    run_case(
        "host settings",
        binary,
        [
            (b"Select mode: ", b"2\n"),
            (b"Select action: ", b"2\n"),
            (b"Host settings", None),
            (b"Target          (required)", None),
            (b"Select setting: ", b"0\n"),
            (b"Select action: ", b"0\n"),
            (b"Select mode: ", b"0\n"),
        ],
    )
    run_case(
        "network settings",
        binary,
        [
            (b"Select mode: ", b"3\n"),
            (b"Select action: ", b"2\n"),
            (b"Network settings", None),
            (b"Operation       network diagnostics", None),
            (b"Select setting: ", b"0\n"),
            (b"Select action: ", b"0\n"),
            (b"Select mode: ", b"0\n"),
        ],
    )
    run_case(
        "invalid numeric choice",
        binary,
        [
            (b"Select mode: ", b"999\n"),
            (b"Invalid choice. Enter a number from 0 to 3.", None),
            (b"Select mode: ", b"0\n"),
        ],
    )
    run_case(
        "CF Scan Plan keyboard and resize without starting",
        binary,
        [
            (b"\x1b[?1049h", None),
            (
                b"Scan Plan",
                [
                    b"\x1b", b"[", b"B", b"\x1b[B\x1b[B\x1b[B\x1b[B\x1b[B\x1b[B",
                    b"\x1b[200~65536\x1b[201~\r",
                ],
            ),
            (b"65536", (31, 66)),
            (b"Candidate Capacity", b"\x1b[B\x1b[200~1024\x1b[201~\r"),
            (b"1024", (10, 47)),
            (b"Terminal is", (31, 66)),
            (b"Finalist Count", b"q"),
            (b"\x1b[?1049l", None),
        ],
        {0},
        ("--cf",),
    )
    run_case(
        "CF compact Resource Plan cancels before probing",
        binary,
        [
            (b"\x1b[?1049h", (31, 66)),
            (b"Candidate Capacity", b"\x1b[F\r"),
            (b"Resource Plan - Confirm", None),
            (b"planned / unique", None),
            (b"candidate / finalist / output", None),
            (b"memory total / budget", None),
            (b"file descriptors", b"\x1bq"),
            (b"\x1b[?1049l", None),
        ],
        {130},
        ("--cf",),
    )

    if os.environ.get("QANAT_ALLOW_NETWORK_TESTS") == "1":
        run_case(
            "host auto mode and terminal restore",
            binary,
            [
                (b"Select mode: ", b"2\n"),
                (b"Select action: ", b"3\n"),
                (b"Host or IP: ", b"127.0.0.1\n"),
                (b"\x1b[?1049h", b"q"),
                (b"\x1b[?1049l", None),
            ],
            {0, 130},
        )

    print("menu PTY tests: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
