#!/usr/bin/env python3
"""Monitor an already installed APK; process survival is NOT gameplay validation.

Requires passwordless sudo for Waydroid. Does not install, download, clear app
data, or modify protection. Stops the test app after failure to avoid crash loops.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import time


def android(*args, check=True):
    return subprocess.run(['sudo', '-n', 'waydroid', 'shell', '--', *args],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=30, check=check)


def failure(pids):
    if not pids:
        return 'process not running'
    if any(not pid for pid in pids):
        return 'process disappeared during observation'
    if len(set(pids)) != 1:
        return 'process restarted during observation'
    return None


def smoke(args):
    root = args.output.resolve()
    root.mkdir()
    pids = []
    error = None
    try:
        android('am', 'force-stop', args.package)
        launch = android('am', 'start', '-W', '-n', args.component)
        (root / 'launch.txt').write_bytes(launch.stdout + launch.stderr)
        if not re.search(rb'^Status: ok\s*$', launch.stdout, re.MULTILINE):
            raise ValueError('activity launch did not report success')
        deadline = time.monotonic() + args.duration
        while True:
            pid = android('pidof', args.package, check=False).stdout.decode().strip()
            pids.append(pid)
            error = failure(pids)
            if error or time.monotonic() >= deadline:
                break
            time.sleep(min(1, max(0, deadline - time.monotonic())))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        error = str(exc)
    finally:
        # Collect exit reasons even if logcat's crash buffer is empty. Zygote
        # can report SIGSEGV while no debuggerd tombstone is generated.
        for name, command in (
            ('exit-info.txt', ('dumpsys', 'activity', 'exit-info', args.package)),
            ('logcat.txt', ('logcat', '-d')),
            ('crash-buffer.txt', ('logcat', '-d', '-b', 'crash')),
            ('screen.png', ('screencap', '-p')),
        ):
            try:
                result = android(*command, check=False)
                (root / name).write_bytes(result.stdout)
            except (OSError, subprocess.SubprocessError) as exc:
                (root / (name + '.error')).write_text(str(exc))
        if error:
            android('am', 'force-stop', args.package, check=False)
    result = {'package': args.package, 'status': 'FAILED' if error else 'process survival only',
              'error': error, 'observed_pids': pids, 'duration_requested': args.duration,
              'gameplay_validated': False}
    (root / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 1 if error else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', required=True)
    parser.add_argument('--component', required=True, help='PACKAGE/ACTIVITY to launch')
    parser.add_argument('--duration', type=int, default=30)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.duration < 1:
        parser.error('duration must be positive')
    if args.component.split('/')[0] != args.package:
        parser.error('component must belong to the package being monitored')
    try:
        parser.exit(smoke(args))
    except (OSError, subprocess.SubprocessError) as exc:
        parser.exit(1, 'error: ' + str(exc) + '\n')


if __name__ == '__main__':
    main()
