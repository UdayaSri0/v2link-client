#!/usr/bin/env python3
"""Require an actual XCB window and 30 seconds of GUI process survival.

Run as an ordinary user under Xvfb. Never use offscreen as a substitute for xcb.
Diagnostics and the extracted payload's dependency audit are kept in --log-dir.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time


def smoke(image: Path, logs: Path, duration: int = 30) -> None:
    logs.mkdir(parents=True, exist_ok=True)
    image = image.resolve()
    env = dict(os.environ)
    # Isolate user data; do not inherit a developer's Qt paths or loader paths.
    for key in ("LD_LIBRARY_PATH", "LD_PRELOAD", "QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH", "PYTHONPATH", "QT_QPA_PLATFORMTHEME"):
        env.pop(key, None)
    with tempfile.TemporaryDirectory(prefix="v2link-smoke-") as temporary:
        work = Path(temporary)
        env.update(HOME=str(work), XDG_CONFIG_HOME=str(work / "config"),
                   XDG_DATA_HOME=str(work / "data"), XDG_CACHE_HOME=str(work / "cache"),
                   XDG_RUNTIME_DIR=str(work / "runtime"), QT_QPA_PLATFORM="xcb",
                   QT_DEBUG_PLUGINS="1", APPIMAGE_EXTRACT_AND_RUN="1")
        (work / "runtime").mkdir(mode=0o700)
        subprocess.run([str(image), "--appimage-extract"], cwd=work, env=env,
                       check=True, stdout=subprocess.DEVNULL, timeout=120)
        appdir = work / "squashfs-root"
        audit = Path(__file__).with_name("prepare_appdir.py")
        with (logs / "elf-audit.log").open("w") as output:
            subprocess.run(["python3", str(audit), str(appdir), "--check"],
                           env=env, check=True, stdout=output, stderr=subprocess.STDOUT, timeout=120)
        assets = appdir / "usr/bin/xray"
        for name in ("xray", "geoip.dat", "geosite.dat", "LICENSE", "VERSION"):
            if not (assets / name).is_file():
                raise RuntimeError(f"missing bundled Xray asset: {name}")
        xray_env = dict(env, XRAY_LOCATION_ASSET=str(assets))
        subprocess.run([str(assets / "xray"), "version"], env=xray_env, check=True, timeout=10)
        config = work / "xray.json"
        config.write_text('{"inbounds":[],"outbounds":[{"protocol":"freedom","settings":{}}]}')
        subprocess.run([str(assets / "xray"), "run", "-test", "-c", str(config)],
                       env=xray_env, check=True, timeout=15)
        with (logs / "qt-debug.log").open("w") as output:
            process = subprocess.Popen([str(image)], env=env, stdout=output,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            try:
                started = time.monotonic()
                found = False
                while time.monotonic() - started < duration:
                    if process.poll() is not None:
                        raise RuntimeError(f"GUI exited early with status {process.returncode}")
                    tree = subprocess.run(["xwininfo", "-root", "-tree"], env=env,
                                          text=True, capture_output=True, timeout=5)
                    (logs / "windows.log").write_text(tree.stdout + tree.stderr)
                    for window_id in re.findall(r'(0x[0-9a-f]+) "v2link-client v[^"\n]+"', tree.stdout):
                        info = subprocess.check_output(["xwininfo", "-id", window_id], env=env, text=True)
                        if "Map State: IsViewable" in info:
                            found = True
                    time.sleep(1)
                if not found:
                    raise RuntimeError("no visible v2link-client window appeared")
                output.flush()
                debug = (logs / "qt-debug.log").read_text()
                if not re.search(r'libqxcb\.so[^\n]*loaded library', debug):
                    raise RuntimeError("Qt did not report loading libqxcb.so")
                if any(message in debug for message in ("Could not load the Qt platform plugin", "cannot open shared object file", "QLibraryPrivate::loadPlugin failed")):
                    raise RuntimeError("Qt plugin/native dependency loading failed; see qt-debug.log")
                print(f"PASS: visible XCB window; process survived {duration}s; bundled Xray and ELF audit passed")
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--log-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        smoke(args.image, args.log_dir)
    except (RuntimeError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"Error: {exc}; diagnostics: {args.log_dir}\n")
