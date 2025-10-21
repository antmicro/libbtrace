# Copyright (c) 2025 Analog Devices, Inc.
# Copyright (c) 2025 Antmicro <www.antmicro.com>
#
# SPDX-License-Identifier: Apache-2.0

import contextlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

from setuptools.command.build import build as _build

dummy_ext_path = Path.cwd() / "bt2" / "dummy_ext.c"
dummy_ext_path.parent.mkdir(parents=True, exist_ok=True)
dummy_ext_path.touch()


@contextlib.contextmanager
def new_wd(path):
    cur = Path.cwd()

    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(cur)


def bt_build(src_dir, build_dir):
    configure_path = Path(src_dir) / "configure"
    with new_wd(build_dir):
        subprocess.run(
            f"{configure_path} --prefix {build_dir} --disable-debug-info "
            "--enable-python-bindings --disable-man-pages",
            shell=True,
            check=True,
        )
        subprocess.run("make -j`nproc`", shell=True, check=True)
        subprocess.run("make install-strip", shell=True, check=True)


def bt_patch_lib(path):
    if sys.platform == "darwin":
        res = subprocess.run(f"otool -L {path}", shell=True, check=True, capture_output=True)
        lines = res.stdout.decode().splitlines()
        bt2_path = next(
            (
                x.strip().rpartition(" (compatibility version")[0]
                for x in lines
                if "libbabeltrace2.0.dylib" in x
            ),
            None,
        )
        if bt2_path is not None:
            subprocess.run(
                f"install_name_tool -change {bt2_path} @loader_path/libbabeltrace2.0.dylib {path}",
                shell=True,
                check=True,
            )
    else:
        subprocess.run(f"patchelf --set-rpath '$ORIGIN' {path}", shell=True, check=True)
        subprocess.run(
            f"patchelf --replace-needed libbabeltrace2.so.0 libbabeltrace2.so {path}",
            shell=True,
            check=True,
        )


def bt_get_plugin_paths(build_dir):
    paths: list[Path] = []
    for plugin in ["ctf", "text", "utils"]:
        paths.append(
            build_dir / "lib" / "babeltrace2" / "plugins" / f"babeltrace-plugin-{plugin}.so"
        )
    return paths


def bt_get_babeltrace2_path(build_dir):
    if sys.platform == "darwin":
        return build_dir / "lib" / "libbabeltrace2.0.dylib"
    else:
        return build_dir / "lib" / "libbabeltrace2.so"


def bt_get_bindings_paths(build_dir):
    bindings_dir = (
        build_dir
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
        / "bt2"
    )
    return bindings_dir.iterdir()


class build(_build):
    def run(self):
        src_dir = Path().cwd().resolve()
        build_dir = (Path(self.build_temp) / "bt_build").resolve()
        build_dir.mkdir(parents=True, exist_ok=True)

        subprocess.run("./bootstrap", shell=True, check=True)
        bt_build(src_dir, build_dir)

        bt2_dir = (Path(self.build_lib) / "bt2").resolve()
        bt2_dir.mkdir(parents=True, exist_ok=True)

        for path in [
            bt_get_babeltrace2_path(build_dir),
            *bt_get_plugin_paths(build_dir),
            *bt_get_bindings_paths(build_dir),
        ]:
            shutil.copy(str(path), bt2_dir / path.name)
            for so in bt2_dir.glob("*.so"):
                bt_patch_lib(so)

        subprocess.run(f"patch {bt2_dir}/__init__.py init.py.patch", shell=True, check=True)

        return super().run()
