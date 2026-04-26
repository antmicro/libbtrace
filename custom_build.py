# Copyright (c) 2025-2026 Analog Devices, Inc.
# Copyright (c) 2025-2026 Antmicro <www.antmicro.com>
#
# SPDX-License-Identifier: Apache-2.0

import contextlib
import os
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

from setuptools.command.build import build as _build
from setuptools.command.build_ext import build_ext as _build_ext

dummy_ext_path = Path.cwd() / "bt2" / "dummy_ext.c"
dummy_ext_path.parent.mkdir(parents=True, exist_ok=True)
dummy_ext_path.write_text(
    "#define PY_SSIZE_T_CLEAN\n"
    "#include <Python.h>\n"
    'static struct PyModuleDef moduledef = { PyModuleDef_HEAD_INIT, "so", NULL, -1, NULL };\n'
    "PyMODINIT_FUNC PyInit_so(void) { return PyModule_Create(&moduledef); }\n"
)

win_msys_prefix = r"c:\msys64\msys2_shell.cmd -defterm -no-start -ucrt64 -where . -c"

env = None
if sys.platform == "win32":
    env = {
        **os.environ,
        "MSYSTEM": "UCRT64",
        "CHERE_INVOKING": "1",
    }


@contextlib.contextmanager
def new_wd(path):
    cur = Path.cwd()

    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(cur)


def prepare_path(path):
    if sys.platform == "win32":
        posix = str(Path(path).as_posix())
        if len(posix) > 3 and posix[1] == ":":
            return f"/{posix[0].lower()}{posix[2:]}"
        return posix
    return path


def prepare_cmd(cmd):
    result = cmd
    if sys.platform == "win32":
        result = f"{win_msys_prefix} '{cmd}'"
    return result


def bt_build(src_dir, build_dir):
    configure_path = prepare_path(Path(src_dir) / "configure")
    cmd = f"{configure_path} --prefix {prepare_path(build_dir)} "
    cmd += "--disable-debug-info --enable-python-bindings --disable-man-pages"

    if sys.platform == "win32":
        python_path = prepare_path(Path(sys.executable))
        py_include = sysconfig.get_path("include").replace("\\", "/")
        cmd += f" PYTHON={python_path} PYTHON_INCLUDE='-I{py_include}'"
    with new_wd(build_dir):
        subprocess.run(
            prepare_cmd(cmd),
            shell=True,
            check=True,
            env=env,
        )
        if sys.platform == "win32":
            setup_cfg = build_dir / "src" / "bindings" / "python" / "bt2" / "setup.cfg"
            setup_cfg.write_text("[build]\ncompiler = mingw32\n\n[build_ext]\ncompiler = mingw32\n")
        subprocess.run(prepare_cmd("make -j12"), shell=True, check=True)
        subprocess.run(prepare_cmd("make install-strip"), shell=True, check=True)


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
    elif sys.platform not in ["win32", "cygwin", "msys"]:
        subprocess.run(f"patchelf --set-rpath '$ORIGIN' {path}", shell=True, check=True)
        subprocess.run(
            f"patchelf --replace-needed libbabeltrace2.so.0 libbabeltrace2.so {path}",
            shell=True,
            check=True,
        )


def bt_get_plugin_paths(build_dir):
    paths: list[Path] = []
    ext = ".dll" if sys.platform == "win32" else ".so"
    for plugin in ["ctf", "text", "utils"]:
        paths.append(
            build_dir / "lib" / "babeltrace2" / "plugins" / f"babeltrace-plugin-{plugin}{ext}"
        )
    return paths


def bt_get_babeltrace2_path(build_dir):
    if sys.platform == "darwin":
        return build_dir / "lib" / "libbabeltrace2.0.dylib"
    elif sys.platform == "win32":
        return build_dir / "bin" / "libbabeltrace2-0.dll"
    else:
        return build_dir / "lib" / "libbabeltrace2.so"


def bt_get_bindings_paths(build_dir):
    matches = list(build_dir.glob("lib/python*/site-packages/bt2")) + list(
        build_dir.glob("Lib/site-packages/bt2")
    )
    if len(matches) == 0:
        raise RuntimeError(f"bt2 bindings not found under {build_dir}")
    if len(matches) > 1:
        raise RuntimeError(f"many bt2 bindings found under {build_dir}")
    return matches[0].iterdir()


class build_ext(_build_ext):
    def finalize_options(self):
        super().finalize_options()
        if sys.platform == "win32":
            self.compiler = "mingw32"

    def build_extension(self, ext):
        if sys.platform != "win32":
            return super().build_extension(ext)

        ext_path = Path(self.get_ext_fullpath(ext.name)).resolve()
        ext_path.parent.mkdir(parents=True, exist_ok=True)

        includes = set(
            filter(
                None,
                [
                    sysconfig.get_path("include"),
                    sysconfig.get_path("platinclude"),
                ],
            )
        )
        include_flags = " ".join(f"-I{prepare_path(p)}" for p in includes)

        py_ver = f"python{sys.version_info.major}{sys.version_info.minor}"
        lib_file = prepare_path(Path(sys.base_prefix) / "libs" / f"{py_ver}.lib")
        src_path = prepare_path(Path(ext.sources[0]).resolve())
        out_path = prepare_path(ext_path)

        cmd = "gcc -shared -static-libgcc -O -Wall "
        cmd += f"{include_flags} {src_path} -o {out_path} {lib_file}"
        subprocess.run(prepare_cmd(cmd), shell=True, check=True, env=env)


class build(_build):
    def run(self):
        src_dir = Path().cwd().resolve()
        build_dir = (Path(self.build_temp) / "bt_build").resolve()
        build_dir.mkdir(parents=True, exist_ok=True)

        bootstrap_path = prepare_path(Path(src_dir) / "bootstrap")
        subprocess.run(prepare_cmd(f"{bootstrap_path}"), shell=True, check=True, env=env)
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
