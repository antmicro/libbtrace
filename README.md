# Libbtrace

Libbtrace is an open-source [Common Trace Format](https://diamon.org/ctf/) (CTF) parser providing [C API](https://babeltrace.org/docs/v2.1/libbabeltrace2/), [Python 3 bindings](https://babeltrace.org/docs/v2.1/python/bt2/), as well as [command-line interface](https://babeltrace.org/docs/v2.1/man1/babeltrace2.1/) (CLI), that allows to view, convert, transform and analyze traces.

It is based on parts of [Babeltrace 2](https://github.com/efficios/babeltrace/).

## Installation

### From Wheels (recommended)

Go to [releases](https://github.com/antmicro/libbtrace/releases/tag/tip) and copy the URL to the wheel for your Python version and operating system. Then install the package using `pip`:
```shell
pip install https://github.com/antmicro/libbtrace/releases/download/tip/<wheel name>.whl
```
for example to install libbtrace for Python 3.12 on Linux use:
```shell
pip install https://github.com/antmicro/libbtrace/releases/download/tip/bt2-0.0.1-cp312-cp312-manylinux_2_28_x86_64.whl
```

### From sources

Ensure that [build dependencies](#build-dependencies) are installed on your system and then run:
```shell
pip install git+https://github.com/antmicro/libbtrace.git
```

## Build dependencies

### Compiler
* Any [GCC](https://gcc.gnu.org/)-like compiler with C99 and
[GNU extension](https://gcc.gnu.org/onlinedocs/gcc/C-Extensions.html)
support. [Clang](https://clang.llvm.org/) is one of those.

* Any  C++ compiler with  C++11 support (for example,
GCC ≥ 4.8 and Clang ≥ 3.3).

### Tools
* [GNU Make](https://www.gnu.org/software/make/)
* [GNU Automake](https://www.gnu.org/software/automake/) ≥ 1.13
* [GNU Autoconf](https://www.gnu.org/software/autoconf/) ≥ 2.69
* [GNU Libtool](https://www.gnu.org/software/libtool/) ≥ 2.2
* [flex](https://github.com/westes/flex) ≥ 2.5.35
* [GNU Bison](https://www.gnu.org/software/bison/bison.html) ≥ 2.5

### Libraries
* A C library (for example, [GNU C Library](https://www.gnu.org/software/libc/), [musl libc](https://www.musl-libc.org/))
* [GLib](https://developer.gnome.org/glib/) ≥ 2.28 (Debian/Ubuntu: `libglib2.0-dev`; Fedora: `glib2-devel`)
* [Python](https://www.python.org) ≥ 3.4 (development libraries and `python3-config`) (Debian/Ubuntu: `python3-dev`; Fedora: `python3-devel`)
* [SWIG](http://www.swig.org) ≥ 3.0
