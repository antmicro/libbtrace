dnl SPDX-License-Identifier: MIT
dnl
dnl Copyright (C) 2017 EfficiOS, Inc.
dnl
dnl Process this file with autoconf to produce a configure script.

# Project version information
m4_define([bt_version_major], [2])
m4_define([bt_version_minor], [2])
m4_define([bt_version_patch], [0])
m4_define([bt_version_dev_stage], [rc1])
m4_define([bt_version], bt_version_major[.]bt_version_minor[.]bt_version_patch[]bt_version_dev_stage)
m4_define([bt_version_name], [[Codename TBD]])
m4_define([bt_version_description], [[Description TBD]])

# Library version information of "libbabeltrace2"
# Following the numbering scheme proposed by libtool for the library version
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
m4_define([bt_lib_version_current], [0])
m4_define([bt_lib_version_revision], [0])
m4_define([bt_lib_version_age], [0])
m4_define([bt_lib_version], bt_lib_version_current[:]bt_lib_version_revision[:]bt_lib_version_age)


##                     ##
## Autoconf base setup ##
##                     ##

AC_PREREQ([2.69])
AC_INIT([babeltrace2],[bt_version],[jeremie dot galarneau at efficios dot com],[],[https://efficios.com/babeltrace/])

AC_SUBST([BABELTRACE_LIBRARY_VERSION], bt_lib_version)

AC_CONFIG_HEADERS([src/common/config.h])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])

AC_DEFINE([BT_VERSION_MAJOR], bt_version_major, [Babeltrace major version])
AC_DEFINE([BT_VERSION_MINOR], bt_version_minor, [Babeltrace minor version])
AC_DEFINE([BT_VERSION_PATCH], bt_version_patch, [Babeltrace patch version])
AC_DEFINE([BT_VERSION_DEV_STAGE], ["]bt_version_dev_stage["], [Babeltrace version development stage (can be empty)])
AC_DEFINE([BT_VERSION_NAME], ["]bt_version_name["], [Babeltrace version name])
AC_DEFINE([BT_VERSION_DESCRIPTION], ["]AS_ESCAPE(bt_version_description)["], [Babeltrace version description])

AC_CANONICAL_TARGET
AC_CANONICAL_HOST


##                     ##
## Automake base setup ##
##                     ##

AM_INIT_AUTOMAKE([1.13 foreign dist-bzip2 no-dist-gzip tar-ustar nostdinc subdir-objects -Wall -Wno-portability -Werror])
AM_MAINTAINER_MODE([enable])

# Enable silent rules by default
AM_SILENT_RULES([yes])


##        ##
## Macros ##
##        ##

AC_DEFUN([CONFIG_NAME], [dnl
enable_[]patsubst([$1], -, _)[]dnl
])

AC_DEFUN([CONFIG_FEATURE], [ dnl
  AC_ARG_ENABLE([$1],
    AS_HELP_STRING([--patsubst(patsubst([$3], yes, disable), no, enable)-$1], [$2]), [
CONFIG_NAME($1)=${enableval}
    ], [
CONFIG_NAME($1)=$3
    ]
  )
])

AC_DEFUN([CONFIG_FEATURE_SET], [ dnl
CONFIG_NAME($1)=$2 dnl
])

AC_DEFUN([CONFIG_FEATURE_ENABLED], [dnl
test "x$[]CONFIG_NAME($1)" = xyes[]dnl
])

AC_DEFUN([CONFIG_FEATURE_NOT_ENABLED], [dnl
test "x$[]CONFIG_NAME($1)" != xyes[]dnl
])

AC_DEFUN([CONFIG_FEATURE_DISABLED], [dnl
test "x$[]CONFIG_NAME($1)" = xno[]dnl
])

AC_DEFUN([CONFIG_FEATURE_UNDEF], [dnl
test "x$[]CONFIG_NAME($1)" = x[]dnl
])

AC_DEFUN([CONFIG_FEATURE_IF_ENABLED], [ dnl
  AS_IF([CONFIG_FEATURE_ENABLED($1)], [ dnl
    $2 dnl
  ], [: dnl
    $3 dnl
  ])
])

AC_DEFUN([CONFIG_FEATURE_IF_DISABLED], [ dnl
  AS_IF([CONFIG_FEATURE_DISABLED($1)], [ dnl
    $2 dnl
  ], [: dnl
    $3 dnl
  ])
])

AC_DEFUN([CONFIG_FEATURE_IF_NOT_ENABLED], [ dnl
  AS_IF([CONFIG_FEATURE_NOT_ENABLED($1)], [ dnl
    $2 dnl
  ], [: dnl
    $3 dnl
  ])
])

AC_DEFUN([CONFIG_FEATURE_IF_UNDEF], [ dnl
  AS_IF([CONFIG_FEATURE_UNDEF($1)], [ dnl
    $2 dnl
  ], [: dnl
    $3 dnl
  ])
])

CONFIG_FEATURE([testoption], [Feature description asdsadsad], [no])

##                      ##
## OS specific defaults ##
##                      ##

MACOS=no
MINGW32=no
LT_NO_UNDEFINED=""
AS_CASE([$host_os],
  [solaris*],
    [
      CONFIG_FEATURE_SET([debug-info], [no])
    ],
  [darwin*],
    [
      CONFIG_FEATURE_SET([debug-info], [no])
      MACOS=yes
    ],
  [freebsd*],
    [
      CONFIG_FEATURE_SET([debug-info], [no])
    ],
  [cygwin*],
    [
      CONFIG_FEATURE_SET([debug-info], [no])
      LT_NO_UNDEFINED="-no-undefined"
    ],
  [mingw*],
    [
      MINGW32=yes
      CONFIG_FEATURE_SET([debug-info], [no])
      LT_NO_UNDEFINED="-no-undefined"
    ]
)

AM_CONDITIONAL([BABELTRACE_BUILD_WITH_MINGW], [test "x$MINGW32" = "xyes"])
AM_CONDITIONAL([BUILD_MACOS], [test "x$MACOS" = "xyes"])

AC_SUBST(LT_NO_UNDEFINED)


##                   ##
## C compiler checks ##
##                   ##

# Choose the C compiler
AC_PROG_CC
# AC_PROG_CC_STDC was merged in AC_PROG_CC in autoconf 2.70
m4_version_prereq([2.70], [], [AC_PROG_CC_STDC])

# Make sure the C compiler supports C99
AS_IF([test "$ac_cv_prog_cc_c99" = "no"], [AC_MSG_ERROR([The compiler does not support C99])])

# Enable available system extensions and LFS support
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

# Make sure we have pthread support
PTHREAD_CFLAGS="-pthread"
AC_SUBST([PTHREAD_CFLAGS])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_C_TYPEOF
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])


##                     ##
## C++ compiler checks ##
##                     ##

# Require a C++11 compiler without GNU extensions (-std=c++11)
AX_CXX_COMPILE_STDCXX([11], [noext], [mandatory])


##               ##
## Header checks ##
##               ##

AC_HEADER_STDBOOL
AC_CHECK_HEADERS([ \
  fcntl.h \
  float.h \
  ftw.h \
  libintl.h \
  limits.h \
  malloc.h \
  netdb.h \
  netinet/in.h \
  stddef.h \
  sys/socket.h \
  sys/time.h
])


##               ##
## Linker checks ##
##               ##

# Check if the linker supports no-as-needed
AX_APPEND_LINK_FLAGS([-Wl,--no-as-needed], [LD_NO_AS_NEEDED])
AC_SUBST([LD_NO_AS_NEEDED])

# Check if the linker supports whole-archive
AX_CHECK_LINK_FLAG([-Wl,--whole-archive,--no-whole-archive],
  [
    AC_SUBST([LD_WHOLE_ARCHIVE], [-Wl,--whole-archive,])
    AC_SUBST([LD_NO_WHOLE_ARCHIVE], [,--no-whole-archive])
  ],[
    # Fallback to force_load for the macOS linker
    AX_CHECK_LINK_FLAG([-Wl,-force_load],
      [
        AC_SUBST([LD_WHOLE_ARCHIVE], [-Wl,-force_load,])
        AC_SUBST([LD_NO_WHOLE_ARCHIVE], [])
      ],[
        AC_MSG_WARN([Can't find a linker option to force the inclusion of the static plugin archive objects.])
      ]
    )
  ]
)

# Check if the linker supports the "notext" keyword
AX_CHECK_LINK_FLAG([-Wl,-z,notext],[
  AC_SUBST([LD_NOTEXT], [-Wl,-z,notext])
])


##                 ##
## Programs checks ##
##                 ##

AM_PROG_AR
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
AC_PROG_LN_S
AC_PROG_SED
AC_CHECK_PROGS([FOLD], [fold])
AC_CHECK_PROGS([ASCIIDOC], [asciidoc])
AC_CHECK_PROGS([XMLTO], [xmlto])

# check for bison
AC_PROG_YACC
AX_PROG_BISON_VERSION([2.5], [have_bison=yes])

AM_CONDITIONAL([HAVE_BISON], [test "x$have_bison" = "xyes"])

# check for flex
# Prior to autoconf 2.70, AC_PROG_FLEX did not take an argument. This is not a
# problem since the argument is silently ignored by older versions.
AC_PROG_LEX([noyywrap])
AX_PROG_FLEX_VERSION([2.5.35], [have_flex=yes])

AM_CONDITIONAL([HAVE_FLEX], [test "x$have_flex" = "xyes"])

# Always check for python, we will fail later if some features require it and
# it's unavailable.
AM_PATH_PYTHON([3.4], [
  AE_PATH_PYTHON_MODULES([PYTHON])

  # pythondir is the path where extra modules are to be installed
  pythondir=$PYTHON_PREFIX/$PYTHON_MODULES_PATH

  # pyexecdir is the path that contains shared objects used by the extra modules
  pyexecdir=$PYTHON_EXEC_PREFIX/$PYTHON_MODULES_PATH

  # If no PYTHON_CONFIG was specified by the user, try to find it, starting
  # with the one specific to the configured python version.
  AS_IF([test "x$PYTHON_CONFIG" = "x"], [
    AC_CHECK_PROGS([PYTHON_CONFIG], [python$PYTHON_VERSION-config python-config])
  ])

  # If PYTHON_CONFIG is set use it to get the includes and ld flags, unless
  # they were specified by the user.
  AS_IF([test "x$PYTHON_CONFIG" != "x" ], [
    AS_IF([test "x$PYTHON_INCLUDE" = "x"], [
      AC_MSG_CHECKING([Python include flags])
      PYTHON_INCLUDE=`$PYTHON_CONFIG --includes`
      AC_MSG_RESULT([$PYTHON_INCLUDE])
    ])
  ])
], [:])

# Initialize and configure libtool
LT_INIT([win32-dll])


##                ##
## Library checks ##
##                ##

# Check what libraries are required on this platform to link sockets programs.
AX_LIB_SOCKET_NSL

# Check for glib >= 2.28 with gmodule support
AM_PATH_GLIB_2_0([2.28.0], [],
  AC_MSG_ERROR([glib >= 2.28 is required - download it from ‘ftp://ftp.gtk.org/pub/gtk’]),
  [gmodule-no-export]
)

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_FORK
AC_FUNC_MKTIME
AC_FUNC_MMAP
AC_FUNC_STRERROR_R
AC_FUNC_STRNLEN
AC_CHECK_FUNCS([ \
  atexit \
  dup2 \
  ftruncate \
  gethostbyname \
  gettimeofday \
  localtime_r \
  memchr \
  memset \
  mkdir \
  mkdtemp \
  munmap \
  rmdir \
  setenv \
  setrlimit \
  socket \
  strchr \
  strdup \
  strerror \
  strndup \
  strnlen \
  strrchr \
  strstr \
  strtoul \
  strtoull \
  tzset \
])

# AC_FUNC_MALLOC causes problems when cross-compiling.
#AC_FUNC_MALLOC
#AC_FUNC_REALLOC

# Check for fmemopen
AC_CHECK_LIB([c], [fmemopen],
  [AC_DEFINE_UNQUOTED([BABELTRACE_HAVE_FMEMOPEN], 1, [Has ‘fmemopen’ support.])]
)

# Check for open_memstream
AC_CHECK_LIB([c], [open_memstream],
  [AC_DEFINE_UNQUOTED([BABELTRACE_HAVE_OPEN_MEMSTREAM], 1, [Has ‘open_memstream’ support.])]
)

# Check for posix_fallocate
AC_CHECK_LIB([c], [posix_fallocate],
  [AC_DEFINE_UNQUOTED([BABELTRACE_HAVE_POSIX_FALLOCATE], 1, [Has ‘posix_fallocate’ support.])]
)


##                 ##
## User variables  ##
##                 ##

AC_ARG_VAR([PYTHON_INCLUDE], [Include flags for Python, bypassing ‘python-config’])
AC_ARG_VAR([PYTHON_LDFLAGS], [Linker flags for Python, bypassing ‘python-config’])
AC_ARG_VAR([PYTHON_CONFIG], [Path to ‘python-config’])

# BABELTRACE_PLUGINS_DIR: Plugins directory
AC_ARG_VAR([BABELTRACE_PLUGINS_DIR], [built-in plugins install directory [‘LIBDIR/babeltrace2/plugins’]])
AS_IF([test "x$BABELTRACE_PLUGINS_DIR" = x], [BABELTRACE_PLUGINS_DIR='${libdir}/babeltrace2/plugins'])

# BABELTRACE_PLUGIN_PROVIDERS_DIR: Plugin providers directory
AC_ARG_VAR([BABELTRACE_PLUGIN_PROVIDERS_DIR], [built-in plugin providers install directory [‘LIBDIR/babeltrace2/plugin-providers’]])
AS_IF([test "x$BABELTRACE_PLUGIN_PROVIDERS_DIR" = x], [BABELTRACE_PLUGIN_PROVIDERS_DIR='${libdir}/babeltrace2/plugin-providers'])

# BABELTRACE_MINIMAL_LOG_LEVEL:
AC_ARG_VAR([BABELTRACE_MINIMAL_LOG_LEVEL], [Minimal log level for Babeltrace program, library, and plugins (‘TRACE’, ‘DEBUG’ (default), or ‘INFO’)])
AS_IF([test "x$BABELTRACE_MINIMAL_LOG_LEVEL" = x], [BABELTRACE_MINIMAL_LOG_LEVEL="DEBUG"])
AS_IF([test "$BABELTRACE_MINIMAL_LOG_LEVEL" != "TRACE" && \
       test "$BABELTRACE_MINIMAL_LOG_LEVEL" != "DEBUG" && \
       test "$BABELTRACE_MINIMAL_LOG_LEVEL" != "INFO"],
  [AC_MSG_ERROR([Invalid ‘BABELTRACE_MINIMAL_LOG_LEVEL’ value (‘$BABELTRACE_MINIMAL_LOG_LEVEL’): use ‘TRACE’, ‘DEBUG’, or ‘INFO’.])]
)
AC_DEFINE_UNQUOTED([BT_LOG_MINIMAL_LEVEL], [__BT_LOGGING_LEVEL_$BABELTRACE_MINIMAL_LOG_LEVEL], [Minimal log level])

# BABELTRACE_DEV_MODE:
AC_ARG_VAR([BABELTRACE_DEV_MODE], [Set to ‘1’ to enable the Babeltrace developer mode (enables run-time checks for plugin developers)])
AS_IF([test "x$BABELTRACE_DEV_MODE" = x1], [
  AC_DEFINE([BT_DEV_MODE], 1, [Babeltrace developer mode])
], [BABELTRACE_DEV_MODE=0])
AM_CONDITIONAL([DEV_MODE], [test "x$BABELTRACE_DEV_MODE" = x1])

# BABELTRACE_DEBUG_MODE:
AC_ARG_VAR([BABELTRACE_DEBUG_MODE], [Set to ‘1’ to enable the Babeltrace debug mode (enables internal assertions for Babeltrace maintainers)])
AS_IF([test "x$BABELTRACE_DEBUG_MODE" = x1], [
  AC_DEFINE([BT_DEBUG_MODE], 1, [Babeltrace debug mode])
], [BABELTRACE_DEBUG_MODE=0])


##                             ##
## Optional features selection ##
##                             ##

# Python bindings
# Disabled by default
CONFIG_FEATURE([python-bindings],[build the Python bindings], [no])

# Python bindings documentation
# Disabled by default
CONFIG_FEATURE([python-bindings-doc],[build the Python bindings documentation], [no])

# Python plugins
# Disabled by default
CONFIG_FEATURE([python-plugins],[enable the Python plugins support for the library and converter], [no])

# Debug info
# Enabled by default, except on some platforms
CONFIG_FEATURE([debug-info],[disable the debug info support (default on macOS, Solaris and Windows)], [yes])

# API documentation
# Disabled by default
CONFIG_FEATURE([api-doc],[build the HTML API documentation], [no])

# Built-in plugins
# Disabled by default
CONFIG_FEATURE([built-in-plugins],[Statically-link in-tree plug-ins into the ‘babeltrace2’ executable], [no])

# Built-in python plugin support
# Disabled by default
CONFIG_FEATURE([built-in-python-plugin-support],[Statically-link Python plugin support into the babeltrace library], [no])

# Man pages
# Enabled by default
CONFIG_FEATURE([man-pages],[Do not build and install man pages (already built in a distributed tarball], [yes])

# When given, add -Werror to WARN_CFLAGS and WARN_CXXFLAGS.
# Disabled by default
CONFIG_FEATURE([Werror],[Treat compiler warnings as errors.], [no])

# When given, build with AddressSanitizer.
CONFIG_FEATURE([asan],[Build with AddressSanitizer.], [no])
CONFIG_FEATURE([ubsan],[Build with UndefinedBehaviorSanitizer.], [no])

##                                          ##
## Check for conflicting features selection ##
##                                          ##

# Check for conflicting Python related features user choices.
CONFIG_FEATURE_IF_ENABLED([python-plugins], [
  CONFIG_FEATURE_IF_UNDEF([python-bindings], [
    # --enable-python-plugins was provided but --enable-python-bindings was
    # omitted. Turn the Python bindings ON anyway because it's needed to
    # use the Python plugins.
    CONFIG_FEATURE_SET([python-bindings], [yes])
  ], [
    CONFIG_FEATURE_IF_DISABLED([python-bindings], [
      # --enable-python-plugins _and_ --disable-python-bindings were
      # used. This is invalid because Python plugins need the Python
      # bindings to be useful.
      AC_MSG_ERROR(‘--enable-python-bindings’ must be used to support Python plugins)
    ])
  ])
])

# Check for conflicting optional features user choices
CONFIG_FEATURE_IF_ENABLED([built-in-plugins], [
  # Built-in plug-ins are only available when the --disable-shared --enable-static options are used.
  CONFIG_FEATURE_IF_NOT_ENABLED([static], [AC_MSG_ERROR(‘--enable-static’ must be used to bundle plug-ins in the ‘babeltrace2’ executable)])
  CONFIG_FEATURE_IF_ENABLED([shared], [AC_MSG_ERROR(‘--disable-shared’ must be used to bundle plug-ins in the ‘babeltrace2’ executable)])
])

CONFIG_FEATURE_IF_ENABLED([built-in-python-plugin-support], [
  CONFIG_FEATURE_IF_NOT_ENABLED([python-plugins], [AC_MSG_ERROR([‘--enable-python-plugins’ must be used to bundle Python plugin support in the ‘babeltrace2’ executable])])
  # Built-in plug-ins are only available when the --disable-shared --enable-static options are used.
  CONFIG_FEATURE_IF_NOT_ENABLED([static], [AC_MSG_ERROR(‘--enable-static’ must be used to bundle Python plugin support in the ‘babeltrace2’ executable)])
  CONFIG_FEATURE_IF_ENABLED([shared], [AC_MSG_ERROR(‘--disable-shared’ must be used to bundle Python plugin support in the ‘babeltrace2’ executable)])
])


##                                                                          ##
## Set automake variables for optional feature conditionnals in Makefile.am ##
##                                                                          ##

AM_CONDITIONAL([ENABLE_PYTHON_BINDINGS], CONFIG_FEATURE_ENABLED([python-bindings]))
AM_CONDITIONAL([ENABLE_PYTHON_BINDINGS_DOC], CONFIG_FEATURE_ENABLED([python-bindings-doc]))
AM_CONDITIONAL([ENABLE_PYTHON_PLUGINS], CONFIG_FEATURE_ENABLED([python-plugins]))
AM_CONDITIONAL([ENABLE_DEBUG_INFO], CONFIG_FEATURE_ENABLED([debug-info]))
AM_CONDITIONAL([ENABLE_API_DOC], CONFIG_FEATURE_ENABLED([api-doc]))
AM_CONDITIONAL([ENABLE_BUILT_IN_PLUGINS], CONFIG_FEATURE_ENABLED([built-in-plugins]))
AM_CONDITIONAL([ENABLE_BUILT_IN_PYTHON_PLUGIN_SUPPORT], CONFIG_FEATURE_ENABLED([built-in-python-plugin-support]))
AM_CONDITIONAL([ENABLE_MAN_PAGES], CONFIG_FEATURE_ENABLED([man-pages]))
AM_CONDITIONAL([ENABLE_PYTHON_COMMON_DEPS], CONFIG_FEATURE_ENABLED([python-bindings]) || CONFIG_FEATURE_ENABLED([python-plugins]))
AM_CONDITIONAL([ENABLE_ASAN], CONFIG_FEATURE_ENABLED([asan]))


##                                                                    ##
## Set defines for optional features conditionnals in the source code ##
##                                                                    ##

CONFIG_FEATURE_IF_ENABLED([built-in-plugins],
  [AC_DEFINE([BT_BUILT_IN_PLUGINS], [1], [Define to ‘1’ to register plug-in attributes in static executable sections])]
)

CONFIG_FEATURE_IF_ENABLED([built-in-python-plugin-support],
  [AC_DEFINE([BT_BUILT_IN_PYTHON_PLUGIN_SUPPORT], [1], [Define to ‘1’ to register plug-in attributes in static executable sections])]
)

CONFIG_FEATURE_IF_ENABLED([python-plugins], [ENABLE_PYTHON_PLUGINS=1], [ENABLE_PYTHON_PLUGINS=0])
AC_SUBST([ENABLE_PYTHON_PLUGINS])

CONFIG_FEATURE_IF_ENABLED([debug-info], [ENABLE_DEBUG_INFO_VAL=1], [ENABLE_DEBUG_INFO_VAL=0])
AC_SUBST([ENABLE_DEBUG_INFO_VAL])

CONFIG_FEATURE_IF_ENABLED([asan], [ENABLE_ASAN=1], [ENABLE_ASAN=0])
AC_SUBST([ENABLE_ASAN])

##                                          ##
## Check for optional features dependencies ##
##                                          ##

AC_CHECK_PROGS([SWIG], [swig])

# The Python bindings require SWIG
CONFIG_FEATURE_IF_ENABLED([python-bindings],
  AS_IF([test x"$SWIG" != x"swig"], [
    AC_MSG_ERROR([Cannot find SWIG.])
  ])
  SWIG_LIB=`$SWIG -swiglib | tr -d '\r\n'`
  AC_SUBST([SWIG_LIB])
)

AS_IF([test "$PYTHON" != :], [have_python=yes], [have_python=no])
AS_IF([test -n "$PYTHON_CONFIG"], [have_python_dev=yes], [have_python_dev=no])

AM_CONDITIONAL([HAVE_PYTHON], [test "x$have_python" = xyes])
AM_CONDITIONAL([HAVE_PYTHON_DEV], [test "x$have_python_dev" = xyes])

AS_IF([test "x$have_python" = xyes], [
  AX_COMPARE_VERSION(["$PYTHON_VERSION"], [ge], ["3.12"], [
    have_python_312_or_greater=yes
  ])
])

AM_CONDITIONAL([HAVE_PYTHON_312_OR_GREATER], [test "x$have_python_312_or_greater" = xyes])

AS_IF([CONFIG_FEATURE_ENABLED([python-bindings]) || CONFIG_FEATURE_ENABLED([python-plugins])], [
  AS_IF([test "x$have_python_dev" = xno], [
    AC_MSG_ERROR([Cannot find a suitable ‘python-config’. You can override the ‘python-config’ path with the ‘PYTHON_CONFIG’ environment variable.])
  ])

  AX_COMPARE_VERSION(["$PYTHON_VERSION"], [ge], ["3.12"], [
    AC_MSG_CHECKING([for python setuptools])
    AS_IF(["$PYTHON" -c "import setuptools" 2>/dev/null], [
      AC_MSG_RESULT([yes])
    ], [
      AC_MSG_RESULT([no])
      AC_MSG_ERROR([Python >= 3.12 removed ‘distutils’, the ‘setuptools’ module needs to be installed for the selected interpreter.])
    ])
  ])
])

CONFIG_FEATURE_IF_ENABLED([python-bindings-doc],
  [
    AE_CHECK_PYTHON_SPHINX([PYTHON])
    AS_IF([test "x$PYTHON_SPHINX_EXISTS" = xno], [
      AC_MSG_ERROR([The Sphinx package for Python 3 is required to build the Python bindings documentation])
    ])

    CONFIG_FEATURE_IF_NOT_ENABLED([python-bindings], [
      AC_MSG_ERROR([The Python bindings are required to build their documentation])
    ])
  ]
)

CONFIG_FEATURE_IF_ENABLED([debug-info], [
  # Check if libelf and libdw are present
  PKG_CHECK_MODULES([ELFUTILS], [libelf >= 0.154 libdw >= 0.154],
    [
      dnl PKG_CHECK_MODULES defines ELFUTILS_LIBS
    ],
    [
      AC_MSG_WARN([pkg-config was unable to find a valid ‘.pc’ for libelf/libdw. Set ‘PKG_CONFIG_PATH’ to specify the pkg-config configuration file location.])

      # Turns out SLES12 doesn't bother shipping .pc file for libelf
      AC_MSG_WARN([Finding libelf without pkg-config.])
      AC_CHECK_LIB([elf], [elf_version], [:], [AC_MSG_ERROR(Missing libelf (from elfutils >= 0.154) which is required by debug info. You can disable this feature using ‘--disable-debug-info’.)])
      AC_CHECK_LIB([dw], [dwarf_begin], [:], [AC_MSG_ERROR(Missing libdw (from elfutils >= 0.154) which is required by debug info. You can disable this feature using ‘--disable-debug-info’.)])
      AE_LIB_ELFUTILS([0], [154], [], [AC_MSG_ERROR(elfutils >= 0.154 is required to use the debug info feature. You can disable this feature using ‘--disable-debug-info’.)])
      ELFUTILS_LIBS="-lelf -ldw"
    ])
])
AC_SUBST([ELFUTILS_LIBS])

CONFIG_FEATURE_IF_ENABLED([api-doc],
  [
    DX_DOXYGEN_FEATURE(ON)
    DX_DOT_FEATURE(OFF)
    DX_HTML_FEATURE(ON)
    DX_CHM_FEATURE(OFF)
    DX_CHI_FEATURE(OFF)
    DX_MAN_FEATURE(OFF)
    DX_RTF_FEATURE(OFF)
    DX_XML_FEATURE(OFF)
    DX_PDF_FEATURE(OFF)
    DX_PS_FEATURE(OFF)
    DX_INIT_DOXYGEN([babeltrace2], [$(builddir)/Doxyfile], [output])
    AS_IF([test -z "$DX_DOXYGEN"],
      [AC_MSG_ERROR([You need doxygen to enable the API documentation])]
    )
  ]
)

have_asciidoc_xmlto=no
warn_prebuilt_man_pages=no

# export AsciiDoc and xmlto existence
AM_CONDITIONAL([HAVE_ASCIIDOC_XMLTO], [test "x$have_asciidoc_xmlto" = "xyes"])

# a wonderful hack that seems necessary because $libdir is
# literally `${exec_prefix}/lib`, and $exec_prefix is set to `NONE`
# by autoconf when it's not specified by the user
AS_IF([test "x$exec_prefix" = xNONE], [
  AS_IF([test "x$prefix" = xNONE], [
    PREFIX="$ac_default_prefix"
  ], [
    PREFIX="$prefix"
  ])

  LIBDIR="$PREFIX/lib"
], [
  LIBDIR="$libdir"
])

AC_SUBST(LIBDIR)

# If --enable-asan is used...
CONFIG_FEATURE_IF_ENABLED([asan], [
  # ... add -fsanitize=address to the *FLAGS variables.
  ASAN_CFLAGS="-fsanitize=address"
  ASAN_CXXFLAGS="-fsanitize=address"
  ASAN_LDFLAGS="-fsanitize=address"
])

# If --enable-ubsan is used...
CONFIG_FEATURE_IF_ENABLED([ubsan], [
  # ... add -fsanitize=undefined to the *FLAGS variables.
  UBSAN_CFLAGS="-fsanitize=undefined"
  UBSAN_CXXFLAGS="-fsanitize=undefined"
  UBSAN_LDFLAGS="-fsanitize=undefined"
])

# CFLAGS from libraries (the glib ones are needed for the following sizeof
# test).
AM_CFLAGS="-fvisibility=hidden ${PTHREAD_CFLAGS} ${GLIB_CFLAGS} ${ASAN_CFLAGS} ${UBSAN_CFLAGS}"
AM_CXXFLAGS="-fvisibility=hidden -fvisibility-inlines-hidden ${PTHREAD_CFLAGS} ${GLIB_CFLAGS} ${ASAN_CXXFLAGS} ${UBSAN_CFLAGS}"
AM_LDFLAGS="${ASAN_LDFLAGS} ${UBSAN_CFLAGS}"

# Check that the current size_t matches the size that glib thinks it should
# be. This catches problems on multi-arch where people try to do a 32-bit
# build while pointing at 64-bit glib headers. This is a common error because
# glib.h is not platform specific but it includes glibconfig.h which is and
# is usually installed in a non-standard path.

# Do this before enabling all the warning flags, as the
# AC_LANG_PROGRAM-generated program may generate some warning, which makes this
# test fail unnecessarily.

# Older versions of the pkg-config macros disallows PKG_* in the autoconf
# output. Specifically allow pkg_config_libdir to be able to print the
# error message.
m4_pattern_allow([PKG_CONFIG_LIBDIR])

save_CFLAGS=${CFLAGS}
CFLAGS="${CFLAGS} ${AM_CFLAGS}"
AC_COMPILE_IFELSE([
  AC_LANG_PROGRAM([dnl
#include <glib.h>
#include <unistd.h>
  ], [dnl
G_STATIC_ASSERT(sizeof(size_t) == GLIB_SIZEOF_SIZE_T);
  ])
],[:],[
  AC_MSG_ERROR([dnl
‘sizeof(size_t)’ doesn't match ‘GLIB_SIZEOF_SIZE_T’. You probably need to set
‘PKG_CONFIG_LIBDIR’ to point to the right pkg-config files for your build
target.
  ])
])
CFLAGS=${save_CFLAGS}

# Detect C and LD warning flags supported by the compiler.

# Detect warning flags supported by the C and C++ compilers and append them to
# WARN_CFLAGS and WARN_CXXFLAGS.
#
m4_define([WARN_FLAGS_LIST], [ dnl
  -Wall dnl
  -Wextra dnl
  -Wmissing-prototypes dnl
  -Wmissing-declarations dnl
  -Wnull-dereference dnl
  -Wundef dnl
  -Wredundant-decls dnl
  -Wshadow dnl
  dnl GCC's -Wshadow warns about constructor parameters shadowing fields, but
  dnl Clang's does not.  Enable Clang's `-Wshadow-field-in-constructor`, to make
  dnl Clang warn about that.
  -Wshadow-field-in-constructor dnl
  -Wshadow-field dnl
  -Wjump-misses-init dnl
  -Wsuggest-attribute=format dnl
  -Wtautological-constant-out-of-range-compare dnl
  -Wnested-externs dnl
  -Wwrite-strings dnl
  -Wformat=2 dnl
  -Wstrict-aliasing dnl
  -Wmissing-noreturn dnl
  -Winit-self dnl
  -Wduplicated-cond dnl
  -Wduplicated-branches dnl
  -Wlogical-op dnl
  -Wsuggest-override dnl
  -Wno-sign-compare dnl
  dnl
  dnl Some versions of SWIG (like 3.0.12) generate code that produces
  dnl -Wcast-function-type warnings.  This warning is present in gcc >= 8.  This
  dnl combo happens on RHEL/Centos 8, for example.  Later versions of SWIG (like
  dnl 4.0.1) have the correct function signatures to not produce this warning.
  dnl It's simpler to just disable the warning globally.
  dnl
  dnl Note that the Debian/Ubuntu SWIG package 3.0.12-2 contains a local patch to
  dnl fix this (python-fix-function-cast-warnings.patch), so you won't be able to
  dnl reproduce the warning using that package.
  dnl
  dnl Ref: https://github.com/swig/swig/issues/1259
  -Wno-cast-function-type dnl
  -Wno-maybe-uninitialized dnl
])

# Pass -Werror as an extra flag during the test: this is needed to make the
# -Wunknown-warning-option diagnostic fatal with clang.
AC_LANG([C++])
AX_APPEND_COMPILE_FLAGS([WARN_FLAGS_LIST], [WARN_CXXFLAGS], [-Werror])
AC_LANG([C])
AX_APPEND_COMPILE_FLAGS([WARN_FLAGS_LIST], [WARN_CFLAGS], [-Werror])

CONFIG_FEATURE_IF_ENABLED([Werror], [WARN_CXXFLAGS="${WARN_CXXFLAGS} -Werror"])
CONFIG_FEATURE_IF_ENABLED([Werror], [WARN_CFLAGS="${WARN_CFLAGS} -Werror"])

# The test used in AX_APPEND_COMPILE_FLAGS, generated using AC_LANG_PROGRAM, is
# written in such a way that it triggers warnings with the following warning
# flags.  So they would always end up disabled if we put them there, because
# the test program would not build.
#
# Enable them here unconditionally.  They are supported by GCC >= 4.8 and by
# Clang >= 3.3 (required by the project) and are only valid for C code.
WARN_CFLAGS="${WARN_CFLAGS} -Wold-style-definition -Wstrict-prototypes"

# CFLAGS from AX_APPEND_COMPILE_FLAGS.
AM_CXXFLAGS="${AM_CXXFLAGS} ${WARN_CXXFLAGS}"
AM_CFLAGS="${AM_CFLAGS} ${WARN_CFLAGS}"

# Done for AM_CXXFLAGS, AM_CFLAGS and AM_LDFLAGS.
AC_SUBST(AM_CXXFLAGS)
AC_SUBST(AM_CFLAGS)
AC_SUBST(AM_LDFLAGS)

# Set global CPPFLAGS in AM_CPPFLAGS
AM_CPPFLAGS="-I\$(top_srcdir)/include -I\$(top_builddir)/src -I\$(top_srcdir)/src -include common/config.h"
AC_SUBST(AM_CPPFLAGS)

# Add glib to global link libs
LIBS="$LIBS $GLIB_LIBS"

# Disable exceptions for the {fmt} library.  This means, for example, that a
# format error will result in an assertion failure (instead of throwing an
# `fmt::format_error` exception).
AC_DEFINE_UNQUOTED([FMT_EXCEPTIONS], 0, [Disable {fmt} exceptions.])

# Abuse autoconf's AC_ARG_PROGRAM output variable 'program_transform_name'
# to rename babeltrace2.bin to babeltrace2 at install time.
program_transform_name="s&babeltrace2\.bin&babeltrace2&;$program_transform_name"
AC_SUBST(program_transform_name)

AC_CONFIG_FILES([
  doc/api/libbabeltrace2/Doxyfile
  doc/api/libbabeltrace2/Makefile
  doc/bindings/python/Makefile
  doc/Makefile
  doc/man/asciidoc-attrs.conf
  doc/man/Makefile
  include/Makefile
  Makefile
  src/babeltrace2-ctf-writer.pc
  src/babeltrace2.pc
  src/bindings/python/bt2/bt2/version.py
  src/bindings/python/bt2/Makefile
  src/bindings/python/bt2/setup.py
  src/cli/Makefile
  src/Makefile
])

AC_OUTPUT

# man pages build enabled/disabled
m4_pushdef([build_man_pages_msg], [Build and install man pages])
m4_popdef([build_man_pages_msg])

# vim: shiftwidth=2 softtabstop=2 expandtab
