# SPDX-FileCopyrightText: 2024 EfficiOS Inc.
#
# SPDX-License-Identifier: MIT

API_DOC_INSTALL_DIR = "$(DESTDIR)$(docdir)/api"

all-local: doxygen-doc

install-data-local: doxygen-doc
	$(mkdir_p) "$(API_DOC_INSTALL_DIR)"
	cp -rv output/html "$(API_DOC_INSTALL_DIR)"

@DX_RULES@

$(DX_DOCDIR)/$(PACKAGE).tag: \
	Doxyfile \
	DoxygenLayout.xml \
	style.css \
	dox/main-page.dox \
	dox/api-fund.dox \
	dox/guides.dox \
	dox/examples.dox \
	dox/group-trace-ir.dox \
	@top_srcdir@/include/babeltrace2/types.h \
	@top_srcdir@/include/babeltrace2/error-reporting.h \
	@top_srcdir@/include/babeltrace2/util.h \
	@top_srcdir@/include/babeltrace2/graph/graph.h \
	@top_srcdir@/include/babeltrace2/graph/component-class-dev.h \
	@top_srcdir@/include/babeltrace2/graph/message.h \
	@top_srcdir@/include/babeltrace2/trace-ir/clock-class.h \
	@top_srcdir@/include/babeltrace2/trace-ir/clock-snapshot.h \
	@top_srcdir@/include/babeltrace2/trace-ir/event.h \
	@top_srcdir@/include/babeltrace2/trace-ir/event-class.h \
	@top_srcdir@/include/babeltrace2/trace-ir/field.h \
	@top_srcdir@/include/babeltrace2/trace-ir/field-class.h \
	@top_srcdir@/include/babeltrace2/trace-ir/field-path.h \
	@top_srcdir@/include/babeltrace2/trace-ir/field-location.h \
	@top_srcdir@/include/babeltrace2/trace-ir/packet.h \
	@top_srcdir@/include/babeltrace2/trace-ir/stream.h \
	@top_srcdir@/include/babeltrace2/trace-ir/stream-class.h \
	@top_srcdir@/include/babeltrace2/trace-ir/trace.h \
	@top_srcdir@/include/babeltrace2/trace-ir/trace-class.h \
	@top_srcdir@/include/babeltrace2/graph/message-iterator.h \
	@top_srcdir@/include/babeltrace2/graph/message-iterator-class.h \
	@top_srcdir@/include/babeltrace2/graph/self-message-iterator.h \
	@top_srcdir@/include/babeltrace2/graph/private-query-executor.h \
	@top_srcdir@/include/babeltrace2/graph/self-component.h \
	@top_srcdir@/include/babeltrace2/graph/self-component-port.h \
	@top_srcdir@/include/babeltrace2/graph/self-component-class.h \
	@top_srcdir@/include/babeltrace2/graph/component.h \
	@top_srcdir@/include/babeltrace2/graph/component-class.h \
	@top_srcdir@/include/babeltrace2/graph/component-descriptor-set.h \
	@top_srcdir@/include/babeltrace2/graph/connection.h \
	@top_srcdir@/include/babeltrace2/graph/port.h \
	@top_srcdir@/include/babeltrace2/graph/interrupter.h \
	@top_srcdir@/include/babeltrace2/graph/query-executor.h \
	@top_srcdir@/include/babeltrace2/integer-range-set.h \
	@top_srcdir@/include/babeltrace2/version.h \
	@top_srcdir@/include/babeltrace2/logging.h \
	@top_srcdir@/include/babeltrace2/plugin/plugin-dev.h \
	@top_srcdir@/include/babeltrace2/plugin/plugin-loading.h \
	@top_srcdir@/include/babeltrace2/value.h

MOSTLYCLEANFILES = $(DX_CLEANFILES)
EXTRA_DIST = \
	Doxyfile.in \
	DoxygenLayout.xml \
	README.md \
	style.css \
	dox \
	examples \
	images
