# Copyright (c) 2025 Analog Devices, Inc.
# Copyright (c) 2025 Antmicro <www.antmicro.com>
#
# SPDX-License-Identifier: Apache-2.0

import pytest


def test_import():
    import bt2

    assert bt2.__version__ == "0.0.1"

    with pytest.raises(RuntimeError) as exc:
        bt2.TraceCollectionMessageIterator("/this/path/does/not/exist")

    assert "Some auto source component" in str(exc.value)
