"""NeuroLog package entrypoint.

The package's top-level modules (`agent.py`, `crash_synth.py`,
`llm_extractor.py`, etc.) intentionally import each other with absolute
names like `from agent_factory import ...` so that any of them can also
be run as standalone scripts (`python smell_pass.py …`,
`python llm_extractor.py …`). That works fine in isolation, but breaks
when ADK web hosts multiple agent packages from the same parent
directory — the absolute import resolves to whichever sibling's
`agent_factory.py` appears first on `sys.path`, and that file may lack
our newer symbols.

Fix: prepend this package's directory to `sys.path` BEFORE importing
the agent module, so our own modules win the lookup. Idempotent: the
insert is gated on the path not already being present.
"""

import os as _os
import sys as _sys

_pkg_dir = _os.path.dirname(_os.path.abspath(__file__))
if _pkg_dir not in _sys.path:
    _sys.path.insert(0, _pkg_dir)

from .agent import root_agent  # noqa: E402
