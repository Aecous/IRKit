"""Apply child-only limits after exec, safe with a multithreaded MCP parent."""

import os
import resource
import sys
from pathlib import Path

timeout = int(sys.argv[1])
resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout + 1))
file_limit = int(sys.argv[2]) * 1024**2
# SQL has no arbitrary Python and needs spill space for full-case GROUP BY/DISTINCT.
# Bind this exception to the trusted entrypoint, not a model-controlled environment flag.
if (
    len(sys.argv) > 6
    and Path(sys.argv[5]).resolve() == Path(__file__).with_name("worker.py").resolve()
    and sys.argv[6] == "query"
):
    file_limit = 8 * 1024**3
resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
os.execv(sys.argv[3], sys.argv[3:])
