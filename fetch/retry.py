"""One fetch of a URL, retried where the failure is the network's rather than the server's answer.

A connection refused or reset, a timeout, or a 5xx or 429 reply is tried again after a wait that
doubles, four tries in all, since a mirror or GitHub answers the same request a moment later; a
4xx reply is the answer and raised at once. Each retry is logged by the caller's log.
"""

import time
import urllib.error
import urllib.request
lazy from collections.abc import Callable

TRIES = 4
FIRST_WAIT = 2.0  # seconds, doubled each retry


def fetch(request: urllib.request.Request, timeout: float, log: Callable[..., None]) -> bytes:
    """The body of request, read whole; see the module's docstring for what is retried."""
    wait = FIRST_WAIT
    for attempt in range(TRIES):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as e:
            if attempt == TRIES - 1 or not (e.code == 429 or e.code >= 500):
                raise
            log(f"retry after {e.code} {e.reason} in {wait:.0f} s")
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            if attempt == TRIES - 1:
                raise
            log(f"retry after {e} in {wait:.0f} s")
        time.sleep(wait)
        wait *= 2
    unreachable = "the last attempt raises or returns"
    raise AssertionError(unreachable)
