# Shared setup for the project's shell scripts. Source it; do not run it.
#
# Every script runs Python through the pinned uv in .uv/, never through the
# python3 on PATH, so a run depends neither on the caller's shell nor on what
# the machine has installed: uv provides the Python .python-version names and
# the tools pyproject.toml locks.
#
# A script elsewhere in the tree sources this with ROOT set to the repository
# root; scripts/ sets it from its own location.

if [ -z "${ROOT-}" ]; then
    ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
fi
UV_HOME="$ROOT/.uv"
UV="$UV_HOME/bin/uv"

# Everything uv downloads stays inside the repository: its cache and its
# Pythons. Only a Python uv installed is used, never one the machine has;
# pyproject.toml says the same for the project.
export UV_CACHE_DIR="$UV_HOME/cache"
export UV_PYTHON_INSTALL_DIR="$UV_HOME/python"
export UV_MANAGED_PYTHON=1

# install-uv sets this, because it is the one script that runs before uv exists.
if [ -z "${UV_BOOTSTRAP-}" ] && [ ! -x "$UV" ]; then
    echo "no uv at $UV; run scripts/install-uv" >&2
    exit 1
fi

# The pinned Python, the project's environment brought up to date first:
# py script.py args. Quiet, so a script's output is its own.
py() {
    "$UV" run --quiet --project "$ROOT" python "$@"
}
