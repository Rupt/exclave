# gdb.py: carried by the launcher in its .debug_gdb_scripts section and auto-loaded by gdb when the launcher is
# the executable (PROPOSAL.md 7.6, 13.1). gdb sees the launcher; this script tells it about the program the
# launcher loaded and the libraries its loader mapped, so that no manual command is needed. It needs the exclave
# in gdb's auto-load safe-path. The launcher exports what the script reads: exclave_original_base, _entry, _path,
# exclave_interp_base, _path, and exclave_debug_hook, a function called once before the jump into the program.
import os
import gdb


def _u64(addr):
    return int.from_bytes(bytes(gdb.selected_inferior().read_memory(addr, 8)), "little")


def _var(name):
    return int(gdb.parse_and_eval("*(unsigned long *)&" + name))


def _path(name):
    return gdb.parse_and_eval("(char *)&" + name).string()


def _quiet(cmd):
    old = gdb.parameter("confirm")
    gdb.execute("set confirm off")
    try:
        return gdb.execute(cmd, to_string=True)
    finally:
        if old:
            gdb.execute("set confirm on")


def _exclave_tree():
    exe = gdb.current_progspace().filename
    if not exe:
        return None
    d = os.path.dirname(os.path.realpath(exe))
    while d and d != "/":
        if os.path.exists(os.path.join(d, ".exclave", "manifest")):
            return os.path.join(d, "tree")
        d = os.path.dirname(d)
    return None


def _in_tree(root, v):
    """A virtual path resolved inside root as a chroot would resolve it (7.4.4); None when a component is missing or the links loop."""
    cur, parts, hops = "", [p for p in v.split("/") if p and p != "."], 0
    while parts:
        p = parts.pop(0)
        if p == "..":
            cur = cur.rsplit("/", 1)[0] if "/" in cur else ""
            continue
        cand = cur + "/" + p
        real = root + cand
        if os.path.islink(real):
            hops += 1
            if hops > 40:
                return None
            t = os.readlink(real)
            parts = [q for q in t.split("/") if q and q != "."] + parts
            if t.startswith("/"):
                cur = ""
        elif os.path.exists(real):
            cur = cand
        else:
            return None
    return cur


def _file_for(root, v):
    """The file gdb should read for virtual path v: the original of a wrapper in the tree, the tree's file, or the host's."""
    if root:
        cur = _in_tree(root, v)
        if cur:
            real = root + cur
            d, b = os.path.split(real)
            payload = os.path.join(d, ".real", b)
            return payload if os.path.exists(payload) else real
    return v if os.path.exists(v) else None


def _add(state, path, bias):
    if bias in state["loaded"] or not path:
        return
    state["loaded"].add(bias)
    _quiet('add-symbol-file "%s" -o %#x' % (path.replace("\\", "\\\\").replace('"', '\\"'), bias))   # an exclave may live under a path with a space


def _r_debug():
    for sym, indirect in (("_r_debug", False), ("_dl_debug_addr", True)):   # glibc's struct; musl's pointer to it
        try:
            a = int(gdb.parse_and_eval("(unsigned long)&" + sym))
        except gdb.error:
            continue
        return _u64(a) if indirect else a
    return 0


def _libraries(state):
    """Every entry of the loader's link map: l_addr, l_name, l_ld, l_next, l_prev; the first is the program."""
    rd = _r_debug()
    if not rd:
        return
    lm, first = _u64(rd + 8), True
    while lm:
        l_addr, l_name, l_next = _u64(lm), _u64(lm + 8), _u64(lm + 24)
        if not first and l_name:
            name = gdb.selected_inferior().read_memory(l_name, 4096).tobytes().split(b"\0", 1)[0].decode("utf-8", "replace")
            if name:
                _add(state, _file_for(state["root"], name), l_addr)
        first, lm = False, l_next
    if not state.get("brk") and _u64(rd + 16):
        state["brk"] = _Reload(_u64(rd + 16), state)


class _Reload(gdb.Breakpoint):
    """r_brk: the loader calls it after every dlopen and dlclose (RT_CONSISTENT); the map is read again."""
    def __init__(self, addr, state):
        super().__init__("*%#x" % addr, internal=True)
        self.state = state

    def stop(self):
        _guarded(_libraries, self.state)
        return False


class _Entry(gdb.Breakpoint):
    """The program's entry point: by now the loader has mapped every library and filled its link map."""
    def __init__(self, addr, state):
        super().__init__("*%#x" % addr, internal=True, temporary=True)
        self.state = state

    def stop(self):
        _guarded(_libraries, self.state)
        return False


def _guarded(fn, *args):
    """A failure of this script must never stop the program: gdb stops on an exception in a breakpoint's stop."""
    try:
        fn(*args)
    except (gdb.error, gdb.MemoryError, OSError, ValueError) as e:
        gdb.write("exclave-launcher.py: %s\n" % e, gdb.STDERR)


class _Hook(gdb.Breakpoint):
    """exclave_debug_hook: the launcher has mapped the program and its loader and is about to jump."""
    def __init__(self):
        super().__init__("exclave_debug_hook", internal=True)

    def stop(self):
        _guarded(self._hook)
        return False

    def _hook(self):
        state = {"root": _exclave_tree(), "loaded": set(), "brk": None}
        _add(state, _path("exclave_original_path"), _var("exclave_original_base"))
        interp = _path("exclave_interp_path")
        if interp:
            _add(state, interp, _var("exclave_interp_base"))
        _Entry(_var("exclave_original_entry"), state)


def _arm():
    """One hook breakpoint per session: the script runs again at every exec of a launcher, and a breakpoint made
    while gdb is still relocating the new image cannot be inserted yet, so a failed attempt is retried when gdb
    is next idle."""
    if getattr(gdb, "_exclave_hook", None) is not None and gdb._exclave_hook.is_valid():
        return
    try:
        gdb._exclave_hook = _Hook()
    except gdb.error:
        gdb._exclave_hook = None
        gdb.post_event(_arm)


gdb.execute("handle SIGSYS nostop noprint pass", to_string=True)   # every translated syscall is a SIGSYS (7.4.1)
_arm()
