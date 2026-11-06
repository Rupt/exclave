"""A user the host knows from SSSD, looked up inside an exclave (DESIGN.md 8.4, 13 item 17).

    test/nss_test.py --exclave EXCLAVE [--musl EXCLAVE] [--work DIR]

The exclave holds SSSD's lookup module, libnss_sss.so.2, and getent: scripts/inputs makes
sss.exclave, Ubuntu's Essential set with libnss-sss added. In a user namespace a tmpfs on /var/lib
holds the socket of a stand-in for SSSD served here, which answers one user by name and by uid in
SSSD's protocol (sssd's src/sss_client/sss_cli.h), and an nsswitch.conf naming sss and winbind for
users and mdns4_minimal for hosts stands over the host's. getent inside the exclave answers the
user both ways, as it would on a host whose users come from LDAP through SSSD; exclave check, under
the same nsswitch.conf, warns of no module for sss and of winbind's and mdns4_minimal's, naming
their packages; and with --musl, on a musl exclave, it warns that the users of sss and winbind are
found only through the host's nscd and that mdns4_minimal's names are not found. Says so and exits
0 when it cannot run, without user namespaces or with a work directory too deep for the socket's
path.
"""

import argparse
import os
import shutil
import socketserver
import struct
import subprocess
import sys
import threading
lazy import socket

import tree

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

# SSSD's NSS protocol: a 16-byte header of four native words, the whole length, the command, a
# status (an errno, 0 for success) and a reserved word, then the body
GET_VERSION, GETPWNAM, GETPWUID = 0x0001, 0x0011, 0x0012
NAME, UID, GID = f"exclave-sss-{os.getpid()}", 4000000 + os.getpid() % 100000, 4000000
ENTRY = (NAME, "*", "a user from SSSD", f"/home/{NAME}", "/bin/sh")


def answer(cmd: int, body: bytes) -> tuple[int, bytes]:
    """The status and body SSSD answers cmd with: the user, or no result."""
    if cmd == GET_VERSION:
        return 0, struct.pack("=I", 1)
    if cmd in (GETPWNAM, GETPWUID):
        if cmd == GETPWNAM:
            hit = body.rstrip(b"\0") == NAME.encode()
        else:
            hit = len(body) >= 4 and struct.unpack("=I", body[:4])[0] == UID
        if not hit:
            return 0, struct.pack("=II", 0, 0)
        strings = b"".join(s.encode() + b"\0" for s in ENTRY)
        return 0, struct.pack("=IIII", 1, 0, UID, GID) + strings
    return 38, b""  # ENOSYS for anything else


class Handler(socketserver.BaseRequestHandler):
    """One client: requests answered until it closes."""

    def handle(self) -> None:
        conn: socket.socket = self.request
        while True:
            head = recv_all(conn, 16)
            if head is None:
                return
            length, cmd, _status, _reserved = struct.unpack("=IIII", head)
            body = recv_all(conn, max(length - 16, 0)) or b""
            status, reply = answer(cmd, body)
            conn.sendall(struct.pack("=IIII", 16 + len(reply), cmd, status, 0) + reply)


def recv_all(conn: socket.socket, n: int) -> bytes | None:
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def in_namespace(work: str, cmd: str) -> subprocess.CompletedProcess[str]:
    """Run cmd in a user and mount namespace with the test's /var/lib/sss and nsswitch.conf."""
    setup = (
        "mount -t tmpfs tmpfs /var/lib && mkdir /var/lib/sss && "
        f"mount --bind {work}/sss /var/lib/sss && "
        f"mount --bind {work}/nsswitch.conf /etc/nsswitch.conf || exit 99; "
    )
    return subprocess.run(
        ["unshare", "-Urm", "sh", "-c", setup + cmd],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
        env={"PATH": "/usr/bin:/bin", "HOME": work},
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "--exclave", required=True, help="an exclave holding libnss_sss.so.2 and getent"
    )
    ap.add_argument("--musl", help="a musl exclave, whose check warns of musl's own case")
    ap.add_argument("--work", default=os.path.join(REPO, "build", "nss-work"))
    args = ap.parse_args()
    if subprocess.run(["unshare", "-Urm", "true"], capture_output=True, check=False).returncode:
        print("nss: cannot run here: no user namespaces")
        return 0
    work = os.path.abspath(args.work)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(os.path.join(work, "sss", "pipes"))
    ex = tree.fresh_exclave(os.path.abspath(args.exclave), os.path.join(work, "sss.exclave"))
    root = os.path.join(ex, "tree")
    if not any(
        f == "libnss_sss.so.2" for _d, _s, fs in os.walk(os.path.join(root, "usr")) for f in fs
    ):
        sys.exit(f"no libnss_sss.so.2 in {args.exclave}")
    with open(os.path.join(work, "nsswitch.conf"), "w") as f:
        f.write("passwd: files sss winbind\ngroup: files sss\nhosts: files mdns4_minimal dns\n")
    path = os.path.join(work, "sss", "pipes", "nss")
    if len(path.encode()) > 107:
        print(
            f"nss: cannot run here: the socket's path passes the 107 bytes sun_path holds: {path}"
        )
        return 0
    server = socketserver.ThreadingUnixStreamServer(path, Handler)
    server.daemon_threads = True
    os.chmod(path, 0o666)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    fails = 0
    try:
        getent = os.path.join(root, tree.vbin(root, "getent").lstrip("/"))
        line = ":".join([NAME, "*", str(UID), str(GID), *ENTRY[2:]])
        for key in (NAME, str(UID)):
            p = in_namespace(work, f"{getent} passwd {key}")
            if p.returncode == 99:
                print(f"nss: cannot run here: {p.stderr.strip()[-120:]}")
                return 0
            ok = p.returncode == 0 and p.stdout == line + "\n"
            got = f"{p.stdout.strip()!r} {p.stderr.strip()!r}"
            print(f"{'ok' if ok else 'FAIL'}: getent passwd {key}: {got}")
            fails += not ok
        # the check, given a log, under the same nsswitch.conf: the module the exclave ships is not
        # named, the one it lacks is, with its package
        log = os.path.join(work, "getent.log")
        p = in_namespace(
            work,
            f"EXCLAVE_LOG={log} {getent} passwd {NAME} >/dev/null; {tree.TOOL[0]} check {ex} {log}",
        )
        warns = [x for x in p.stdout.split("\n") if "nsswitch.conf" in x]
        ok = (
            len(warns) == 2
            and "names mdns4_minimal" in warns[0]
            and "libnss-mdns" in warns[0]
            and "names winbind" in warns[1]
            and "libnss-winbind" in warns[1]
        )
        got = f"{warns!r} {p.stderr[-200:]!r}"
        what = "exclave check warns of mdns4_minimal and winbind, not sss"
        print(f"{'ok' if ok else 'FAIL'}: {what}: {got}")
        fails += not ok
        if args.musl:
            # a musl tree: no module loads, users and groups only through the host's nscd
            mx = tree.fresh_exclave(os.path.abspath(args.musl), os.path.join(work, "musl.exclave"))
            mroot = os.path.join(mx, "tree")
            msh = os.path.join(mroot, tree.vbin(mroot, "sh").lstrip("/"))
            mlog = os.path.join(work, "musl.log")
            p = in_namespace(
                work, f"EXCLAVE_LOG={mlog} {msh} -c true; {tree.TOOL[0]} check {mx} {mlog}"
            )
            warns = [x for x in p.stdout.split("\n") if "nsswitch.conf" in x]
            ok = (
                len(warns) == 2
                and "names sss, winbind for users or groups" in warns[0]
                and "nscd" in warns[0]
                and "names mdns4_minimal; musl loads no NSS modules" in warns[1]
                and "nscd" not in warns[1]
            )
            got = f"{warns!r} {p.stderr[-200:]!r}"
            what = "on musl, users through nscd and mdns4_minimal unknown"
            print(f"{'ok' if ok else 'FAIL'}: {what}: {got}")
            fails += not ok
    finally:
        server.shutdown()
        server.server_close()
    print(f"nss: {fails} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
