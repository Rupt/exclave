This directory is an exclave: Linux software packed with the
libraries and files it needs, so that its programs run from here, by
path, with nothing installed. It was made by exclave, a tool that
builds such directories. It runs on Linux 3.10 or later, on the
machine type it was built for ("file .exclave/launcher" names it),
with no root, setup step, daemon or container, and running it changes
nothing in tree/ or .exclave/ and leaves nothing behind. It is not a
sandbox: its programs run as you, with your files and your network.

What is here

  tree/              the software's own /: usually the packages listed
                     in .exclave/hashes, unpacked as if installed.
  .exclave/launcher  a small program that starts the others. Every
                     program in tree/ is a hard link to it, a
                     "wrapper"; the original sits in a hidden .real/
                     directory beside it, and running tree/usr/bin/NAME
                     runs tree/usr/bin/.real/NAME inside the exclave.
  .exclave/manifest  the maker's settings; "exclave 1" alone means none.
  .exclave/hashes    one "pkg" line per package that went in: name,
                     version, architecture and hash of the package
                     file; then hashes of the launcher, the manifest
                     and, on the "tree" line, all of tree/. Not where
                     they came from.
  other names        shortcuts into tree/ that the maker added.

A hashes file with no "tree" line marks an unwrapped, unfinished
exclave: its programs would use this system's libraries.

Running it

With EX the path of this directory, run from your own directory:

  EX/NAME ARGS...                    a shortcut, if the maker made one
  EX/tree/usr/bin/NAME ARGS...       any program in the exclave
  EX/tree/bin/sh                     a shell inside the exclave, if it
                                     has one
  EX/.exclave/launcher PROG ARGS...  PROG run inside the exclave: one of
                                     your own, such as one the
                                     exclave's compiler built, or an
                                     exclave path, /usr/bin/NAME

A symlink to a program in tree/ works too; a copy does not, and a
program run straight from .real/ is likely to fail.

Inside, a program sees the top-level directories that tree/ fills,
/usr, /etc, /lib and the rest, as its own, read-only: writing there
fails as on a read-only disk. Everything else is this system's: /home,
/tmp, /proc, /dev, the working directory, and eight files such as
/etc/passwd and /etc/resolv.conf that say who you are and how network
names are looked up. PATH is the exclave's, so this system's commands
are not found by name. The locale is C.UTF-8 and the time zone UTC by
default, and sudo, su and other setuid programs do not work inside.

EXCLAVE_LOG=/some/file makes every process append one line per call
that names a file: the call, its result and the path. Messages that
begin "launcher:" come from the exclave, not from the program.

Moving, copying, removing

Nothing outside this directory refers to it: move it, copy it with
cp -a, pack it with tar, or remove it with rm -r. A copy that splits
the hard links (cp -r) still runs, larger by the launcher's size per
program. Do not edit a program in tree/ in place: they are all one
file. An exclave does not run from a filesystem mounted noexec.

Checking it

The hashes are BLAKE2b-256, so "b2sum -l 256 .exclave/launcher" prints
the recorded launcher hash, and a package file fetched again its pkg
hash. The exclave tool, which builds these directories, is not part
of this one:

  exclave check DIR   every program wrapped, the libraries each needs
                      found inside, tree/ against its recorded hash
  exclave unwrap DIR  unwrap the exclave for editing; exclave wrap DIR
                      wraps it again
  exclave relink DIR  put in another launcher, relinking every program

Licences

The software in tree/ keeps its packages' licences, and passing this
directory on passes their terms on with it. Their texts are in
tree/usr/share/doc/*/copyright and tree/usr/share/common-licenses/
(Debian, Ubuntu) or tree/usr/share/licenses/ (Fedora and others);
exclave prune keeps them. An Alpine package's licence text comes in
its -doc package, so an Alpine exclave has it only if that went in.
The launcher is part of exclave, Copyright (c) 2026 Rupert Tombs,
under the MIT licence, whose text it carries: "readelf -p
.exclave.license .exclave/launcher" prints it.

This file is the same in every exclave; a maker may replace it.
