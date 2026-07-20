Indirect branch profiling
=========================

``--enable-indirect-profile`` instruments x86 ``FF /2`` indirect calls and
``FF /4`` indirect jumps (the ``jmp *r/m`` form), plus near returns ``C2`` and
``C3``.  Direct jumps are not recorded.  CSV labels are ``indirect_call``,
``indirect_jmp``, and ``indirect_ret``.  The
instrumented build is intended for target-distribution profiling only; its
execution time is not a performance result.

For the unbiased baseline profile, enable the profiler with PbRP disabled.  It
is independent of ``--disable-tcg-stats``::

  ../configure --extra-cflags="-O2" \
      --enable-linux-user --target-list=x86_64-linux-user \
      --prefix=/usr --sysconfdir=/etc \
      --libdir=/usr/lib/x86_64-linux-gnu \
      --libexecdir=/usr/lib/qemu \
      --interp-prefix=/home/dongwei/lib/qemu-binfmt/%M \
      --disable-docs --disable-werror --disable-blobs \
      --disable-reg-opt --disable-inst-opt --disable-func-opt \
      --disable-ret-opt --disable-tcg-stats \
      --enable-indirect-profile
  make -j$(nproc)

First verify that the translator starts and exits normally with an x86-64
guest executable::

  QEMU_INDIRECT_PROFILE_OUT=/tmp/hello.csv \
      ./qemu-x86_64 /path/to/x86_64/hello
  test -s /tmp/hello.csv
  head /tmp/hello.csv

The CSV always contains a header.  A minimal or statically linked hello-world
may have no profiled branches, so a header-only file is valid.  To verify that
the branch records themselves work, run a dynamically linked program or a
small x86-64 test that calls functions through function pointers.

Set ``QEMU_INDIRECT_PROFILE_OUT`` to select the CSV output file::

  QEMU_INDIRECT_PROFILE_OUT=/tmp/perlbench.csv \
      ./qemu-x86_64 /path/to/perlbench [arguments]

Use ``%p`` in the path for workloads that fork.  It expands to the host QEMU
process ID and prevents parent and child processes from overwriting each
other::

  QEMU_INDIRECT_PROFILE_OUT=/tmp/perlbench-%p.csv ./qemu-x86_64 ...

After a guest fork, the child starts with an empty profile rather than the
parent's inherited observations.

Without the variable, QEMU writes ``indirect-profile-<pid>.csv`` in its
current directory.  Each row represents one static guest branch site.  The
four target entries use the Space-Saving algorithm: ``count`` is an estimated
frequency and ``error`` is its maximum overestimate.  A zero error means the
count is exact.  ``replacements`` indicates that the site observed more target
variation than the four retained entries could represent exactly.
