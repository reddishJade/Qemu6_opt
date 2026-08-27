Indirect branch profiling
=========================

``--enable-indirect-profile`` instruments x86 ``FF /2`` indirect calls and
``FF /4`` indirect jumps (the ``jmp *r/m`` form), plus near returns ``C2`` and
``C3``.  Direct jumps are not recorded.  CSV labels are ``indirect_call``,
``indirect_jmp``, and ``indirect_ret``.  The
instrumented build is intended for target-distribution profiling only; its
execution time is not a performance result.

The profiler is the analysis phase that precedes PBRP and RFICH.  Configure
rejects combinations with either optimization so that the measured target
distribution remains unbiased.  It is independent of
``--disable-tcg-stats``::

  ../configure --extra-cflags="-O2" \
      --enable-linux-user --target-list=x86_64-linux-user \
      --prefix=/usr --sysconfdir=/etc \
      --libdir=/usr/lib/x86_64-linux-gnu \
      --libexecdir=/usr/lib/qemu \
      --interp-prefix=/home/dongwei/lib/qemu-binfmt/%M \
      --disable-docs --disable-werror --disable-blobs \
      --disable-reg-opt --disable-inst-opt --disable-func-opt \
      --disable-pbrp --disable-rfich --disable-tcg-stats \
      --enable-indirect-profile
  make -j$(nproc)

First verify that the translator starts and exits normally with an x86-64
guest executable::

  ./qemu-x86_64 /path/to/x86_64/hello
  profile=$(ls -t indirect-profile-*.csv | head -n 1)
  test -s "$profile"
  head "$profile"

The CSV always contains a header.  A minimal or statically linked hello-world
may have no profiled branches, so a header-only file is valid.  To verify that
the branch records themselves work, run a dynamically linked program or a
small x86-64 test that calls functions through function pointers.

QEMU writes ``indirect-profile-<pid>.csv`` in its current directory without
requiring a runtime environment variable.  The PID suffix prevents forked
processes from overwriting each other; each child starts with an empty profile
rather than inherited observations.  Each row represents one static guest
branch site.  The
four target entries use the Space-Saving algorithm: ``count`` is an estimated
frequency and ``error`` is its maximum overestimate.  A zero error means the
count is exact.  ``replacements`` indicates that the site observed more target
variation than the four retained entries could represent exactly.
