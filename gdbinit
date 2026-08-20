directory /home/luo/Qemu6
file /home/luo/Qemu6/build/qemu-x86_64
set args /home/luo/test/sigsegv

b main
b host_signal_handler
b handle_pending_signal
b dump_core_and_abort
b accel/tcg/cpu-exec.c:810
run
