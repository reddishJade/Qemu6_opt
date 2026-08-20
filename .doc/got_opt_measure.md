# CONFIG_INDIRECT_JUMP_OPT_GOT 最小验证/测量

脚本：

```sh
bash scripts/got-opt-measure.sh
```

它会生成一个很小的 x86_64 guest：

- `got_call_once()` 执行 `call *got_target@GOTPCREL(%rip)`
- `got_jmp_once()` 执行 `jmp *got_target@GOTPCREL(%rip)`
- `objdump` 会先确认 guest 里确实存在 RIP-relative indirect `call/jmp`

默认对比两个 QEMU：

```sh
QEMU_GOT_ON=build-got-on/qemu-x86_64 \
QEMU_GOT_OFF=build-got-off/qemu-x86_64 \
bash scripts/got-opt-measure.sh
```

如果还没有两套构建，可以让脚本按当前仓库已有的 linux-user/x86_64 debug 配置生成：

```sh
bash scripts/got-opt-measure.sh --build-qemu
```

如果 x86_64 guest 动态库需要指定运行时 sysroot，沿用 QEMU linux-user 的变量：

```sh
QEMU_LD_PREFIX=/path/to/x86_64/sysroot bash scripts/got-opt-measure.sh
```

输出里重点看：

```text
got: indirect_call=... indirect_jmp=... rip_call=... rip_jmp=... slot_readable=... target_exec=... target_changed=...
got_runtime: guard_hits=... guard_misses=...
hit_condition: rip_call>0 && rip_jmp>0 && slot_readable>0 && target_exec>0 && guard_hits>0 => yes/no
```

预期：

- `got-on` 使用 `--enable-indirect-jump-opt-got-debug` 构建时，应出现 `got:` / `got_runtime:` 统计。
- 命中条件成立时，`rip_call`、`rip_jmp`、`slot_readable`、`target_exec`、`guard_hits` 都应大于 0。
- 当前 guest 使用稳定的动态函数 GOT 入口，正常情况下 `target_changed=0`；如果后续要测 GOT 运行期改写，可保留同一脚本框架替换 guest 工件。
- `got-off` 未开启 debug 时通常显示 `counters: unavailable`，用于确认关闭优化后不会走 GOT debug 统计路径。
