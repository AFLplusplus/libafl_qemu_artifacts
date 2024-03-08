# kAFL / Nyx experiment

The experiment was run on an x64 machine under Ubuntu 22.04.
The CPU was an `11th Gen Intel(R) Core(TM) i5-11400 @ 2.60GHz`.
We last run the experiment with the commit `d94f27f5140ac394f105f0d8997cc2aaa6eeefb1`.

## Instructions

- Clone and deploy [kAFL](https://github.com/IntelLabs/kAFL).
- Run the previously created Windows VM with both `LibaflNtfsFuzz_nyx.exe` and `fuzz_nyx.cmd` to the VM.
- run kAFL with the newly created disk. Here is an example of a command you could use, but you may have to adapt it to have it working on your side.

**The command uses `--purge`, which will reset the working directory at each restart of the fuzzer.**

```bash
kafl fuzz --purge \
	-m 4096 \
	--qemu-extra "-drive if=ide,format=qcow2,file=windows.qcow2 -drive if=pflash,format=qcow2,file=OVMF_CODE.qcow2 -drive if=pflash,format=qcow2,file=OVMF_VARS.qcow2 -nographic" \
	--seed-dir=seed \
	--log-hprintf \
	--append "" \
	-v \
	-l \
	-t 10 \
	-ts 10
```

*Note*: We use OVMF to have the boot working correctly on our side. You can grab these files from the QEMU project (or from `/usr/share/edk2/x64` if you have QEMU installed on your host).
