# LibAFL QEMU Windows Kernel Fuzzing

This folder contains the `LibAFL QEMU` Windows Kernel fuzzer.

**This example is not standalone and requires building the Windows VM as well as the target harness for the reasons explained in the root directory of the Windows artifacts. You will also need to generate the initial seed from Windows. Please refer to the root directory of the Windows fuzzer artifacts for more information.**

## Build

To build the fuzzer, run

```bash
LIBAFL_EDGES_MAP_SIZE=65536 cargo build --release
```

## Run

You will need first to create a bunch of directories.

```bash
mkdir -p corpus_initial corpus_generated crashes
```

Please copy in `corpus_initial` any seed you would like to use.

```bash
./target/release/qemu_windows_ntfs \
	--qemu-args " \
		-L $PWD/target/release/qemu-libafl-bridge/build/qemu-bundle/usr/local/share/qemu \
		-accel accel=tcg \
		-smp 1 \
		-m 4G \
		-drive if=ide,format=qcow2,file=windows.qcow2 \
		-drive if=pflash,format=qcow2,file=OVMF_CODE.qcow2 \
		-drive if=pflash,format=qcow2,file=OVMF_VARS.qcow2 \
		-device VGA \
		-nographic" \
	--initial-corpus-dir=$PWD/corpus_initial/ \
	--generated-corpus-dir=$PWD/corpus_generated/ \
	--crashes-dir=./crashes/ \
	--result-output=results.json
```

This will run the fuzzer with QEMU normal snapshots and not JIT'ed edge coverage feedback.

*Note*: We use OVMF to have the boot working correctly on our side. You can grab these files from the QEMU project (or from `/usr/share/edk2/x64` if you have QEMU installed on your host).


### Notable additional options

- `-j`: The edge coverage code is JIT'ed
- `-s`: Use Fast Snapshots instead of classic QEMU Snapshots.