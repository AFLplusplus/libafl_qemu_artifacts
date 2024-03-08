# Windows NTFS Fuzzing - Target Harness

Here is the root directory of the Windows NTFS Fuzzing artifacts.

## Overview

- target_harness/: Windows code to run in the target VM. **Please start here if you wish to reproduce the experiments.**
- fuzzers/: Home directory of the fuzzers built and compared in the paper.
    - kafl/: kAFL / Nyx fuzzer's home directory. Go there to get the instructions to replicate the kAFL experiment.
    - libafl/: LibAFL fuzzer's home directory. Go there to get the code to replicate the LibAFL experiment.

Generally speaking, these instructions should be taken with a grain of salt. You may have to adapt parts of the scripts & commands specified there, since each build environment differs.


## About reproducibility

Unfortunately, it is tough to come up with a point-and-click reproducible experiment when it comes to Windows, mostly for licensing reasons.
We are trying (at the time of writing these lines) to come up with an easier approach than the current one, but we cannot provide any guarantee.
It is challenging to setup Windows targets properly (especially for kAFL / Nyx because they are based on an old version of QEMU).
Feel free to reach out at `romain [dot] malmain [at] eurecom [dot] fr` if you encounter problems while trying to reproduce the Windows-related experiments.

## Seed generation

For our experiments, we generated seeds using the `diskmgmt.msc` tool available in Windows 10.
Once the tool is open, simply click on `Action > Create VHD`.
We used a size of 128M and the `VHD` format with `Fixed size`.
Once the disk was created, we initialized it (by scrolling the list of disks until our newly created disk appeared) with a `GPT` partition table and an `NTFS` File system and a `Default` Allocation unit size also with `diskmgmt.msc`.