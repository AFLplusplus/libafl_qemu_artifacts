# Windows NTFS Fuzzing - Target Harness

The source code of the windows-side fuzzer's harness is made available here.

## Versions

To make replication as easy as possible, we provide here a list of the various tools used to build the Windows-side harness.
Maybe other versions will work, maybe not.

**Build environment**:
- OS: Windows 10 19045.3930
- IDE: Visual Studio Version 17.8.5
- .NET Framework: Version 4.8.09037
- Compiler toolchain: Visual C++ 2022 - 00482

**Target environment**:
- OS: Windows 10 ... (installed via the disk image called `Win10_22H2_English_x64v1.iso` (SHA256: `a6f470ca6d331eb353b815c043e327a347f594f37ff525f17764738fe812852e`), downloadable on Microsoft's official webside - see below). No updates were performed after installation.

## Build

Building must be done through Visual Studio (no easier solution was found) in a Windows 10 environment.

Import the Project `LibaflNtfsFuzz` in Visual Studio.
Three targets are available:
- `Debug`: Builds a debug version of the target without going through the fuzzer, with a mock command interface. Convenient during harness development without having to run it through the fuzzer. The final executable is generated in the root directory of the project with the name `LibaflNtfsFuzz_Debug`.
- `Release`: Similar to `libafl`. Can be ignored.
- `libafl`: Builds a libafl-compatible version of the harness. It should be run in LibAFL QEMU, using the LibAFL fuzzer. The final executable is generated in the root directory of the project with the name `LibaflNtfsFuzz_libafl`.
- `nyx`: Builds a Nyx-compatible version of the harness. It should be run in Nyx, using the Nyx fuzzer. The final executable is generated in the root directory of the project with the name `LibaflNtfsFuzz_nyx`.

## Run

Once the applications are built, they should be imported and executed at boot time in the target VM in one way or another.
We provide an example of a walkthrough that could be followed to obtain a working setup.
You may have to adapt it depending on your own environment.

### Walkthrough

- **Get a runnable Windows VM**: The easiest solution is to [get a Windows 10 Disk Image](https://www.microsoft.com/en-us/software-download/windows10ISO) and install Windows 10 on an empty QCOW2 disk. Typically, 16GB should be enough. 4 GB of RAM at least is necessary. An example of QEMU command you could use to install Windows can be found below. **Warning**: use a QEMU command as close as possible to fuzzer's QEMU command to avoid problems during fuzzing. The version of QEMU (as well as the accelerator) used for setup and fuzzing should be the same. Otherwise, you will likely meet many issues. Please also install [OSFMount](https://www.osforensics.com/tools/mount-disk-images.html) alongside Windows to get RAM Disks working.

- **Install the harness**: Put the previously built harness on a QCOW2 disk (you could insert another QCOW2 disk for example, or copy the files on the main disk) and the corresponding script (can be found in the `scripts` subdirectory - choose depending on the experiment). Our script opens the harness present in the volume `F:`, please adapt the path to your needs. A dummy disk `ref.vhd` (similar to the one generated as seed, you can reuse the same) should be present in the same folder as the target-side harness.

- **Autorun the script at boot**: The easiest option is to create a task in Windows' **Task Scheduler** to schedule the script to run when Windows boots. Please check online for detailed instructions on how to create such a task.

We recommend using QEMU's snapshots (`-snapshot` option) for the LibAFL experiment to avoid waiting for booting each time (it is very long - around 5 to 10 mins depending on your hardware). kAFL does not work well with QEMU snapshots, but it is less important since boot is done after a few seconds.

In general, create backups of your disks before performing any fuzzing on them. It should not be a problem, but
it could possibly become unstable in case of a mismanipulation. 

At this point, you should have a ready-to-use VM. Now, it's time to start fuzzing.
You can run either LibAFL QEMU (check `fuzzers/libafl`) or kAFL / Nyx (check `fuzzers/kafl`).