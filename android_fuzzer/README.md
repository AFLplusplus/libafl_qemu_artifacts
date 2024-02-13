# Android Library Fuzzing with LibAFL QEMU

Where to start? There is a fairly known closed source parsing library on Samsung devices, `libimagecodec.quram.so`.

This library was fuzzed firstly by Project Zero (blogpost [here](https://googleprojectzero.blogspot.com/2020/07/mms-exploit-part-1-introduction-to-qmage.html)) with some custom hacks to QEMU and later on by @flankerhqd (video [here](https://www.youtube.com/watch?v=y05uja2o6GE)) with a different harness and a custom fuzzer based on Unicorn. From this last presentation, we borrow the ideas from the few slides describing the harness.

## Requisites

You need to download some garbage on your Linux box before starting:

 - Root folder of the Firmware for Samsung Galaxy A70 SM-A7050 Android Pie 9, from https://samsony.net/en/mobiles/SM-A7050/download/2021
 - Android NDK r21d, from https://developer.android.com/ndk/downloads
 - Rust, with https://rustup.rs/
 - C compiler/autotools/etc...

If you never unpacked a Samsung firmware, this is what you have to do IIRC:

 - Extract the ZIP archive content
 - Inside `AP_A7050ZCU5ATA2_CL17532319_QB28570117_REV00_user_low_ship_MULTI_CERT_meta_OS9.tar.md5` there is `system.ext4.lz4`, the system folder of the phone containing the libraries, the loader and more.
 - Extract the image using `unlz4 system.img.ext4.lz4`, convert it to a raw img using `simg2img system.img.ext4 system.img` and then now we can mount the ext4 filesystem and access its content with `sudo mount -t ext4 -o loop system.img system/`

If the procedure changed as I did it long time ago send a PR please.

## Harnessing and linking around

If you are into reverse engineering, it is not difficult to understand what to reverse starting from the flow graphs in the Flanker's slides. I used Ghidra and got a working harness to fuzz the DNG and JPEG image parsers in the library easily, I will not discuss the reversing details here. What you have to know is that I did two harnesses, one simple and useful while developing the fuzzer, another more complex triggering the juicy paths.

The simple one is, well, simple:

```C
int QuramGetImageInfoFromFile2(char *filename, int zero1, int zero2, int *w, int *h, int* getImageOut1, int* getImageOut2);
int QrParseMetadata(char *filename, unsigned int* metadata);

void harnessSimple(char* filename) {
  int w, h, a, b;
  unsigned int metadata[71] = {0};

  if (QuramGetImageInfoFromFile2(filename, 0, 0, &w, &h, &a, &b) == 0) {
    QrParseMetadata(filename, metadata);
  }
}

int main(int argc, char** argv) {
  harnessSimple(argv[1]);
  return 0;
}
```

Here for you the commands, this time was fairly simple, no chains of find+grep to find libraries needed from your side:

```
# build
./android-ndk-r21d/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang -c harness.c
# link
./android-ndk-r21d/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang++ harness.o -L system/system/lib64/ -llog -limagecodec.quram -lz -ljnigraphics -Wl,-rpath=system/system/lib64/ -o harness
```

The quram libs are in `system/system/lib64/`.

You can test the binary with a normal qemu usermode, for instance the one installed from the repos of your distro with:

```
QEMU_LD_PREFIX=./system/ qemu-aarch64 ./harness dng_seeds/not_kitty.dng
```

The other harness is more complex and it is made to invoke the `QrDecodeDNGFile` routine, not simply to parse the image metadata.


## Building the fuzzer

To build the fuzzer and use QASan, you must inform cargo of the aarhc64 NDK cross compiler path, something like:

```
CROSS_CC=/path/to/android-ndk-r21d/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang cargo build --release
```
