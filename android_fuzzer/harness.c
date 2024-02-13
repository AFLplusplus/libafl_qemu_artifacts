/*
Our target is system/system/lib64/libimagecodec.quram.so.

From a public exposed JNI function, Java_com_sec_samsung_gallery_decoder_QuramCodecInterface_nativeDecodeFile,
we can see that QuramGetImageInfoFromFile2 is called and it is a possible attack surface.

After reversing a bit, we know that the prototype for that function is

int QuramGetImageInfoFromFile2(char *filename, int zero1, int zero2, int *w, int *h, int* decinfo_part1, int* decinfo_part2);

In the JNI function, if the call to QuramGetImageInfoFromFile2 returns 0, QrParseMetadata is then called.

int QrParseMetadata(char *filename, char *metadata);

Always reversing the JNI wrapper, we know that the metadata buffer has size 0x11c.

Compile and test with:

./android-ndk-r21d/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang -c harness.c
./android-ndk-r21d/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang++ harness.o -L system/system/lib64/ -llog -limagecodec.quram -lz -ljnigraphics -Wl,-rpath=system/system/lib64/ -o harness
*/

#include <stdlib.h>
#include <string.h>
#include <signal.h>

void removeSignalHandlers(void) {
  signal(SIGABRT, SIG_DFL);
  signal(SIGFPE, SIG_DFL);
  signal(SIGSEGV, SIG_DFL);
  signal(SIGILL, SIG_DFL);
  signal(SIGBUS, SIG_DFL);
}

int QuramGetImageInfoFromFile2(char *filename, int zero1, int zero2, int *w, int *h, int* getImageOut1, int* getImageOut2);
int QrParseMetadata(char *filename, unsigned int* metadata);

void parseQPNG_icc(char* filename, int zero, int* getImageOut1);
int QrDecodeDNGFile(char* filename, void* bmapPixelsAddr, int zero, int flag, unsigned int* parsedMeta);

int harnessDecode(char* filename) {
    int nativeInt = 5; // or 3
    unsigned int inSampleSize = 3; // common
    char flagX01 = 0; // '\x01';

    unsigned int meta[71];
    unsigned int nativeIntFlag = 0;
    int w, h, getImageOut1, getImageOut2;
    int ret = QuramGetImageInfoFromFile2(filename, 0, 0, &w, &h, &getImageOut1, &getImageOut2);
    // printf("QuramGetImageInfoFromFile2 %d (%d, %d)\n", ret, w, h);
    if (ret == 3) {
      parseQPNG_icc(filename, 0, &getImageOut1);
    }
    unsigned int* parsedMeta = (unsigned int*)malloc(0x48);
    if (!parsedMeta) {
      return 0;
    }
    memset(parsedMeta, 0, 0x48);
    parsedMeta[6] = inSampleSize;
    if (nativeInt == 5) {
      nativeIntFlag = 7;
      parsedMeta[7] = 7;
    }
    else {
      if (nativeInt == 3) {
        nativeIntFlag = 0;
        parsedMeta[7] = 0;
      }
      else {
        nativeIntFlag = 0;
      }
    }
    parsedMeta[8] = (unsigned int)(flagX01 == '\x01');
    if (ret == 0) {
      memset(meta, 0, sizeof(meta));
      ret = QrParseMetadata(filename, meta);
      // printf("QrParseMetadata %d\n", ret);
      if (ret != 0) {
        parsedMeta[9] = 0;
        if ((int)meta[69] < 1) {
          meta[69] = meta[65];
        }
        if ((int)meta[70] < 1) {
          meta[70] = meta[66];
        }
        parsedMeta[4] = meta[69];
        parsedMeta[5] = meta[70];
        h = meta[70];
        w = meta[69];
        if (parsedMeta[8] == 0) {
          float sampleSizeF = 1.0;
          if (inSampleSize != 0) {
            sampleSizeF = (float)inSampleSize;
          }
          int sampledW = (int)((float)w / sampleSizeF);
          int sampledH = (int)((float)h / sampleSizeF);
          if ((sampledW < 1) || (sampledH < 1)) {
            goto exit_free;
          }
          //void* bmap = createBitmap(jniEnv, sampledW, sampledH, nativeInt, 0); // JNI call
          //if (bmap == NULL) goto exit_free;
          void* bmapPixelsAddr = calloc(sampledW * sampledH, 1);
          if (bmapPixelsAddr == NULL) {
            goto exit_free;
          }
          //nativeInt = AndroidBitmap_lockPixels(jniEnv, bmap, &bmapPixelsAddr);
          //if (-1 < nativeInt) {
            nativeInt = QrDecodeDNGFile(filename, bmapPixelsAddr, 0, nativeIntFlag, parsedMeta);
            //AndroidBitmap_unlockPixels(jniEnv,  );
          //}
          free(bmapPixelsAddr);
        }
      }
    }
exit_free:
    free(parsedMeta);
    return 0;
}



void harnessSimple(char* filename) {
  int w, h, a, b;
  unsigned int metadata[71] = {0};

  if (QuramGetImageInfoFromFile2(filename, 0, 0, &w, &h, &a, &b) == 0) {
    QrParseMetadata(filename, metadata);
  }
}



int main(int argc, char** argv) {

  if (argc < 2) {
	  fprintf(stderr, "no arg\n");
	  return 1;
  }
  
  removeSignalHandlers();
  
  //harnessSimple(argv[1]);
  harnessDecode(argv[1]);

  return 0;
}
