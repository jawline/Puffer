#if defined(__ANDROID__)

#include <cstdio>
#include <jni.h>

#define _GNU_SOURCE

#include "core.h"
#include <sys/mman.h>

FILE* mk_tmpfile(JNIEnv *env, jstring s) {
  const char *cstr = env->GetStringUTFChars(s, NULL);

  FILE *bfile = tmpfile();

  if (!bfile) {
      debug("Reject tmpfile");
      abort();
  }

  if (fwrite(cstr, strlen(cstr) + 1, 1, bfile) != 1) {
      debug("Failed write");
      abort();
  }

  rewind(bfile);
  return bfile;
}

extern "C" JNIEXPORT void JNICALL
Java_com_parsed_securitywall_SecurityFilter_launch(JNIEnv *env, jobject service, jint tunfd,
                                                   jint quitfd, jint lanBlockLevel,
                                                   jstring blockListStr, jstring allowListStr) {
    auto bfile = mk_tmpfile(env, blockListStr);
    auto afile = mk_tmpfile(env, allowListStr);

    BlockList b(bfile, afile);

    debug("Creating event loop");

    EventLoop loop(tunfd, quitfd, lanBlockLevel, b, env, service);

    debug("Entering proxy");
    loop.user_space_ip_proxy();
}

#endif
