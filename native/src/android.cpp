#if defined(__ANDROID__)

#include <cstdio>
#include <jni.h>

#define _GNU_SOURCE

#include "core.h"
#include <sys/mman.h>

extern "C" JNIEXPORT void JNICALL Java_com_parsed_securitywall_SecurityFilter_launch(JNIEnv *env, jobject service, jint tunfd, jint quitfd,
                                                                                     jstring blockListStr) {

  const char *cstr = env->GetStringUTFChars(blockListStr, NULL);

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
  BlockList b(bfile);

  debug("Creating event loop");

  EventLoop loop(tunfd, quitfd, b, env, service);

  debug("Entering proxy");
  loop.user_space_ip_proxy();
}

#endif
