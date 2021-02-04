#if defined(__ANDROID__)

#include <jni.h>
#include <cstdio>
#define _GNU_SOURCE
#include <sys/mman.h>
#include "general.h"

extern "C" JNIEXPORT void JNICALL Java_com_parsed_securitywall_SecurityFilter_launch(JNIEnv* env, jobject service, jint tunfd, jint quitfd, jstring blockListStr) {

    const char *cstr = env->GetStringUTFChars(blockListStr, NULL);

    FILE* bfile = tmpfile();

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

    event_loop_t loop(b);
    loop.env = env;
    loop.swall = service;
    loop.quit_fd = quitfd;
    debug("Creating TESTTUN");
    user_space_ip_proxy(tunfd, loop);
}

#endif
