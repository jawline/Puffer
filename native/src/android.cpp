#if defined(__ANDROID__)

#include <jni.h>
#include <cstdio>
#include "general.h"

extern "C" JNIEXPORT void JNICALL Java_com_parsed_securitywall_SecurityFilter_launch(JNIEnv* env, jobject service, jint tunfd, jint quitfd) {
    BlockList b;
    event_loop_t loop(b);
    loop.env = env;
    loop.swall = service;
    loop.quit_fd = quitfd;
    debug("Creating TESTTUN");
    user_space_ip_proxy(tunfd, loop);
}

#endif
