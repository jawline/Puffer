#ifndef _LGH
#define _LGH

#if defined(__ANDROID__)
#include <android/log.h>
#define log(fmt, ...)                                                          \
  do {                                                                         \
    __android_log_print(ANDROID_LOG_DEBUG, "SecurityWall-Native",              \
                        "%s:%d:%s(): " fmt "\n", __FILE__, __LINE__, __func__, \
                        ##__VA_ARGS__);                                        \
  } while (0)
#else
#define log(fmt, ...)                                                          \
  do {                                                                         \
    fprintf(stderr, "%s:%d:%s(): " fmt "\n", __FILE__, __LINE__, __func__,     \
            ##__VA_ARGS__);                                                    \
  } while (0)
#endif

#if defined(DEBUG)
#define debug(fmt, ...) log(fmt, ##__VA_ARGS__)
#else
#define debug(fmt, ...)                                                        \
  do {                                                                         \
  } while (0)
#endif

#define DROP_GUARD(e)                                                          \
  if (!(e)) {                                                                  \
    debug("Dropped Packet (%i) (DROP GUARD) %i", e, __LINE__);                 \
    return;                                                                    \
  }

#define DROP_GUARD_INT(e)                                                      \
  if (!(e)) {                                                                  \
    debug("Dropped Packet (%i) (DROP GUARD) %i", e, __LINE__);                 \
    return -1;                                                                 \
  }

#define DROP_GUARD_RET(e, r)                                                   \
  if (!(e)) {                                                                  \
    debug("Dropped Packet (%i) (DROP GUARD) %i", e, __LINE__);                 \
    return r;                                                                  \
  }

template<typename T>
static inline T fatal_guard(T r) {
  if (r < 0) {
    debug("Guard violated");
    abort();
  }
  return r;
}

#endif
