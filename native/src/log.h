#ifndef _LGH
#define _LGH

#ifndef DEBUG
#define DEBUG 1
#endif

#if defined(DEBUG)

#if defined(__ANDROID__)
#include <android/log.h>

#define debug(fmt, ...) \
        do { if (DEBUG) __android_log_print(ANDROID_LOG_DEBUG, "SecurityWall-Native", "%s:%d:%s(): " fmt "\n", __FILE__, \
                                __LINE__, __func__, ## __VA_ARGS__); } while (0)

#else

#define debug(fmt, ...) \
        do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt "\n", __FILE__, \
                                __LINE__, __func__, ## __VA_ARGS__); } while (0)

#endif

#else
#define (debug, fmt, ...) do {} while (0)
#endif

#define DROP_GUARD(e) if (!(e)) { \
  debug("Dropped Packet (%i) (DROP GUARD) %i", e, __LINE__); \
  return; \
}

#define DROP_GUARD_INT(e) if (!(e)) { \
  debug("Dropped Packet (%i) (DROP GUARD) %i", e, __LINE__); \
  return - 1; \
}

#define DROP_GUARD_RET(e, r) if (!(e)) { \
  debug("Dropped Packet (%i) (DROP GUARD) %i", e, __LINE__); \
  return r; \
}

#endif
