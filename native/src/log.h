#ifndef _LGH
#define _LGH

#ifndef DEBUG
#define DEBUG 0
#endif

#define debug(fmt, ...) \
        do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt "\n", __FILE__, \
                                __LINE__, __func__, ## __VA_ARGS__); } while (0)

#define DROP_GUARD(e) if (!(e)) { \
  debug("Dropped Packet (%i) (DROP GUARD) %i", e, __LINE__); \
  return; \
}

#define DROP_GUARD_INT(e) if (!(e)) { \
  debug("Dropped Packet (%i) (DROP GUARD) %i", e, __LINE__); \
  return - 1; \
}

#endif
