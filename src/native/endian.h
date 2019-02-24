#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__NetBSD__) || defined(__OpenBSD__)

#include <sys/endian.h>

#elif defined(__APPLE__)

/* OS X endian.h doesn't provide be|le macros  */
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)
#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)

#elif defined(__MINIOS__)

#include <endian.h>
#include <byteswap.h>

#if (BYTE_ORDER == LITTLE_ENDIAN)
#define htobe64(x) (bswap_64(x))
#define be64toh(x) (bswap_64(x))
#elif (BYTE_ORDER == BIG_ENDIAN)
#define htobe64(x) (x)
#define be64toh(x) (x)
#else
#error "Cannot determine byte order"
#endif

#else

/* Needs _DEFAULT_SOURCE with glibc */
#include <endian.h>

#endif
