/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __JHASH_H
#define __JHASH_H

#include <linux/types.h>

__attribute__((__always_inline__))
static inline __u32 rol32(__u32 word, unsigned int shift)
{
	return (word << shift) | (word >> ((-shift) & 31));
}

#define __jhash_mix(a, b, c)			\
{						\
	a -= c;  a ^= rol32(c, 4);  c += b;	\
	b -= a;  b ^= rol32(a, 6);  a += c;	\
	c -= b;  c ^= rol32(b, 8);  b += a;	\
	a -= c;  a ^= rol32(c, 16); c += b;	\
	b -= a;  b ^= rol32(a, 19); a += c;	\
	c -= b;  c ^= rol32(b, 4);  b += a;	\
}

#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= rol32(b, 14);		\
	a ^= c; a -= rol32(c, 11);		\
	b ^= a; b -= rol32(a, 25);		\
	c ^= b; c -= rol32(b, 16);		\
	a ^= c; a -= rol32(c, 4);		\
	b ^= a; b -= rol32(a, 14);		\
	c ^= b; c -= rol32(b, 24);		\
}

#define JHASH_INITVAL 0xdeadbeef

__attribute__((__always_inline__))
static inline __u32 jhash(const void *key, __u32 length, __u32 initval)
{
	__u32 a, b, c;
	const unsigned char *k = key;

	a = b = c = JHASH_INITVAL + length + initval;

	while (length > 12) {
		a += *(__u32 *)(k);
		b += *(__u32 *)(k + 4);
		c += *(__u32 *)(k + 8);
		__jhash_mix(a, b, c);
		length -= 12;
		k += 12;
	}
	switch (length) {
	case 12: c += (__u32)k[11] << 24;	/* fall through */
	case 11: c += (__u32)k[10] << 16;	/* fall through */
	case 10: c += (__u32)k[9] << 8;	/* fall through */
	case 9:  c += k[8];			/* fall through */
	case 8:  b += (__u32)k[7] << 24;	/* fall through */
	case 7:  b += (__u32)k[6] << 16;	/* fall through */
	case 6:  b += (__u32)k[5] << 8;	/* fall through */
	case 5:  b += k[4];			/* fall through */
	case 4:  a += (__u32)k[3] << 24;	/* fall through */
	case 3:  a += (__u32)k[2] << 16;	/* fall through */
	case 2:  a += (__u32)k[1] << 8;	/* fall through */
	case 1:  a += k[0];
		__jhash_final(a, b, c);		/* fall through */
	case 0:
		break;
	}

	return c;
}

__attribute__((__always_inline__))
static inline __u32 __jhash_nwords(__u32 a, __u32 b, __u32 c, __u32 initval)
{
	a += initval;
	b += initval;
	c += initval;
	__jhash_final(a, b, c);
	return c;
}

__attribute__((__always_inline__))
static inline __u32 jhash_2words(__u32 a, __u32 b, __u32 initval)
{
	return __jhash_nwords(a, b, 0, initval + JHASH_INITVAL + (2 << 2));
}

__attribute__((__always_inline__))
static inline __u32 jhash_1word(__u32 a, __u32 initval)
{
	return __jhash_nwords(a, 0, 0, initval + JHASH_INITVAL + (1 << 2));
}

#endif /* __JHASH_H */
