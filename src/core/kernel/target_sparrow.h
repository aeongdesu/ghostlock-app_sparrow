#ifndef GHOSTLOCK_TARGET_SPARROW_H
#define GHOSTLOCK_TARGET_SPARROW_H

/* PICO 4 Ultra (sparrow) kernel 5.10.198 image-domain base.
 * The OTA Image's kallsyms relative base is 0xffffffc008000000; the
 * upstream default 0xffffffc080000000 is for other device families. */
#ifndef GHOSTLOCK_KIMAGE_TEXT_BASE
#define GHOSTLOCK_KIMAGE_TEXT_BASE 0xffffffc008000000
#endif

/* Sparrow reports 5.10 with android12 in its release string. The root script
 * still parses uname -r; this is only the compile-time fallback used when the
 * device's release string cannot be parsed. */
#ifndef GHOSTLOCK_KMI_FALLBACK
#define GHOSTLOCK_KMI_FALLBACK "android12-5.10"
#endif

#include "kernel/target.h"

#endif
