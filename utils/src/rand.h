#ifndef _RAND_H_
#define _RAND_H_

/*
 * We could play around a bit with some macros to get aligned constant
 * word sized buffers filled by single instructions.
 */
void pseudo_random_bytes(void *data, unsigned int len);

#endif
