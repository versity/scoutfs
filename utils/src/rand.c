#include <string.h>

#include "rand.h"
#include "sparse.h"
#include "util.h"

#include <openssl/rand.h>

void pseudo_random_bytes(void *data, unsigned int len)
{
	RAND_bytes(data, len);
}
