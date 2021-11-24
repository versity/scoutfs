#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sparse.h"
#include "util.h"
#include "format.h"

#include "quorum.h"

bool quorum_slot_present(struct scoutfs_super_block *super, int i)
{
	return super->qconf.slots[i].addr.v4.family == cpu_to_le16(SCOUTFS_AF_IPV4);
}

bool valid_quorum_slots(struct scoutfs_quorum_slot *slots)
{
	struct in_addr in;
	bool valid = true;
	char *addr;
	int i;
	int j;

	for (i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		if (slots[i].addr.v4.family == cpu_to_le16(SCOUTFS_AF_NONE))
			continue;

		if (slots[i].addr.v4.family != cpu_to_le16(SCOUTFS_AF_IPV4)) {
			fprintf(stderr, "quorum slot nr %u has invalid family %u\n",
				i, le16_to_cpu(slots[i].addr.v4.family));
			valid = false;
		}

		for (j = i + 1; j < SCOUTFS_QUORUM_MAX_SLOTS; j++) {
			if (slots[i].addr.v4.family != cpu_to_le16(SCOUTFS_AF_IPV4))
				continue;

			if (slots[i].addr.v4.addr == slots[j].addr.v4.addr &&
			    slots[i].addr.v4.port == slots[j].addr.v4.port) {

				in.s_addr =
					htonl(le32_to_cpu(slots[i].addr.v4.addr));
				addr = inet_ntoa(in);
				fprintf(stderr, "quorum slot nr %u and %u have the same address %s:%u\n",
					i, j, addr,
					le16_to_cpu(slots[i].addr.v4.port));
				valid = false;
			}
		}
	}

	return valid;
}

/*
 * Print quorum slots to stdout, a line at a time.   The first line is
 * not indented and the rest of the lines use the indent string from the
 * caller.
 */
void print_quorum_slots(struct scoutfs_quorum_slot *slots, int nr, char *indent)
{
	struct scoutfs_quorum_slot *sl;
	struct in_addr in;
	bool first = true;
	int i;

	for (i = 0, sl = slots; i < SCOUTFS_QUORUM_MAX_SLOTS; i++, sl++) {

		if (sl->addr.v4.family != cpu_to_le16(SCOUTFS_AF_IPV4))
			continue;

		in.s_addr = htonl(le32_to_cpu(sl->addr.v4.addr));
		printf("%s%u: %s:%u\n", first ? "" : indent,
		       i, inet_ntoa(in), le16_to_cpu(sl->addr.v4.port));

		first = false;
	}
}

