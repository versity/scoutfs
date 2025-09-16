#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sparse.h"
#include "util.h"
#include "format.h"

#include "quorum.h"

bool quorum_slot_present(struct scoutfs_super_block *super, int i)
{
	return ((super->qconf.slots[i].addr.v4.family == cpu_to_le16(SCOUTFS_AF_IPV4)) ||
		(super->qconf.slots[i].addr.v6.family == cpu_to_le16(SCOUTFS_AF_IPV6)));
}

bool valid_quorum_slots(struct scoutfs_quorum_slot *slots)
{
	struct in_addr in;
	bool valid = true;
	char *addr;
	char ip6addr[INET6_ADDRSTRLEN];
	int i;
	int j;

	for (i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		if (slots[i].addr.v4.family == cpu_to_le16(SCOUTFS_AF_IPV4)) {
			for (j = i + 1; j < SCOUTFS_QUORUM_MAX_SLOTS; j++) {
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
		} else if (slots[i].addr.v6.family == cpu_to_le16(SCOUTFS_AF_IPV6)) {
			for (j = i + 1; j < SCOUTFS_QUORUM_MAX_SLOTS; j++) {
				if ((IN6_ARE_ADDR_EQUAL(slots[i].addr.v6.addr, slots[j].addr.v6.addr)) &&
				    (slots[i].addr.v6.port == slots[j].addr.v6.port)) {
					fprintf(stderr, "quorum slot nr %u and %u have the same address [%s]:%u\n",
						i, j,
						inet_ntop(AF_INET6, slots[i].addr.v6.addr, ip6addr, INET6_ADDRSTRLEN),
						le16_to_cpu(slots[i].addr.v6.port));
					valid = false;
				}
			}
		} else if (slots[i].addr.v6.family != cpu_to_le16(SCOUTFS_AF_NONE)) {
			fprintf(stderr, "quorum slot nr %u has invalid family %u\n",
				i, le16_to_cpu(slots[i].addr.v4.family));
			valid = false;
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
	char ip6addr[INET6_ADDRSTRLEN];
	bool first = true;
	int i;

	for (i = 0, sl = slots; i < SCOUTFS_QUORUM_MAX_SLOTS; i++, sl++) {
		if (sl->addr.v4.family == cpu_to_le16(SCOUTFS_AF_IPV4)) {
			in.s_addr = htonl(le32_to_cpu(sl->addr.v4.addr));
			printf("%s%u: %s:%u\n", first ? "" : indent,
			       i, inet_ntoa(in), le16_to_cpu(sl->addr.v4.port));

			first = false;
		} else if (sl->addr.v6.family == cpu_to_le16(SCOUTFS_AF_IPV6)) {
			printf("%s%u: [%s]:%u\n", first ? "" : indent, i,
				inet_ntop(AF_INET6, sl->addr.v6.addr, ip6addr, INET6_ADDRSTRLEN),
				le16_to_cpu(sl->addr.v6.port));
			first = false;
		}
	}
}

