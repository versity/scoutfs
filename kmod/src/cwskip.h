#ifndef _SCOUTFS_CWSKIP_H_
#define _SCOUTFS_CWSKIP_H_

/* A billion seems like a lot. */
#define SCOUTFS_CWSKIP_MAX_HEIGHT 30

struct scoutfs_cwskip_node {
	int height;
	unsigned int write_seq;
	struct scoutfs_cwskip_node *links[];
};

#define SCOUTFS_CWSKIP_FULL_NODE_BYTES \
	offsetof(struct scoutfs_cwskip_node, links[SCOUTFS_CWSKIP_MAX_HEIGHT + 1])

typedef int (*scoutfs_cwskip_cmp_t)(void *K, void *C);

struct scoutfs_cwskip_root {
	scoutfs_cwskip_cmp_t cmp_fn;
	unsigned long node_off;
	union {
		struct scoutfs_cwskip_node node;
		__u8 __full_root_node[SCOUTFS_CWSKIP_FULL_NODE_BYTES];
	};
};

struct scoutfs_cwskip_reader {
	struct scoutfs_cwskip_root *root;
	struct scoutfs_cwskip_node *prev;
	struct scoutfs_cwskip_node *node;
	unsigned int prev_seq;
	unsigned int node_seq;
};

/*
 * The full height prevs array makes these pretty enormous :/.
 */
struct scoutfs_cwskip_writer {
	struct scoutfs_cwskip_root *root;
	bool node_locked;
	int locked_height;
	struct scoutfs_cwskip_node *node;
	struct scoutfs_cwskip_node *prevs[SCOUTFS_CWSKIP_MAX_HEIGHT];
};

void scoutfs_cwskip_init_root(struct scoutfs_cwskip_root *root, scoutfs_cwskip_cmp_t cmp_fn,
			      unsigned long node_off);
bool scoutfs_cwskip_empty(struct scoutfs_cwskip_root *root);
int scoutfs_cwskip_rand_height(void);

void scoutfs_cwskip_read_begin(struct scoutfs_cwskip_root *root, void *key, void **prev_cont,
			       void **node_cont, int *node_cmp, struct scoutfs_cwskip_reader *rd);
bool scoutfs_cwskip_read_valid(struct scoutfs_cwskip_reader *rd);
bool scoutfs_cwskip_read_next(struct scoutfs_cwskip_reader *rd, void **prev_cont, void **node_cont);
void scoutfs_cwskip_read_end(struct scoutfs_cwskip_reader *rd);

void scoutfs_cwskip_write_begin(struct scoutfs_cwskip_root *root, void *key, int lock_height,
				void **prev_cont, void **node_cont, int *node_cmp,
				struct scoutfs_cwskip_writer *wr);
void scoutfs_cwskip_write_insert(struct scoutfs_cwskip_writer *wr,
				 struct scoutfs_cwskip_node *ins);
void scoutfs_cwskip_write_remove(struct scoutfs_cwskip_writer *wr,
				 struct scoutfs_cwskip_node *node);
bool scoutfs_cwskip_write_next(struct scoutfs_cwskip_writer *wr, int lock_height,
			       void **prev_cont, void **node_cont);
void scoutfs_cwskip_write_end(struct scoutfs_cwskip_writer *wr);

#endif
