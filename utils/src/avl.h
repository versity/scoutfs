#ifndef _AVL_H_
#define _AVL_H_

struct scoutfs_avl_node *avl_first(struct scoutfs_avl_root *root);
struct scoutfs_avl_node *avl_next(struct scoutfs_avl_root *root,
				  struct scoutfs_avl_node *node);

#endif
