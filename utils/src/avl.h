#ifndef _AVL_H_
#define _AVL_H_

__le16 avl_node_off(struct scoutfs_avl_root *root,
		    struct scoutfs_avl_node *node);
struct scoutfs_avl_node *avl_first(struct scoutfs_avl_root *root);
struct scoutfs_avl_node *avl_next(struct scoutfs_avl_root *root,
				  struct scoutfs_avl_node *node);

#endif
