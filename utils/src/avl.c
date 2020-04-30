#include "sparse.h"
#include "util.h"
#include "format.h"
#include "avl.h"

static struct scoutfs_avl_node *node_ptr(struct scoutfs_avl_root *root,

					 __le16 off)
{
	return off ? (void *)root + le16_to_cpu(off) : NULL;
}

struct scoutfs_avl_node *avl_first(struct scoutfs_avl_root *root)
{
	struct scoutfs_avl_node *node = node_ptr(root, root->node);

	while (node && node->left)
		node = node_ptr(root, node->left);

	return node;
}

struct scoutfs_avl_node *avl_next(struct scoutfs_avl_root *root,
				  struct scoutfs_avl_node *node)
{
	struct scoutfs_avl_node *parent;

	if (node->right) {
		node = node_ptr(root, node->right);
		while (node->left)
			node = node_ptr(root, node->left);
		return node;
	}

	while ((parent = node_ptr(root, node->parent)) &&
	       node == node_ptr(root, parent->right))
		node = parent;

	return parent;
}
