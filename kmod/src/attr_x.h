#ifndef _SCOUTFS_ATTR_X_H_
#define _SCOUTFS_ATTR_X_H_

#include <linux/kernel.h>
#include <linux/fs.h>
#include "ioctl.h"

int scoutfs_get_attr_x(struct inode *inode, struct scoutfs_ioctl_inode_attr_x *iax);
int scoutfs_set_attr_x(struct inode *inode, struct scoutfs_ioctl_inode_attr_x *iax);

#endif
