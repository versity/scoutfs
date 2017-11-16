/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * dlmglue.h
 *
 * dlmglue constants for userspace decoding
 *
 * Copyright (C) 2002, 2004 Oracle.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */


#ifndef DLMGLUE_H
#define DLMGLUE_H

/* Max length of lockid name */
#define OCFS2_LOCK_ID_MAX_LEN  32

#define DLM_LVB_LEN  64

enum ocfs2_ast_action {
	OCFS2_AST_INVALID = 0,
	OCFS2_AST_ATTACH,
	OCFS2_AST_CONVERT,
	OCFS2_AST_DOWNCONVERT,
};

/* actions for an unlockast function to take. */
enum ocfs2_unlock_action {
	OCFS2_UNLOCK_INVALID = 0,
	OCFS2_UNLOCK_CANCEL_CONVERT,
	OCFS2_UNLOCK_DROP_LOCK,
};

/* ocfs2_lock_res->l_flags flags. */
#define OCFS2_LOCK_ATTACHED      (0x00000001) /* we have initialized
					       * the lvb */
#define OCFS2_LOCK_BUSY          (0x00000002) /* we are currently in
					       * dlm_lock */
#define OCFS2_LOCK_BLOCKED       (0x00000004) /* blocked waiting to
					       * downconvert*/
#define OCFS2_LOCK_LOCAL         (0x00000008) /* newly created inode */
#define OCFS2_LOCK_NEEDS_REFRESH (0x00000010)
#define OCFS2_LOCK_REFRESHING    (0x00000020)
#define OCFS2_LOCK_INITIALIZED   (0x00000040) /* track initialization
					       * for shutdown paths */
#define OCFS2_LOCK_FREEING       (0x00000080) /* help dlmglue track
					       * when to skip queueing
					       * a lock because it's
					       * about to be
					       * dropped. */
#define OCFS2_LOCK_QUEUED        (0x00000100) /* queued for downconvert */
#define OCFS2_LOCK_NOCACHE       (0x00000200) /* don't use a holder count */
#define OCFS2_LOCK_PENDING       (0x00000400) /* This lockres is pending a
						 call to dlm_lock.  Only
						 exists with BUSY set. */
#define OCFS2_LOCK_UPCONVERT_FINISHING (0x00000800) /* blocks the dc thread
						     * from downconverting
						     * before the upconvert
						     * has completed */

#define OCFS2_LOCK_NONBLOCK_FINISHED (0x00001000) /* NONBLOCK cluster
						   * lock has already
						   * returned, do not block
						   * dc thread from
						   * downconverting */

/* The cluster stack fields */
#define OCFS2_STACK_LABEL_LEN		4
#define OCFS2_CLUSTER_NAME_LEN		16

/*
 * Return value from ->downconvert_worker functions.
 *
 * These control the precise actions of ocfs2_unblock_lock()
 * and ocfs2_process_blocked_lock()
 *
 */
enum ocfs2_unblock_action {
	UNBLOCK_CONTINUE	= 0, /* Continue downconvert */
	UNBLOCK_CONTINUE_POST	= 1, /* Continue downconvert, fire
				      * ->post_unlock callback */
	UNBLOCK_STOP_POST	= 2, /* Do not downconvert, fire
				      * ->post_unlock() callback. */
};

#endif	/* DLMGLUE_H */
