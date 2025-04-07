#ifndef _SCOUTFS_TRIGGERS_H_
#define _SCOUTFS_TRIGGERS_H_

enum scoutfs_trigger {
	SCOUTFS_TRIGGER_BLOCK_REMOVE_STALE,
	SCOUTFS_TRIGGER_SRCH_COMPACT_LOGS_PAD_SAFE,
	SCOUTFS_TRIGGER_SRCH_FORCE_LOG_ROTATE,
	SCOUTFS_TRIGGER_SRCH_MERGE_STOP_SAFE,
	SCOUTFS_TRIGGER_STATFS_LOCK_PURGE,
	SCOUTFS_TRIGGER_NR,
};

bool scoutfs_trigger_test_and_clear(struct super_block *sb, unsigned int t);

#define scoutfs_trigger(sb, which)	\
	scoutfs_trigger_test_and_clear(sb, SCOUTFS_TRIGGER_##which)

int scoutfs_setup_triggers(struct super_block *sb);
void scoutfs_destroy_triggers(struct super_block *sb);

#endif
