#ifndef _SCOUTFS_SERVER_H_
#define _SCOUTFS_SERVER_H_

#define SNH_FMT \
	"seq %llu recv_seq %llu id %llu data_len %u cmd %u flags 0x%x error %u"
#define SNH_ARG(nh)							\
	le64_to_cpu((nh)->seq), le64_to_cpu((nh)->recv_seq),		\
	le64_to_cpu((nh)->id), le16_to_cpu((nh)->data_len), (nh)->cmd,	\
	(nh)->flags, (nh)->error

#define snh_trace_define(name)		\
	__field(__u64, name##_seq)	\
	__field(__u64, name##_recv_seq)	\
	__field(__u64, name##_id)	\
	__field(__u16, name##_data_len)	\
	__field(__u8, name##_cmd)	\
	__field(__u8, name##_flags)	\
	__field(__u8, name##_error)

#define snh_trace_assign(name, nh)				\
do {								\
	__typeof__(nh) _nh = (nh);				\
								\
	__entry->name##_seq = le64_to_cpu(_nh->seq);		\
	__entry->name##_recv_seq = le64_to_cpu(_nh->recv_seq);		\
	__entry->name##_id = le64_to_cpu(_nh->id);		\
	__entry->name##_data_len = le16_to_cpu(_nh->data_len);	\
	__entry->name##_cmd = _nh->cmd;				\
	__entry->name##_flags = _nh->flags;			\
	__entry->name##_error = _nh->error;			\
} while (0)

#define snh_trace_args(name)						      \
	__entry->name##_seq, __entry->name##_recv_seq, __entry->name##_id,    \
	__entry->name##_data_len, __entry->name##_cmd, __entry->name##_flags, \
	__entry->name##_error

u64 scoutfs_server_reserved_meta_blocks(struct super_block *sb);

int scoutfs_server_lock_request(struct super_block *sb, u64 rid,
				struct scoutfs_net_lock *nl);
int scoutfs_server_lock_response(struct super_block *sb, u64 rid, u64 id,
				 struct scoutfs_net_lock *nl);
int scoutfs_server_lock_recover_request(struct super_block *sb, u64 rid,
					struct scoutfs_key *key);
void scoutfs_server_recov_finish(struct super_block *sb, u64 rid, int which);

int scoutfs_server_send_omap_request(struct super_block *sb, u64 rid,
				     struct scoutfs_open_ino_map_args *args);
int scoutfs_server_send_omap_response(struct super_block *sb, u64 rid, u64 id,
				      struct scoutfs_open_ino_map *map, int err);

u64 scoutfs_server_seq(struct super_block *sb);
u64 scoutfs_server_next_seq(struct super_block *sb);
void scoutfs_server_set_seq_if_greater(struct super_block *sb, u64 seq);

void scoutfs_server_start(struct super_block *sb, struct scoutfs_quorum_config *qconf, u64 term);
void scoutfs_server_stop(struct super_block *sb);
void scoutfs_server_stop_wait(struct super_block *sb);
bool scoutfs_server_is_running(struct super_block *sb);
bool scoutfs_server_is_up(struct super_block *sb);
bool scoutfs_server_is_down(struct super_block *sb);

int scoutfs_server_setup(struct super_block *sb);
void scoutfs_server_destroy(struct super_block *sb);

#endif
