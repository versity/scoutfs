
/*
 * Tracing squota_input
 */
#define SQI_FMT "[%u %llu %llu %llu]"

#define SQI_ARGS(i)						\
	(i)->op, (i)->attrs[0], (i)->attrs[1], (i)->attrs[2]

#define SQI_FIELDS(pref)					\
	__array(__u64, pref##_attrs, SQ_NS__NR_SELECT)		\
	__field(__u8, pref##_op)

#define SQI_ASSIGN(pref, i)					\
	__entry->pref##_attrs[0] = (i)->attrs[0];		\
	__entry->pref##_attrs[1] = (i)->attrs[1];		\
	__entry->pref##_attrs[2] = (i)->attrs[2];		\
	__entry->pref##_op = (i)->op;

#define SQI_ENTRY_ARGS(pref)					\
	__entry->pref##_op, __entry->pref##_attrs[0],		\
	__entry->pref##_attrs[1], __entry->pref##_attrs[2]

/*
 * Tracing squota_rule
 */
#define SQR_FMT "[%u %llu,%u,%x %llu,%u,%x %llu,%u,%x %u %llu]"

#define SQR_ARGS(r)							\
	(r)->prio,							\
	(r)->name_val[0], (r)->name_source[0], (r)->name_flags[0],	\
	(r)->name_val[1], (r)->name_source[1], (r)->name_flags[1],	\
	(r)->name_val[2], (r)->name_source[2], (r)->name_flags[2],	\
	(r)->op, (r)->limit						\

#define SQR_FIELDS(pref)			\
	__array(__u64, pref##_name_val, 3)	\
	__field(__u64, pref##_limit)		\
	__array(__u8, pref##_name_source, 3)	\
	__array(__u8, pref##_name_flags, 3)	\
	__field(__u8, pref##_prio)		\
	__field(__u8, pref##_op)

#define SQR_ASSIGN(pref, r)					\
	__entry->pref##_name_val[0] = (r)->names[0].val;	\
	__entry->pref##_name_val[1] = (r)->names[1].val;	\
	__entry->pref##_name_val[2] = (r)->names[2].val;	\
	__entry->pref##_limit = (r)->limit;			\
	__entry->pref##_name_source[0] = (r)->names[0].source;	\
	__entry->pref##_name_source[1] = (r)->names[1].source;	\
	__entry->pref##_name_source[2] = (r)->names[2].source;	\
	__entry->pref##_name_flags[0] = (r)->names[0].flags;	\
	__entry->pref##_name_flags[1] = (r)->names[1].flags;	\
	__entry->pref##_name_flags[2] = (r)->names[2].flags;	\
	__entry->pref##_prio = (r)->prio;			\
	__entry->pref##_op = (r)->op;

#define SQR_ENTRY_ARGS(pref)						\
	__entry->pref##_prio, __entry->pref##_name_val[0],		\
	__entry->pref##_name_source[0], __entry->pref##_name_flags[0],	\
	__entry->pref##_name_val[1], __entry->pref##_name_source[1],	\
	__entry->pref##_name_flags[1], __entry->pref##_name_val[2],	\
	__entry->pref##_name_source[2], __entry->pref##_name_flags[2],	\
	__entry->pref##_op, __entry->pref##_limit

TRACE_EVENT(scoutfs_quota_check,
	TP_PROTO(struct super_block *sb, long rs_ptr, struct squota_input *inp, int ret),

	TP_ARGS(sb, rs_ptr, inp, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(long, rs_ptr)
		SQI_FIELDS(i)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->rs_ptr = rs_ptr;
		SQI_ASSIGN(i, inp);
		__entry->ret = ret;
	),

	TP_printk(SCSBF" rs_ptr %ld ret %d inp "SQI_FMT,
		  SCSB_TRACE_ARGS, __entry->rs_ptr, __entry->ret, SQI_ENTRY_ARGS(i))
);

DECLARE_EVENT_CLASS(scoutfs_quota_rule_op_class,
	TP_PROTO(struct super_block *sb, struct squota_rule *rule, int ret),

	TP_ARGS(sb, rule, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		SQR_FIELDS(r)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		SQR_ASSIGN(r, rule);
		__entry->ret = ret;
	),

	TP_printk(SCSBF" "SQR_FMT" ret %d",
		  SCSB_TRACE_ARGS, SQR_ENTRY_ARGS(r), __entry->ret)
);
DEFINE_EVENT(scoutfs_quota_rule_op_class, scoutfs_quota_add_rule,
	TP_PROTO(struct super_block *sb, struct squota_rule *rule, int ret),
	TP_ARGS(sb, rule, ret)
);
DEFINE_EVENT(scoutfs_quota_rule_op_class, scoutfs_quota_del_rule,
	TP_PROTO(struct super_block *sb, struct squota_rule *rule, int ret),
	TP_ARGS(sb, rule, ret)
);

TRACE_EVENT(scoutfs_quota_totl_check,
	TP_PROTO(struct super_block *sb, struct squota_input *inp, struct scoutfs_key *key,
		 u64 limit, int ret),

	TP_ARGS(sb, inp, key, limit, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		SQI_FIELDS(i)
		sk_trace_define(k)
		__field(__u64, limit)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		SQI_ASSIGN(i, inp);
		sk_trace_assign(k, key);
		__entry->limit = limit;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" inp "SQI_FMT" key "SK_FMT" limit %llu ret %d",
		  SCSB_TRACE_ARGS, SQI_ENTRY_ARGS(i), sk_trace_args(k), __entry->limit,
		  __entry->ret)
);
