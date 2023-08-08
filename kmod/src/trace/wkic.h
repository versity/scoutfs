
DECLARE_EVENT_CLASS(scoutfs_wkic_wpage_class,
	TP_PROTO(struct super_block *sb, void *ptr, int which, bool n0l, bool n1l,
		 struct scoutfs_key *start, struct scoutfs_key *end),

	TP_ARGS(sb, ptr, which, n0l, n1l, start, end),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(void *, ptr)
		__field(int, which)
		__field(bool, n0l)
		__field(bool, n1l)
		sk_trace_define(start)
		sk_trace_define(end)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ptr = ptr;
		__entry->which = which;
		__entry->n0l = n0l;
		__entry->n1l = n1l;
		sk_trace_assign(start, start);
		sk_trace_assign(end, end);
		__entry->which = which;
	),

	TP_printk(SCSBF" ptr %p wh %d nl %u,%u start "SK_FMT " end "SK_FMT, SCSB_TRACE_ARGS,
			__entry->ptr, __entry->which, __entry->n0l, __entry->n1l,
			sk_trace_args(start), sk_trace_args(end))
);

DEFINE_EVENT(scoutfs_wkic_wpage_class, scoutfs_wkic_wpage_alloced,
	TP_PROTO(struct super_block *sb, void *ptr, int which, bool n0l, bool n1l,
		 struct scoutfs_key *start, struct scoutfs_key *end),
	TP_ARGS(sb, ptr, which, n0l, n1l, start, end)
);
DEFINE_EVENT(scoutfs_wkic_wpage_class, scoutfs_wkic_wpage_freeing,
	TP_PROTO(struct super_block *sb, void *ptr, int which, bool n0l, bool n1l,
		 struct scoutfs_key *start, struct scoutfs_key *end),
	TP_ARGS(sb, ptr, which, n0l, n1l, start, end)
);
DEFINE_EVENT(scoutfs_wkic_wpage_class, scoutfs_wkic_wpage_found,
	TP_PROTO(struct super_block *sb, void *ptr, int which, bool n0l, bool n1l,
		 struct scoutfs_key *start, struct scoutfs_key *end),
	TP_ARGS(sb, ptr, which, n0l, n1l, start, end)
);
DEFINE_EVENT(scoutfs_wkic_wpage_class, scoutfs_wkic_wpage_trimmed,
	TP_PROTO(struct super_block *sb, void *ptr, int which, bool n0l, bool n1l,
		 struct scoutfs_key *start, struct scoutfs_key *end),
	TP_ARGS(sb, ptr, which, n0l, n1l, start, end)
);
DEFINE_EVENT(scoutfs_wkic_wpage_class, scoutfs_wkic_wpage_erased,
	TP_PROTO(struct super_block *sb, void *ptr, int which, bool n0l, bool n1l,
		 struct scoutfs_key *start, struct scoutfs_key *end),
	TP_ARGS(sb, ptr, which, n0l, n1l, start, end)
);
DEFINE_EVENT(scoutfs_wkic_wpage_class, scoutfs_wkic_wpage_inserting,
	TP_PROTO(struct super_block *sb, void *ptr, int which, bool n0l, bool n1l,
		 struct scoutfs_key *start, struct scoutfs_key *end),
	TP_ARGS(sb, ptr, which, n0l, n1l, start, end)
);
DEFINE_EVENT(scoutfs_wkic_wpage_class, scoutfs_wkic_wpage_inserted,
	TP_PROTO(struct super_block *sb, void *ptr, int which, bool n0l, bool n1l,
		 struct scoutfs_key *start, struct scoutfs_key *end),
	TP_ARGS(sb, ptr, which, n0l, n1l, start, end)
);
DEFINE_EVENT(scoutfs_wkic_wpage_class, scoutfs_wkic_wpage_shrinking,
	TP_PROTO(struct super_block *sb, void *ptr, int which, bool n0l, bool n1l,
		 struct scoutfs_key *start, struct scoutfs_key *end),
	TP_ARGS(sb, ptr, which, n0l, n1l, start, end)
);
DEFINE_EVENT(scoutfs_wkic_wpage_class, scoutfs_wkic_wpage_dropping,
	TP_PROTO(struct super_block *sb, void *ptr, int which, bool n0l, bool n1l,
		 struct scoutfs_key *start, struct scoutfs_key *end),
	TP_ARGS(sb, ptr, which, n0l, n1l, start, end)
);
DEFINE_EVENT(scoutfs_wkic_wpage_class, scoutfs_wkic_wpage_replaying,
	TP_PROTO(struct super_block *sb, void *ptr, int which, bool n0l, bool n1l,
		 struct scoutfs_key *start, struct scoutfs_key *end),
	TP_ARGS(sb, ptr, which, n0l, n1l, start, end)
);
DEFINE_EVENT(scoutfs_wkic_wpage_class, scoutfs_wkic_wpage_filled,
	TP_PROTO(struct super_block *sb, void *ptr, int which, bool n0l, bool n1l,
		 struct scoutfs_key *start, struct scoutfs_key *end),
	TP_ARGS(sb, ptr, which, n0l, n1l, start, end)
);

TRACE_EVENT(scoutfs_wkic_read_items,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *key, struct scoutfs_key *start,
		 struct scoutfs_key *end),

	TP_ARGS(sb, key, start, end),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		sk_trace_define(key)
		sk_trace_define(start)
		sk_trace_define(end)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		sk_trace_assign(key, start);
		sk_trace_assign(start, start);
		sk_trace_assign(end, end);
	),

	TP_printk(SCSBF" key "SK_FMT" start "SK_FMT " end "SK_FMT, SCSB_TRACE_ARGS,
			sk_trace_args(key), sk_trace_args(start), sk_trace_args(end))
);
