Versity ScoutFS Release Notes
=============================

---
v1.16
\
*Oct 4, 2023*

Fix an issue where the server could hang on startup if its persistent
allocator structures were left in a specific degraded state by the
previously active server.

---
v1.15
\
*Jul 17, 2023*

Process log btree merge splicing in multiple commits.  This prevents a
rare case where pending log merge completions contain more work than can
be done in a single server commit, causing the server to trigger an
assert shortly after starting.

Fix spurious EINVAL from data writes when data\_prealloc\_contig\_only was
set to 0.

---
v1.14
\
*Jun 29, 2023*

Add get\_referring\_entries ioctl for getting directory entries that
refer to an inode.

Fix excessive CPU use in the move\_blocks interface when moving a large
number of extents.

Reduce fragmented data allocation when contig\_only prealloc is not in
use by more consistently allocating multi-block extents within each
aligned prealloc region.

Avoid rare deadlock in metadata block cache recalim under both heavy
load and memory pressure.

Fix crash when using quorum\_heartbeat\_timeout\_ms mount option.

---
v1.13
\
*May 19, 2023*

Add the quorum\_heartbeat\_timeout\_ms mount option to set the quorum
heartbeat timeout.

Change some task prioritization and allocation behavior of the quorum
agent to help reduce delays in sending and receiving heartbeat messages.

---
v1.12
\
*Apr 17, 2023*

Add the prepare-empty-data-device scoutfs command.  A data device can be
unused when no files have data blocks, perhaps because they're archived
and offline.  In this case the data device can be swapped out for
another device without changes to the metadata device.

Fix an oversight which limited inode timestamps to second granularity
for some operations.  All operations now record timestamps with full
nanosecond precision.

Fix spurious ENOENT failures when renaming from other directories into
the root directory.

---
v1.11
\
*Feb 2, 2023*

Fixed a free extent processing error that could prevent mount from
proceeding when free data extents were sufficiently fragmented.  It now
properly handle very fragmented free extent maps.

Fixed a statfs server processing race that could return spurious errors
and shut down the server.  With the race closed statfs processing is
reliable.

Fixed a rare livelock in the move\_blocks ioctl.  With the right
relationship between ioctl arguments and eventual file extent items the
core loop in the move\_blocks ioctl could get stuck looping on an extent
item and never return.  The loop exit conditions were fixed and the loop
will always advance through all extents.

Changed the 'print' scoutfs commands to flush the block cache for the
devices.  It was inconvenient to expect cache flushing to be a separate
step to ensure consistency with remote node writes.

---
v1.10
\
*Dec 7, 2022*

Fixed a potential directory entry cache management deadlock that could
occur when many nodes performed heavy metadata write loads across shared
directories and their child subdirectories.  The deadlock could halt
invalidation progress on a node which could then stop use of locks that
needed invalidation on that node which would result in almost all tasks
hanging on those locks that would never make progress. 

Fixed a circumstance where metadata change sequence index item
modification could leave behind old stale metadata sequence items.  The
duplication case required concurrent metadata updates across mounts with
particular open transaction patterns so the duplicate items are rare.
They resulted in a small amount of additional load when walking change
indexes but had no effect on correctness.

Fixed a rare case where sparse file extension might not write partial
blocks of zeros which was found in testing.  This required using
truncate to extend files past file sizes that end in partial blocks
along with the right transaction commit and memory reclaim patterns.
This never affected regular non-sparse files nor files prepopulated with
fallocate.

---
v1.9
\
*Oct 29, 2022*

Fix VFS cached directory entry consistency verification that could cause
spurious "no such file or directory" (ENOENT) errors from rename over
NFS under certain conditions.  The problem was only every with the
consistency of in-memory cached dentry objects, persistent data was
correct and eventual eviction of the bad cached objects would stop
generating the errors.

---
v1.8
\
*Oct 18, 2022*

Add support for Linux POSIX Access Control Lists, as described in
acl(5).  Mount options are added to enable ("acl") and disable ("noacl")
support.  The default is to support ACLs.  ACLs are stored in the
existing extended attribute scheme so adding support is does not require
a format change.

Add options to control data extent preallocation.  The default behavior
does not change.  The options can relax the limits on preallocation
which will then trigger under more write patterns and increase the risk
of preallocated space which is never used.  The options are described in
scoutfs(5).

---
v1.7
\
*Aug 26, 2022*

* **Fixed possible persistent errors moving freed data extents**
\
  Fixed a case where the server could hit persistent errors trying to
  move a client's freed extents in one commit.  The client had to free
  a large number of extents that occupied distant positions in the
  global free extent btree.  Very large fragmented files could cause
  this.  The server now moves the freed extents in multiple commits and
  can always ensure forward progress.

* **Fixed possible persistent errors from freed duplicate extents**
\
  Background orphan deletion wasn't properly synchronizing with
  foreground tasks deleting very large files.  If a deletion took long
  enough then background deletion could also attempt to delete inode items
  while the deletion was making progress.  This could create duplicate
  deletions of data extent items which causes the server to abort when
  it later discovers the duplicate extents as it merges free lists.

---
v1.6
\
*Jul 7, 2022*

* **Fix memory leaks in rare corner cases**
\
  Analysis tools found a few corner cases that leaked small structures,
  generally around error handling or startup and shutdown.

* **Add --skip-likely-huge scoutfs print command option**
\
  Add an option to scoutfs print to reduce the size of the output
  so that it can be used to see system-wide metadata without being
  overwhelmed by file-level details.

---
v1.5
\
*Jun 21, 2022*

* **Fix persistent error during server startup**
\
  Fixed a case where the server would always hit a consistent error on
  seartup, preventing the system from mounting.  This required a rare
  but valid state across the clients.

* **Fix a client hang that would lead to fencing**
\
  The client module's use of in-kernel networking was missing annotation
  that could lead to communication hanging.  The server would fence the
  client when it stopped communicating.  This could be identified by the
  server fencing a client after it disconnected with no attempt by the
  client to reconnect.

---
v1.4
\
*May 6, 2022*

* **Fix possible client crash during server failover**
\
  Fixed a narrow window during server failover and lock recovery that
  could cause a client mount to believe that it had an inconsistent item
  cache and panic.  This required very specific lock state and messaging
  patterns between multiple mounts and multiple servers which made it
  unlikely to occur in the field.

---
v1.3
\
*Apr 7, 2022*

* **Fix rare server instability under heavy load**
\
  Fixed a case of server instability under heavy load due to concurrent
  work fully exhausting metadata block allocation pools reserved for a
  single server transaction.  This would cause brief interruption as the
  server shutdown and the next server started up and made progress as
  pending work was retried.

* **Fix slow fencing preventing server startup**
\
  If a server had to process many fence requests with a slow fencing
  mechanism it could be interrupted before it finished.  The server
  now makes sure heartbeat messages are sent while it is making progress
  on fencing requests so that other quorum members don't interrupt the
  process.

* **Performance improvement in getxattr and setxattr**
\
  Kernel allocation patterns in the getxattr and setxattr
  implementations were causing significant contention between CPUs.  Their
  allocation strategy was changed so that concurrent tasks can call these
  xattr methods without degrading performance.

---
v1.2
\
*Mar 14, 2022*

* **Fix deadlock between fallocate() and read() system calls**
\
  Fixed a lock inversion that could cause two tasks to deadlock if they
  performed fallocate() and read() on a file at the same time.   The
  deadlock was uninterruptible so the machine needed to be rebooted.  This
  was relatively rare as fallocate() is usually used to prepare files
  before they're used.

* **Fix instability from heavy file deletion workloads**
\
  Fixed rare circumstances under which background file deletion cleanup
  tasks could try to delete a file while it is being deleted by another
  task.  Heavy load across multiple nodes, either many files being deleted
  or large files being deleted, increased the chances of this happening.
  Heavy staging could cause this problem because staging can create many
  internal temporary files that need to be deleted.

---
v1.1
\
*Feb 4, 2022*


* **Add scoutfs(1) change-quorum-config command**
\
  Add a change-quorum-config command to scoutfs(1) to change the quorum
  configuration stored in the metadata device while the file system is
  unmounted.   This can be used to change the mounts that will
  participate in quorum and the IP addresses they use.

* **Fix Rare Risk of Item Cache Corruption**
\
  Code review found a rare potential source of item cache corruption.
  If this happened it would look as though deleted parts of the filesystem
  returned, but only at the time they were deleted.  Old deleted items are
  not affected.  This problem only affected the item cache, never
  persistent storage.  Unmounting and remounting would drop the bad item
  cache and resync it with the correct persistent data.

---
v1.0
\
*Nov 8, 2021*


* **Initial Release**
\
  Version 1.0 marks the first GA release.
