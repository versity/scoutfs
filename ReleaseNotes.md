Versity ScoutFS Release Notes
=============================

---
v1.3-rc
\
*TBD*

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
