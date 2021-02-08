# Introduction

scoutfs is a clustered in-kernel Linux filesystem designed and built
from the ground up to support large archival systems.

Its key differentiating features are:

 - Integrated consistent indexing accelerates archival maintenance operations
 - Commit logs allow nodes to write concurrently without contention

It meets best of breed expectations:

 * Fully consistent POSIX semantics between nodes
 * Rich metadata to ensure the integrity of metadata references
 * Atomic transactions to maintain consistent persistent structures
 * First class kernel implementation for high performance and low latency
 * Open GPLv2 implementation
 
Learn more in the [white paper](https://docs.wixstatic.com/ugd/aaa89b_88a5cc84be0b4d1a90f60d8900834d28.pdf).

# Current Status

**Alpha Open Source Development**

scoutfs is under heavy active development.  We're developing it in the
open to give the community an opportunity to affect the design and
implementation.

The core architectural design elements are in place.  Much surrounding
functionality hasn't been implemented.  It's appropriate for early
adopters and interested developers, not for production use.

In that vein, expect significant incompatible changes to both the format
of network messages and persistent structures. Since the format hash-checking
has now been removed in preparation for release, if there is any doubt, mkfs
is strongly recommended.

The current kernel module is developed against the RHEL/CentOS 7.x
kernel to minimize the friction of developing and testing with partners'
existing infrastructure.  Once we're happy with the design we'll shift
development to the upstream kernel while maintaining distro
compatibility branches.

# Community Mailing List

Please join us on the open scoutfs-devel@scoutfs.org [mailing list
hosted on Google Groups](https://groups.google.com/a/scoutfs.org/forum/#!forum/scoutfs-devel)
for all discussion of scoutfs.

# Quick Start

**This following a very rough example of the procedure to get up and
running, experience will be needed to fill in the gaps.  We're happy to
help on the mailing list.**

The requirements for running scoutfs on a small cluster are:

 1. One or more nodes running x86-64 CentOS/RHEL 7.4 (or 7.3)
 2. Access to two shared block devices
 3. IPv4 connectivity between the nodes

The steps for getting scoutfs mounted and operational are:

 1. Get the kernel module running on the nodes
 2. Make a new filesystem on the devices with the userspace utilities
 3. Mount the devices on all the nodes

In this example we use three nodes.  The names of the block devices are
the same on all the nodes.  Two of the nodes will be quorum members.  A
majority of quorum members must be mounted to elect a leader to run a
server that all the mounts connect to.  It should be noted that two
quorum members results in a majority of one, each member itself, so
split brain elections are possible but so unlikely that it's fine for a
demonstration.

1. Get the Kernel Module and Userspace Binaries

   * Either use snapshot RPMs built from git by Versity:

   ```shell
   rpm -i https://scoutfs.s3-us-west-2.amazonaws.com/scoutfs-repo-0.0.1-1.el7_4.noarch.rpm
   yum install scoutfs-utils kmod-scoutfs
   ```

   * Or use the binaries built from checked out git repositories:

   ```shell
   yum install kernel-devel
   git clone git@github.com:versity/scoutfs.git
   make -C scoutfs
   modprobe libcrc32c
   insmod scoutfs/kmod/src/scoutfs.ko
   alias scoutfs=$PWD/scoutfs/utils/src/scoutfs
   ```

2. Make a New Filesystem (**destroys contents**)

   We specify quorum slots with the addresses of each of the quorum
   member nodes, the metadata device, and the data device.

   ```shell
   scoutfs mkfs -Q 0,$NODE0_ADDR,12345 -Q 1,$NODE1_ADDR,12345 /dev/meta_dev /dev/data_dev
   ```

3. Mount the Filesystem

   First, mount each of the quorum nodes so that they can elect and
   start a server for the remaining node to connect to.  The slot numbers
   were specified with the leading "0,..."  and "1,..." in the mkfs options
   above.

   ```shell
   mount -t scoutfs -o quorum_slot_nr=$SLOT_NR,metadev_path=/dev/meta_dev /dev/data_dev /mnt/scoutfs
   ```

   Then mount the remaining node which can now connect to the running server.

   ```shell
   mount -t scoutfs -o metadev_path=/dev/meta_dev /dev/data_dev /mnt/scoutfs
   ```

4. For Kicks, Observe the Metadata Change Index

   The `meta_seq` index tracks the inodes that are changed in each
   transaction.

   ```shell
   scoutfs walk-inodes meta_seq 0 -1 /mnt/scoutfs
   touch /mnt/scoutfs/one; sync
   scoutfs walk-inodes meta_seq 0 -1 /mnt/scoutfs
   touch /mnt/scoutfs/two; sync
   scoutfs walk-inodes meta_seq 0 -1 /mnt/scoutfs
   touch /mnt/scoutfs/one; sync
   scoutfs walk-inodes meta_seq 0 -1 /mnt/scoutfs
   ```
