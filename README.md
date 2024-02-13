# Introduction

scoutfs is a clustered in-kernel Linux filesystem designed to support
large archival systems.  It features additional interfaces and metadata
so that archive agents can perform their maintenance workflows without
walking all the files in the namespace.  Its cluster support lets
deployments add nodes to satisfy archival tier bandwidth targets.

The design goal is to reach file populations in the trillions, with the
archival bandwidth to match, while remaining operational and responsive.

Highlights of the design and implementation include:

 * Fully consistent POSIX semantics between nodes
 * Atomic transactions to maintain consistent persistent structures
 * Integrated archival metadata replaces syncing to external databases
 * Dynamic seperation of resources lets nodes write in parallel
 * 64bit throughout; no limits on file or directory sizes or counts
 * Open GPLv2 implementation

# Community Mailing List

Please join us on the open scoutfs-devel@scoutfs.org [mailing list
hosted on Google Groups](https://groups.google.com/a/scoutfs.org/forum/#!forum/scoutfs-devel)

# Building Quick start

To get started with building all the components of the software and
run the included self-tests, you will need to install the following
packages listed below. For convenience, the below text can be copy
and pasted into a (root) terminal and should work on el7, 8 and 9.

```
	yum -y group install "Development Tools"
	yum -y install kernel-devel
	yum -y install git attr psmisc bc
	yum -y install openssl-devel libblkid-devel libuuid-devel zlib-devel
	yum -y install xfsprogs-devel libacl-devel libattr-devel
```
