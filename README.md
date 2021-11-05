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
