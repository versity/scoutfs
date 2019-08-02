
This test suite exercises multi-node scoutfs by using multiple mounts on
one host to simulate multiple nodes across a network.

It also contains a light test wrapper that executes xfstests on one of
the test mounts.

## Invoking Tests

The basic test invocation has to specify the location of locally checked
out git repos for scoutfs software that will be modified by the script,
the number of mounts to test, whether to create a new fs and insert the
built module, and where to put the results.

    # bash ./run-tests.sh                       \
        -d /dev/vda                             \
        -i                                      \
        -K $HOME/git/scoutfs-kmod-dev           \
        -k master                               \
        -m                                      \
        -n 3                                    \
        -q 2                                    \
        -r ./results                            \
        -U $HOME/git/scoutfs-utils-dev          \
        -u master

All options can be seen by running with -h.

The script will try to check out a newly pulled version of the specified
branch in each specified local repository.  They should be clean and the
script will try to fetch from origin and specifically check out local
branches that track the branches on origin.

This script is built to test multi-node systems on one host by using
different mounts of the same device.  The script creates a fake block
device in front of the main fs block device for each mount that will be
tested.  Currently it will create free loop devices and will mount on
/mnt/test.[0-9].

All tests will be run by default.  Particular tests can be included or
excluded by providing test name regular expressions with the -I and -E
options.  The definitive list of tests and the order in which they'll be
run is found in the sequence file.

## xfstests

The last test that is run checks out, builds, and runs xfstests.  It
needs -X and -x options for the xfstests git repo and branch.  The test
verifies that the expected set of xfstests tests ran and passed.

        -X $HOME/git/scoutfs-xfstests           \
        -x scoutfs                              \

An xfstests repo that knows about scoutfs is only required to sprinkle
the scoutfs cases throughout the xfstests harness.

## Individual Test Invocation

Each test is run in a new bash invocation.  A set of directories in the
test volume and in the results path are created for the test.  Each
test's working directory isn't managed.

Test output, temp files, and dmesg snapshots are all put in a tmp/ dir
in the results/ dir.  Per-test dirs are only destroyed before each test
invocation.

The harness will check for unexpected output in dmesg after each
individual test.

Each test that fails will have its results appened to the fail.log file
in the results/ directory.  The details of the failure can be examined
in the directories for each test in results/output/ and results/tmp/. 

## Writing tests

Tests have access to a set of t\_ prefixed bash functions that are found
in files in funcs/.

Tests complete by calling t\_ functions which indicate the result of the
test and can return a message.  If the tests passes then its output is
compared with known good output.  If the output doesn't match then the
test fails.  The t\_ completion functions return specific status codes so
that returning without calling one can be detected.

The golden output has to be consistent across test platforms so there
are a number of filter functions which strip out local details from
command output.  t\_filter\_fs is by far the most used which canonicalizes
fs mount paths and block device details.

Tests can be relatively loose about checking errors.  If commands
produce output in failure cases then the test will fail without having
to specifically test for errors on every command execution.  Care should
be taken to make sure that blowing through a bunch of commands with no
error checking doesn't produce catastrophic results.  Usually tests are
simple and it's fine.

A bare sync will sync all the mounted filesystems and ensure that
no mounts have dirty data.  sync -f can be used to sync just a specific
filesystem, though it doesn't exist on all platforms.

The harness doesn't currently ensure that all mounts are restored after
each test invocation.  It probably should.  Currently it's the
responsibility of the test to restore any mounts it alters and there are
t\_ functions to mount all configured mount points.

## Environment Variables

Tests have a number of exported environment variables that are commonly
used during the test.

| Variable      | Description          | Origin          | Example            |
| ------------- | -------------------  | --------------- | ------------------ |
| T\_B[0-9]     | per-mount blockdev   | created per run | /dev/loop0         |
| T\_D[0-9]     | per-mount test dir   | made for test   | /mnt/test.[0-9]/t  |
| T\_DEVICE     | main FS device       | -d              | /dev/sda           |
| T\_EXDEV      | extra scratch dev    | -e              | /dev/sdb           |
| T\_M[0-9]     | mount paths          | mounted per run | /mnt/test.[0-9]/   |
| T\_NR\_MOUNTS | number of mounts     | -n              | 3                  |
| T\_O[0-9]     | mount options        | created per run | -o server\_addr=   |
| T\_QUORUM     | quorum count         | -q              | 2                  |
| T\_TMP        | per-test tmp prefix  | made for test   | results/tmp/t/tmp  |
| T\_TMPDIR     | per-test tmp dir dir | made for test   | results/tmp/t      |

There are also a number of variables that are set in response to options
and are exported but their use is rare so they aren't included here.

