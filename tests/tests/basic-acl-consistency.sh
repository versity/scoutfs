
#
# Test basic clustered posix acl consistency.
#

t_require_commands getfacl setfacl

GETFACL="getfacl --absolute-names"

filter_scratch() {
	sed "s@$T_MSCR@t_mscr@g"
}

acl_compare()
{
	diff -u - <($GETFACL $T_MSCR/data/dir_a/dir_b | filter_scratch) <<EOF1
# file: t_mscr/data/dir_a/dir_b
# owner: t_usr_3
# group: t_grp_3
# flags: -s-
user::rwx
group::rwx
group:t_grp_2:r-x
mask::rwx
other::---
default:user::rwx
default:group::rwx
default:group:t_grp_2:r-x
default:group:t_grp_3:rwx
default:mask::rwx
default:other::---

EOF1

	test $? -eq 0 || t_fail "dir_b differs"

	diff -u - <($GETFACL -p $T_MSCR/data/dir_a/dir_b/dir_c/dir_d | filter_scratch) <<EOF3
# file: t_mscr/data/dir_a/dir_b/dir_c/dir_d
# owner: t_usr_1
# group: t_grp_1
# flags: -s-
user::rwx
group::rwx
group:t_grp_2:r-x
mask::rwx
other::---
default:user::rwx
default:group::rwx
default:group:t_grp_2:r-x
default:group:t_grp_3:rwx
default:mask::rwx
default:other::---

EOF3
	test $? -eq 0 || t_fail "dir_d differs"

	diff -u - <($GETFACL $T_MSCR/data/dir_a/dir_b/dir_c | filter_scratch) <<EOF2
# file: t_mscr/data/dir_a/dir_b/dir_c
# owner: t_usr_3
# group: t_grp_2
# flags: -s-
user::rwx
group::rwx
group:t_grp_2:r-x
mask::rwx
other::---
default:user::rwx
default:group::rwx
default:group:t_grp_2:r-x
default:group:t_grp_3:rwx
default:mask::rwx
default:other::---

EOF2
	test $? -eq 0 || t_fail "dir_c differs"
}
echo "== make scratch fs"
t_scratch_mkfs
t_scratch_mount

rm -rf $T_MSCR/data

echo "== create uid/gids"
groupadd -g 7101 t_grp_1 > /dev/null 2>&1
useradd -g 7101 -u 7101 t_usr_1 > /dev/null 2>&1
groupadd -g 7102 t_grp_2 > /dev/null 2>&1
groupadd -g 7103 t_grp_3 > /dev/null 2>&1
useradd -g 7103 -u 7103 t_usr_3 > /dev/null 2>&1

echo "== set acls and permissions"
mkdir -p $T_MSCR/data/dir_a/dir_b
chown t_usr_3:t_grp_3 $T_MSCR/data/dir_a/dir_b
chmod 2770 $T_MSCR/data/dir_a/dir_b
setfacl -m g:t_grp_2:rx $T_MSCR/data/dir_a/dir_b
setfacl -m d:g:t_grp_2:rx $T_MSCR/data/dir_a/dir_b
setfacl -m d:g:t_grp_3:rwx $T_MSCR/data/dir_a/dir_b

mkdir -p $T_MSCR/data/dir_a/dir_b/dir_c
chown t_usr_3:t_grp_2 $T_MSCR/data/dir_a/dir_b/dir_c
setfacl -x g:t_grp_3 $T_MSCR/data/dir_a/dir_b/dir_c

mkdir -p $T_MSCR/data/dir_a/dir_b/dir_c/dir_d
chown t_usr_1:t_grp_1 $T_MSCR/data/dir_a/dir_b/dir_c/dir_d
setfacl -x g:t_grp_3 $T_MSCR/data/dir_a/dir_b/dir_c/dir_d

echo "== compare output"
acl_compare

echo "== drop caches and compare again"
sync
echo 3 > /proc/sys/vm/drop_caches
acl_compare

echo "== cleanup scratch fs"
t_scratch_umount

t_pass
