
#
# test basic POSIX acl functionality.
#

t_require_commands stat rm touch mkdir getfacl setfacl id sudo
t_require_mounts 2

# from quota.sh
TEST_UID=22222
TEST_GID=44444

# sys_setreuid() set fs[uid] to e[ug]id
SET_UID="--ruid=$TEST_UID --euid=$TEST_UID"
SET_GID="--rgid=$TEST_GID --egid=$TEST_GID --clear-groups"

# helper to avoid capturing dates from ls output
L() {
	stat -c "%F %A %u %g %s %N" $@
}

echo "== setup test directory"
cd "$T_D0"

echo "== getfacl"
L .
getfacl .

echo "== basic non-acl access through permissions"
rm -rf dir-testuid
mkdir dir-testuid
ln -sf dir-testuid symlinkdir-testuid
chown root:44444 dir-testuid
L dir-testuid
setpriv $SET_UID $SET_GID touch dir-testuid/file-group-write
setpriv $SET_UID $SET_GID touch symlinkdir-testuid/symlink-file-group-write
chmod g+w dir-testuid
setpriv $SET_UID $SET_GID touch dir-testuid/file-group-write
setpriv $SET_UID $SET_GID touch symlinkdir-testuid/symlink-file-group-write
L dir-testuid/file-group-write
L symlinkdir-testuid/symlink-file-group-write

echo "== basic acl access"
rm -rf dir-root
mkdir dir-root
ln -sf dir-root symlinkdir-root
L dir-root
setpriv $SET_UID touch dir-root/file-group-write
setpriv $SET_UID touch symlinkdir-root/file-group-write
setfacl -m u:22222:rwx dir-root
getfacl dir-root
setpriv $SET_UID touch dir-root/file-group-write
setpriv $SET_UID touch symlinkdir-root/file-group-write
L dir-root/file-group-write
L symlinkdir-root/file-group-write

echo "== directory exec"
setpriv $SET_UID bash -c "cd dir-root 2>&- && echo Success"
setpriv $SET_UID bash -c "cd symlinkdir-root 2>&- && echo Success"
setfacl -m u:22222:rw dir-root
getfacl dir-root
setpriv $SET_UID bash -c "cd dir-root 2>&- || echo Failed"
setpriv $SET_UID bash -c "cd symlinkdir-root 2>&- || echo Failed"
setfacl -m g:44444:rwx dir-root
getfacl dir-root
setpriv $SET_GID bash -c "cd dir-root 2>&- && echo Success"
setpriv $SET_GID bash -c "cd symlinkdir-root 2>&- && echo Success"

echo "== get/set attr"
rm -rf file-root
touch file-root
L file-root
setpriv $SET_UID getfattr -d file-root
setpriv $SET_UID setfattr -n "user.test1" -v "Success" file-root
setpriv $SET_UID getfattr -d file-root
setfacl -m u:22222:rw file-root
getfacl file-root
setpriv $SET_UID setfattr -n "user.test2" -v "Success" file-root
setpriv $SET_UID getfattr -d file-root
setfacl -x u:22222 file-root
getfacl file-root
setpriv $SET_UID setfattr -n "user.test3" -v "Success" file-root
setpriv $SET_UID getfattr -d file-root
setfacl -m g:44444:rw file-root
getfacl file-root
setpriv $SET_GID setfattr -n "user.test4" -v "Success" file-root
setpriv $SET_GID getfattr -d file-root

echo "== inheritance / default acl"
rm -rf dir-root2
mkdir dir-root2
L dir-root2
setpriv $SET_UID mkdir dir-root2/dir
setpriv $SET_UID touch dir-root2/dir/file
setfacl -m d:u:22222:rwx dir-root2
getfacl dir-root2
setpriv $SET_UID mkdir dir-root2/dir
setpriv $SET_UID touch dir-root2/dir/file
setfacl -m u:22222:rwx dir-root2
getfacl dir-root2
setpriv $SET_UID mkdir dir-root2/dir
setpriv $SET_UID touch dir-root2/dir/file
L dir-root2/dir
getfacl dir-root2/dir
L dir-root2/dir/file
getfacl dir-root2/dir/file

echo "== cleanup"

t_pass
