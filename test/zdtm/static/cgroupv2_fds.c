#include <fcntl.h>
#include <limits.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Restore cgroup-v2 notification files before reopening guest descriptors";
const char *test_author = "CRIU contributors";

char *dirname;
TEST_OPTION(dirname, string, "cgroup-v2 mount directory", 1);

int main(int argc, char **argv)
{
	char path[PATH_MAX], value[64], byte;
	int ready[2], done[2], notify, status;
	pid_t child;

	test_init(argc, argv);
	if (mkdir(dirname, 0755) || mount("cgroup2", dirname, "cgroup2", 0, NULL))
		return 1;
	ssprintf(path, "%s/zdtm-cgroupv2-fds", dirname);
	if (mkdir(path, 0755))
		return 1;
	ssprintf(path, "%s/zdtm-cgroupv2-fds/cgroup.subtree_control", dirname);
	if (write_value(path, "+memory"))
		return 1;
	ssprintf(path, "%s/zdtm-cgroupv2-fds/leaf", dirname);
	if (mkdir(path, 0755))
		return 1;
	ssprintf(path, "%s/zdtm-cgroupv2-fds/leaf/cgroup.procs", dirname);
	ssprintf(value, "%d", getpid());
	if (write_value(path, value))
		return 1;
	ssprintf(path, "%s/zdtm-cgroupv2-fds/leaf/memory.pressure", dirname);
	if (chown(path, 1000, 1000) || chmod(path, 0600) || pipe(ready) || pipe(done))
		return 1;
	child = fork();
	if (child < 0)
		return 1;
	if (child == 0) {
		struct stat st;
		int fd;

		close(ready[0]);
		close(done[1]);
		if (setgid(1000) || setuid(1000))
			_exit(1);
		fd = open(path, O_RDWR);
		if (fd < 0 || write(ready[1], "r", 1) != 1 || read(done[0], &byte, 1) != 1)
			_exit(1);
		if (fstat(fd, &st) || st.st_uid != 1000 || st.st_gid != 1000 || (st.st_mode & 0777) != 0600)
			_exit(1);
		_exit(0);
	}
	close(ready[1]);
	close(done[0]);
	if (read(ready[0], &byte, 1) != 1)
		return 1;
	ssprintf(path, "%s/zdtm-cgroupv2-fds/leaf/memory.events", dirname);
	notify = inotify_init1(IN_NONBLOCK);
	if (notify < 0 || inotify_add_watch(notify, path, IN_MODIFY) < 0)
		return 1;

	test_daemon();
	test_waitsig();

	if (write(done[1], "d", 1) != 1 || waitpid(child, &status, 0) != child ||
	    !WIFEXITED(status) || WEXITSTATUS(status)) {
		fail("delegated pressure descriptor permissions were not restored");
		return 1;
	}
	if (access(path, R_OK)) {
		fail("memory controller notification file is absent");
		return 1;
	}
	close(notify);
	if (umount(dirname))
		return 1;
	pass();
	return 0;
}
