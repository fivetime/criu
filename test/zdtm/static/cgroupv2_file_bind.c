#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Preserve a writable cgroup-v2 file bind mount over a read-only namespace-root mount";
const char *test_author = "CRIU contributors";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

/*
 * zdtm roots the tree's cgroup namespace at a non-root cgroup (the
 * 'cgroupns' flag), so the cgroup2 mount root below reads "/" here but
 * not to CRIU.
 */
int main(int argc, char **argv)
{
	char cg[PATH_MAX], path[PATH_MAX], target[PATH_MAX], value[64];
	struct stat source_stat, bind_stat, fd_stat;
	int fd, target_fd;

	test_init(argc, argv);
	if (mkdir(dirname, 0700) || mount("test", dirname, "tmpfs", 0, NULL))
		return 1;
	ssprintf(cg, "%s/cgroup", dirname);
	if (mkdir(cg, 0700) || mount("none", cg, "cgroup2", 0, NULL))
		return 1;
	ssprintf(path, "%s/memory.pressure", cg);
	ssprintf(target, "%s/pressure", dirname);
	target_fd = open(target, O_CREAT | O_WRONLY, 0600);
	if (target_fd < 0)
		return 1;
	close(target_fd);
	if (mount(path, target, NULL, MS_BIND, NULL) ||
	    mount(NULL, cg, NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL))
		return 1;
	/* Read-only: CRIU refuses writable PSI descriptors (trigger state). */
	fd = open(target, O_RDONLY);
	if (fd < 0)
		return 1;

	test_daemon();
	test_waitsig();

	if (stat(path, &source_stat) || stat(target, &bind_stat) || fstat(fd, &fd_stat) ||
	    !S_ISREG(bind_stat.st_mode) || source_stat.st_dev != bind_stat.st_dev ||
	    source_stat.st_ino != bind_stat.st_ino || fd_stat.st_dev != bind_stat.st_dev ||
	    fd_stat.st_ino != bind_stat.st_ino || pread(fd, value, sizeof(value), 0) <= 0) {
		fail("cgroup pressure file bind or retained descriptor changed");
		return 1;
	}
	close(fd);
	if (umount(target) || umount(cg) || umount(dirname))
		return 1;
	pass();
	return 0;
}
