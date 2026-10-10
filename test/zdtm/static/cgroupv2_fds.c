#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
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

#ifdef CGROUP_DEEP_EMPTY
/* No task lives in this branch while dumping. In particular the watched
 * cgroup must be collected by the hierarchy walk, not a task's cgroup set.
 */
#define EMPTY_BRANCH "zdtm-cgroupv2-fds/user.slice/user-1000.slice/user@1000.service/app.slice/dbus.socket"

static int create_empty_branch(void)
{
	char path[PATH_MAX], *slash;

	ssprintf(path, "%s/" EMPTY_BRANCH, dirname);
	slash = path + strlen(dirname) + strlen("/zdtm-cgroupv2-fds");
	while (*slash) {
		slash = strchr(slash + 1, '/');
		if (!slash)
			break;
		*slash = '\0';
		if (mkdir(path, 0755))
			return -1;
		*slash = '/';
	}
	return mkdir(path, 0755);
}

static int check_empty_branch_watch(int notify, int watch)
{
	char path[PATH_MAX], value[64];
	union {
		char data[4096];
		struct inotify_event align;
	} events;
	struct pollfd pfd = { .fd = notify, .events = POLLIN };
	ssize_t size, offset;

	/* Discard any events left over from dump or restore. */
	while (read(notify, events.data, sizeof(events.data)) > 0)
		;
	if (errno != EAGAIN)
		return -1;
	ssprintf(path, "%s/" EMPTY_BRANCH "/cgroup.procs", dirname);
	ssprintf(value, "%d", getpid());
	if (write_value(path, value))
		return -1;
	if (poll(&pfd, 1, 5000) != 1 || !(pfd.revents & POLLIN))
		return -1;
	size = read(notify, events.data, sizeof(events.data));
	if (size < 0)
		return -1;
	ssprintf(path, "%s/zdtm-cgroupv2-fds/leaf/cgroup.procs", dirname);
	if (write_value(path, value))
		return -1;
	for (offset = 0; offset < size;) {
		struct inotify_event *event = (void *)(events.data + offset);

		if ((size_t)(size - offset) < sizeof(*event) ||
		    event->len > (size_t)(size - offset) - sizeof(*event))
			return -1;
		if (event->wd == watch && (event->mask & IN_MODIFY))
			return 0;
		offset += sizeof(*event) + event->len;
	}
	return -1;
}
#endif

int main(int argc, char **argv)
{
	char path[PATH_MAX], value[64], byte;
	int ready[2], done[2], notify, status;
	pid_t child;
#ifdef CGROUP_DEEP_EMPTY
	int deep_watch;
#endif

	test_init(argc, argv);
	if (mkdir(dirname, 0755) || mount("cgroup2", dirname, "cgroup2", 0, NULL))
		return 1;
	ssprintf(path, "%s/zdtm-cgroupv2-fds", dirname);
	if (mkdir(path, 0755))
		return 1;
#ifdef CGROUPNS_ROOT
	ssprintf(path, "%s/zdtm-cgroupv2-fds/cgroup.procs", dirname);
	ssprintf(value, "%d", getpid());
	if (write_value(path, value) || unshare(CLONE_NEWCGROUP))
		return 1;
#endif
	ssprintf(path, "%s/zdtm-cgroupv2-fds/leaf", dirname);
	if (mkdir(path, 0755))
		return 1;
	ssprintf(path, "%s/zdtm-cgroupv2-fds/leaf/cgroup.procs", dirname);
	ssprintf(value, "%d", getpid());
	if (write_value(path, value))
		return 1;
	ssprintf(path, "%s/zdtm-cgroupv2-fds/cgroup.subtree_control", dirname);
	if (write_value(path, "+memory"))
		return 1;
#ifdef CGROUP_DEEP_EMPTY
	if (create_empty_branch())
		return 1;
#endif
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
		/* Statistics readers have no per-open PSI trigger to checkpoint. */
		fd = open(path, O_RDONLY);
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
#ifdef CGROUP_DEEP_EMPTY
	ssprintf(path, "%s/" EMPTY_BRANCH "/cgroup.events", dirname);
	deep_watch = inotify_add_watch(notify, path, IN_MODIFY);
	if (deep_watch < 0)
		return 1;
#endif

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
#ifdef CGROUP_DEEP_EMPTY
	if (check_empty_branch_watch(notify, deep_watch)) {
		fail("deep empty cgroup or its original notification watch was not restored");
		return 1;
	}
#endif
	close(notify);
	if (umount(dirname))
		return 1;
	pass();
	return 0;
}
