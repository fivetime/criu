#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mountinfo.h"
#include "zdtmtst.h"

const char *test_doc = "Restore shared and shared-slave peers with disjoint roots";
const char *test_author = "CRIU contributors";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

static int bind_dir(const char *source, const char *target)
{
	if (mkdir(target, 0700) || mount(source, target, NULL, MS_BIND, NULL)) {
		pr_perror("bind %s to %s", source, target);
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	MNTNS_ZDTM(before);
	MNTNS_ZDTM(after);
	int fd, cwd;

	test_init(argc, argv);
	if (mkdir(dirname, 0700) || mount("disjoint", dirname, "tmpfs", 0, NULL) ||
	    mount(NULL, dirname, NULL, MS_PRIVATE, NULL)) {
		pr_perror("prepare private tmpfs");
		return 1;
	}
	cwd = open(".", O_DIRECTORY);
	if (cwd < 0 || chdir(dirname))
		return 1;
	if (mkdir("source", 0700) || mkdir("source/a", 0700) || mkdir("source/b", 0700) ||
	    mkdir("source/a/child", 0700) || mkdir("source/b/child", 0700))
		return 1;
	if (bind_dir("source", "anchor") || mount(NULL, "anchor", NULL, MS_SHARED, NULL) ||
	    bind_dir("anchor", "slave-anchor") || mount(NULL, "slave-anchor", NULL, MS_SLAVE, NULL) ||
	    mount(NULL, "slave-anchor", NULL, MS_SHARED, NULL))
		return 1;
	if (bind_dir("anchor/a", "left") || bind_dir("anchor/a", "left-alias") ||
	    bind_dir("anchor/b", "right") || bind_dir("anchor/b", "right-alias") ||
	    bind_dir("slave-anchor/a", "slave-left") || bind_dir("slave-anchor/b", "slave-right"))
		return 1;
	/* Only the private source retains the common root of each peer group. */
	if (umount("slave-anchor") || umount("anchor") || fchdir(cwd))
		return 1;
	close(cwd);
	if (mntns_parse_mountinfo(&before))
		return 1;

	test_daemon();
	test_waitsig();

	if (mntns_parse_mountinfo(&after) || mntns_compare(&before, &after)) {
		fail("shared/slave topology changed");
		return 1;
	}
	if (chdir(dirname) || mount("child", "left/child", "tmpfs", 0, NULL)) {
		pr_perror("mount propagated child");
		return 1;
	}
	fd = open("left/child/marker", O_CREAT | O_WRONLY, 0600);
	if (fd < 0)
		return 1;
	close(fd);
	if (access("left-alias/child/marker", F_OK) || access("slave-left/child/marker", F_OK) ||
	    !access("right/child/marker", F_OK) || !access("slave-right/child/marker", F_OK)) {
		fail("restored propagation does not respect peer roots");
		return 1;
	}
	if (umount("left/child"))
		return 1;
	mntns_free_all(&before);
	mntns_free_all(&after);
	pass();
	return 0;
}
