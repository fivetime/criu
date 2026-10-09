#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Restore distinct and shared nested UTS namespaces and namespace descriptors";
const char *test_author = "CRIU contributors";

int main(int argc, char **argv)
{
	struct utsname before, after;
	int ready[3][2], done[3][2], status, root_fd, shared_fd = -1, i, ret = 1;
	pid_t children[3] = { 0 };
	char path[64], byte;

	test_init(argc, argv);
	root_fd = open("/proc/self/ns/uts", O_RDONLY);
	if (root_fd < 0 || uname(&before))
		return 1;
	for (i = 0; i < 3; i++) {
		if (pipe(ready[i]) || pipe(done[i]))
			goto out;
		children[i] = fork();
		if (children[i] < 0)
			goto out;
		if (!children[i]) {
			const char *node = i == 1 ? "sub-two" : "sub-one";
			const char *domain = i == 1 ? "domain-two" : "domain-one";

			close(ready[i][0]);
			close(done[i][1]);
			if (i == 2) {
				if (setns(shared_fd, CLONE_NEWUTS))
					_exit(1);
			} else if (unshare(CLONE_NEWUTS) || sethostname(node, strlen(node)) ||
				   setdomainname(domain, strlen(domain))) {
				_exit(1);
			}
			if (write(ready[i][1], "r", 1) != 1 || read(done[i][0], &byte, 1) != 1 || uname(&after))
				_exit(1);
			node = i == 1 ? "sub-two" : "shared-after";
			_exit(strcmp(after.nodename, node) || strcmp(after.domainname, domain) ? 1 : 0);
		}
		close(ready[i][1]);
		close(done[i][0]);
		if (read(ready[i][0], &byte, 1) != 1)
			goto out;
		close(ready[i][0]);
		if (i == 0) {
			ssprintf(path, "/proc/%d/ns/uts", children[i]);
			shared_fd = open(path, O_RDONLY);
			if (shared_fd < 0)
				goto out;
		}
	}

	test_daemon();
	test_waitsig();

	if (setns(shared_fd, CLONE_NEWUTS) || uname(&after) || strcmp(after.nodename, "sub-one") ||
	    strcmp(after.domainname, "domain-one") || sethostname("shared-after", strlen("shared-after")) ||
	    setns(root_fd, CLONE_NEWUTS) || uname(&after) || strcmp(after.nodename, before.nodename) ||
	    strcmp(after.domainname, before.domainname)) {
		fail("UTS namespace descriptor identity or root namespace changed");
		goto out;
	}
	for (i = 0; i < 3; i++) {
		if (write(done[i][1], "d", 1) != 1 || waitpid(children[i], &status, 0) != children[i] ||
		    !WIFEXITED(status) || WEXITSTATUS(status)) {
			fail("nested UTS namespace contents or sharing changed");
			goto out;
		}
		children[i] = 0;
	}
	pass();
	ret = 0;
out:
	for (i = 0; i < 3; i++)
		if (children[i] > 0) {
			kill(children[i], SIGKILL);
			waitpid(children[i], NULL, 0);
		}
	close(root_fd);
	if (shared_fd >= 0)
		close(shared_fd);
	return ret;
}
