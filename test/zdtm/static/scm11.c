#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Restore queued SCM_RIGHTS across socketpair owners";
const char *test_author = "Simon Zhou <jp.zdm2008@gmail.com>";

static int queue_pipe(int sock, const char *value)
{
	char control[CMSG_SPACE(2 * sizeof(int))] = {};
	char byte = 'p';
	struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = control, .msg_controllen = sizeof(control) };
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	int pipes[2], ret;

	if (pipe(pipes))
		return -1;
	if (write(pipes[1], value, strlen(value) + 1) != strlen(value) + 1) {
		close(pipes[0]);
		close(pipes[1]);
		return -1;
	}
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(pipes));
	memcpy(CMSG_DATA(cmsg), pipes, sizeof(pipes));
	ret = sendmsg(sock, &msg, 0);
	/* Only the queued message owns these descriptors at checkpoint. */
	close(pipes[0]);
	close(pipes[1]);
	return ret == 1 ? 0 : -1;
}

static int check_pipe(int sock, const char *value)
{
	char control[CMSG_SPACE(2 * sizeof(int))] = {};
	char byte, data[32];
	struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = control, .msg_controllen = sizeof(control) };
	struct cmsghdr *cmsg;
	int pipes[2], ret = -1;

	if (recvmsg(sock, &msg, MSG_DONTWAIT) != 1 || byte != 'p' ||
	    (msg.msg_flags & (MSG_CTRUNC | MSG_TRUNC)))
		return -1;
	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
	    cmsg->cmsg_len != CMSG_LEN(sizeof(pipes)))
		return -1;
	memcpy(pipes, CMSG_DATA(cmsg), sizeof(pipes));
	if (fcntl(pipes[0], F_SETFL, O_NONBLOCK))
		goto out;
	if (read(pipes[0], data, sizeof(data)) != strlen(value) + 1 || memcmp(data, value, strlen(value) + 1))
		goto out;
	/* Check both received endpoints, not merely that fd numbers exist. */
	if (write(pipes[1], "again", 6) != 6 || read(pipes[0], data, sizeof(data)) != 6 ||
	    memcmp(data, "again", 6))
		goto out;
	ret = 0;
out:
	close(pipes[0]);
	close(pipes[1]);
	return ret;
}

int main(int argc, char **argv)
{
	task_waiter_t waiter;
	int sk[2], status, ret;
	pid_t pid;

	test_init(argc, argv);
	task_waiter_init(&waiter);
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sk)) {
		pr_perror("Can't create socketpair");
		return 1;
	}
	pid = test_fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		return 1;
	}
	if (!pid) {
		close(sk[0]);
		if (queue_pipe(sk[1], "child")) {
			pr_perror("Can't queue child pipe");
			return 1;
		}
		task_waiter_complete(&waiter, 1);
		task_waiter_wait4(&waiter, 2);
		ret = check_pipe(sk[1], "parent");
		if (ret)
			fail("Child received wrong SCM_RIGHTS");
		close(sk[1]);
		return ret ? 1 : 0;
	}
	close(sk[1]);
	if (queue_pipe(sk[0], "parent")) {
		pr_perror("Can't queue parent pipe");
		return 1;
	}
	task_waiter_wait4(&waiter, 1);
	test_daemon();
	test_waitsig();
	ret = check_pipe(sk[0], "child");
	if (ret)
		fail("Parent received wrong SCM_RIGHTS");
	task_waiter_complete(&waiter, 2);
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status)) {
		fail("Child failed SCM_RIGHTS verification");
		return 1;
	}
	close(sk[0]);
	if (!ret)
		pass();
	return ret ? 1 : 0;
}
