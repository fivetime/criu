#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static volatile sig_atomic_t stop, verify;

static void handle(int sig)
{
	if (sig == SIGUSR1)
		verify = 1;
	else
		stop = 1;
}

static int rights(int socket, int fd, int receive)
{
	char control[CMSG_SPACE(sizeof(fd))] = {}, byte = 'x';
	struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = control, .msg_controllen = sizeof(control) };
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

	if (receive) {
		if (recvmsg(socket, &msg, MSG_DONTWAIT) != 1 || msg.msg_flags & MSG_CTRUNC)
			return -1;
		if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
		    cmsg->cmsg_len != CMSG_LEN(sizeof(fd)))
			return -1;
		memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
		return fd;
	}
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
	return sendmsg(socket, &msg, 0) == 1 ? 0 : -1;
}

int main(int argc, char **argv)
{
	const char trigger[] = "some 2000000 2000000";
	char status[160];
	unsigned long counter = 0;
	int flags, fd, output, sockets[2] = { -1, -1 }, checks = 0;
	int armed, queued, error = 0;

	if (argc != 4 && argc != 5)
		return 2;
	armed = strstr(argv[1], "armed") && !strstr(argv[1], "unarmed");
	queued = strstr(argv[1], "scm") != NULL;
	flags = strstr(argv[1], "readonly") ? O_RDONLY :
		strstr(argv[1], "opath") ? O_PATH :
		strstr(argv[1], "wronly") ? O_WRONLY : O_RDWR;
	if (argc == 5) {
		/* Exercise a bind alias that exists only in the dumped mount namespace. */
		if (unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL) ||
		    mount(argv[2], argv[4], NULL, MS_BIND, NULL))
			return 3;
		argv[2] = argv[4];
	}
	fd = open(argv[2], flags | O_NONBLOCK);
	if (fd < 0 || (armed && write(fd, trigger, sizeof(trigger)) != (ssize_t)sizeof(trigger)))
		return 4;
	if (strstr(argv[1], "dup")) {
		int original = fd;
		fd = dup(fd);
		close(original);
		if (fd < 0)
			return 5;
	}
	if (queued) {
		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) || rights(sockets[0], fd, 0))
			return 6;
		close(fd);
		fd = -1; /* Only the queued SCM_RIGHTS message retains this description. */
	}
	output = open(argv[3], O_CREAT | O_EXCL | O_WRONLY, 0600);
	if (output < 0)
		return 7;
	signal(SIGTERM, handle);
	signal(SIGINT, handle);
	signal(SIGUSR1, handle);
	while (!stop) {
		if (verify) {
			struct pollfd pfd;
			verify = 0;
			if (queued && fd < 0)
				fd = rights(sockets[1], -1, 1);
			if (fd < 0 || (fcntl(fd, F_GETFL) & (O_ACCMODE | O_PATH)) != flags)
				error = 1;
			pfd = (struct pollfd){ .fd = fd, .events = POLLPRI };
			if (armed && (poll(&pfd, 1, 0) < 0 || pfd.revents & (POLLERR | POLLHUP | POLLNVAL)))
				error = 2;
			if (armed && (write(fd, trigger, sizeof(trigger)) != -1 || errno != EBUSY))
				error = 3;
			checks++;
		}
		int len = snprintf(status, sizeof(status), "%d %lu %d %d %d\n",
				   getpid(), ++counter, checks, error, flags);
		if (pwrite(output, status, len, 0) != len || ftruncate(output, len))
			return 8;
		usleep(10000);
	}
	close(output);
	if (fd >= 0)
		close(fd);
	return error ? 9 : 0;
}
