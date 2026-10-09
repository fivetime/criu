#include <unistd.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <string.h>
#include <sched.h>

#include "util.h"
#include "namespaces.h"
#include "sysctl.h"
#include "uts_ns.h"
#include "fdstore.h"
#include "pstree.h"

#include "protobuf.h"
#include "images/utsns.pb-c.h"

int dump_uts_ns(int ns_id)
{
	int ret;
	struct cr_img *img;
	struct utsname ubuf;
	UtsnsEntry ue = UTSNS_ENTRY__INIT;

	img = open_image(CR_FD_UTSNS, O_DUMP, ns_id);
	if (!img)
		return -1;

	ret = uname(&ubuf);
	if (ret < 0) {
		pr_perror("Error calling uname");
		goto err;
	}

	ue.nodename = ubuf.nodename;
	ue.domainname = ubuf.domainname;

	ret = pb_write_one(img, &ue, PB_UTSNS);
err:
	close_image(img);
	return ret < 0 ? -1 : 0;
}

int prepare_utsns(int pid)
{
	int ret;
	struct cr_img *img;
	UtsnsEntry *ue;
	struct sysctl_req req[] = {
		{ "kernel/hostname" },
		{ "kernel/domainname" },
	};

	img = open_image(CR_FD_UTSNS, O_RSTR, pid);
	if (!img)
		return -1;

	ret = pb_read_one(img, &ue, PB_UTSNS);
	if (ret < 0)
		goto out;

	req[0].arg = ue->nodename;
	req[0].type = CTL_STR(strlen(ue->nodename));
	req[1].arg = ue->domainname;
	req[1].type = CTL_STR(strlen(ue->domainname));

	ret = sysctl_op(req, ARRAY_SIZE(req), CTL_WRITE, CLONE_NEWUTS);
	utsns_entry__free_unpacked(ue, NULL);
out:
	close_image(img);
	return ret;
}

struct ns_desc uts_ns_desc = NS_DESC_ENTRY(CLONE_NEWUTS, "uts");

static int create_uts_namespaces(void *unused)
{
	struct ns_id *ns;
	int root_fd, fd, ret = -1;

	root_fd = open_proc(PROC_SELF, "ns/uts");
	if (root_fd < 0)
		return -1;

	for (ns = ns_ids; ns; ns = ns->next) {
		if (ns->nd != &uts_ns_desc)
			continue;
		if (ns->type == NS_ROOT) {
			fd = dup(root_fd);
		} else {
			if (unshare(CLONE_NEWUTS)) {
				pr_perror("Unable to create UTS namespace %u", ns->id);
				goto out;
			}
			if (prepare_utsns(ns->id))
				goto out;
			fd = open_proc(PROC_SELF, "ns/uts");
		}
		if (fd < 0)
			goto out;
		ns->uts.nsfd_id = fdstore_add(fd);
		close(fd);
		if (ns->uts.nsfd_id < 0)
			goto out;
	}
	ret = 0;
out:
	close(root_fd);
	return ret;
}

int prepare_uts_namespaces(void)
{
	if (!(root_ns_mask & CLONE_NEWUTS))
		return 0;

	/* Keep the root task in its own UTS namespace while preparing peers. */
	return call_in_child_process(create_uts_namespaces, NULL);
}

int restore_task_uts_ns(struct pstree_item *item)
{
	struct ns_id *ns;
	int fd, ret;

	if (!(root_ns_mask & CLONE_NEWUTS) || !item->ids || !item->ids->has_uts_ns_id)
		return 0;
	ns = lookup_ns_by_id(item->ids->uts_ns_id, &uts_ns_desc);
	if (!ns) {
		pr_err("Missing UTS namespace %u\n", item->ids->uts_ns_id);
		return -1;
	}
	fd = fdstore_get(ns->uts.nsfd_id);
	if (fd < 0)
		return -1;
	ret = setns(fd, CLONE_NEWUTS);
	if (ret)
		pr_perror("Unable to join UTS namespace %u", ns->id);
	close(fd);
	return ret;
}
