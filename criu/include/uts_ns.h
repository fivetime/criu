#ifndef __CR_UTS_NS_H__
#define __CR_UTS_NS_H__

extern int dump_uts_ns(int ns_id);
extern int prepare_utsns(int pid);
extern int prepare_uts_namespaces(void);
struct pstree_item;
extern int restore_task_uts_ns(struct pstree_item *item);

extern struct ns_desc uts_ns_desc;

#endif /* __CR_UTS_NS_H__ */
