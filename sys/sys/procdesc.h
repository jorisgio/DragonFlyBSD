#ifndef _SYS_PROCDESC_H
#define _SYS_PROCDESC_H

#include <sys/types.h>

#ifdef _KERNEL

struct proc;
struct filedesc;

int holdproc_capcheck(struct filedesc *fdp, int fd, cap_rights_t rights,
	struct proc **p);
void procdesc_reap(struct proc *p);

#else /* !_KERNEL */

pid_t pdfork(int *, int);

#endif /* _KERNEL */

#endif /* !_SYS_PROCDESC_H */
