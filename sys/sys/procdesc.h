#ifndef _SYS_PROCDESC_H
#define _SYS_PROCDESC_H

#include <sys/types.h>

#ifdef _KERNEL

/* XXX temp declaration for standalone patch */
#define CAP_PDKILL 0
#define CAP_PDGETPID 0


struct proc;
struct filedesc;

int holdproc_capcheck(struct filedesc *fdp, int fd, cap_rights_t rights,
	struct proc **p);
void procdesc_reap(struct proc *p);

#else /* !_KERNEL */

pid_t pdfork(int *, int);

#endif /* _KERNEL */

#endif /* !_SYS_PROCDESC_H */
