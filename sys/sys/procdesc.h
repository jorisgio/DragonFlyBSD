#ifndef _SYS_PROCDESC_H
#define _SYS_PROCDESC_H

#include <sys/types.h>

#ifdef _KERNEL

int holdproc_capcheck(struct filedesc *fdp, int fd, cap_rights_t rights,
	struct proc **p);
int kern_pdgetpid(struct filedesc *fdp, int fd, pid_t *pid);

#else /* !_KERNEL */

pid_t pdfork(int *, int);

#endif /* _KERNEL */

#endif /* !_SYS_PROCDESC_H */
