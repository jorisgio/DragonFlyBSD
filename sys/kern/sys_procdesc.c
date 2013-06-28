#include "opt_procdesc.h"

#include <sys/proc.h>
#include <sys/procdesc.h>
#include <sys/file.h>
#include <sys/filedesc.h>

#ifdef PROCDESC

static int procdesc_read (struct file *fp, struct uio *uio,
	struct ucred *cred, int flags);
static int procdesc_write (struct file *fp, struct uio *uio,
	struct ucred *cred, int flags);
static int procdesc_ioctl (struct file *fp, struct uio *uio,
	struct ucred *cred, struct sysmsg *msg);
static int procdesc_kqfilter (struct file *fp, struct knote *kn);
static int procdesc_stat (struct file *fp, struct stat *sb,
	struct ucred *cred);
static int procdesc_close (struct file *fp);
static int procdesc_shutdown (struct file *fp, int how);

struct fileops procdesc_ops {
	.fo_read = procdesc_read,
	.fo_write = procdesc_write,
	.fo_ioctl = procdesc_ioctl,
	.fo_kqfilter = procdesc_kqfilter,
	.fo_stat = procdesc_stat,
	.fo_close = procdesc_close,
	.fo_shutdown = procdesc_shutdown
}

/*
 * When a process is reaped, the normal operations are not valid anymore
 * since the proc structure is gone.
 * These are fileops used when the referenced process has completely died.
 */
struct fileops procdesc_reaped_ops {
	.fo_read = procdesc_read,
	.fo_write = procdesc_write,
	.fo_ioctl = procdesc_ioctl,
	.fo_kqfilter = procdesc_kqfilter,
	.fo_stat = procdesc_stat,
	.fo_close = procdesc_close,
	.fo_shutdown = procdesc_shutdown
}


//static void procdesc_init(void __unusded *dummy);
//SYSINIT(procdesc, SI_SUB_VFS, SI_ORDER_ANY, procdesc_init, NULL)

/*
 * Returns the process referenced by the given filedescriptor
 * or ESRCH if the process has died.
 */
int
holdproc_capcheck(struct filedesc *fdp, int fd, cap_rights_t rights,
	struct proc **p)
{

	struct file *fp;
	struct prochandle *ph;
	int error;

	KASSERT(p != NULL, ("holdproc_capcheck called with a NULL pointer"));

	if ((error = holdfp_capcheck(fdp, fd, &fp, -1, rights, -1)) != 0) {
		return (error);
	}

	if (fp->f_type != DTYPE_PROC) {
		fdrop(fp);
		return (EINVAL);
	}

	lwkt_gettoken(&proc_token);

	if ((*p = fp->f_data) == NULL) {
		error = ESRCH;
	} else {
		PHOLD(p);
		error = 0;
	}
	lwkt_relttoken(&proc_token);
	fdrop(fp);
	return (error);
}

int
kern_pdgetpid(struct filedesc *fdp, int fd, pid_t *pid)
{
	struct proc *p;
	int error;

	if ((error = holdproc_capcheck(fdp, fd, CAP_PDGETPID, &p)) != 0) {
		return (error);
	}

	*pid = p->p_pid;
	PRELE(p);
	return (0);
}


/*
 * syscall to retrieve the pid of the process referenced by the file descriptor
 */
int
sys_pdgetpid(struct pdgetpid_args *uap)
{
	struct proc *p = curproc;
	int error;
	pid_t pid;

	KASSERT(p != NULL, ("pdgetpid called with NULL curproc"));

	error = kern_pdgetpid(p->p_fd, uap->fd, pid);
	if (error == 0)
		error = copyout(&pid, uap->pidp, sizeof(pid));
	return (error);
}

/*
 * Callback for cleaning things up when a process is reap
 */
void
procdesc_reap(struct proc *p)
{
	KASSERT(p->p_procdesc != NULL, ("procdesc_reap: p_procdesc is NULL"));

	p->p_procdesc->f_data = NULL;
	p->p_procdesc = NULL;
}


/*
 * last close on a process descriptor
 * If the process is still running, terminates with SIGKILL if P_KILLONCLOSE is
 * set, and let init clean up the mess.
 */
static int
procdesc_close(struct file *fp)
{
	struct proc *p;

	struct proc *q = curproc;
	KASSERT(q != NULL, ("procdesc_close: cuproc is NULL"));

	fp->f_ops = &badfileops;

	if (p != NULL) {
		/*
		 * process has not yet been reaped
		 */
		lwkt_gettoken(&q->p_token);
		if ( p->p_stat == SZOMB ) {
			/*
			 * process is already dead and waiting reaping
			 * reap it, this will callback procdec_reap and clean
			 * the procdesc reference. Proc is already in SZOMB,
			 * hence kern_wait will not wait.
			 */
			while (proc_reap(q, p, NULL, NULL)) {
				;
			}
		} else {
			/*
			 * If the process is not yet dead, we need to kill it.
			 * Since we don't want to wait synchronously, we
			 * reparent the process to init.
			 */

			p->p_sigparent = SIGCHLD;
			proc_reparent(p, initproc);
			if (p->p_flags & P_KILLONCLOSE)
				ksignal(p, SIGKILL);
		}

		lwkt_reltoken(&q->p_token);
	}
	return(0);
}


static int
procdesc_read(struct file *fp, struct uio *uio, struct ucred *cred,
	int flags)
{

	return (EOPNOTSUPP);
}

static int
procdesc_write(struct file *fp, struct uio *uio, struct ucred *cred,
	int flags)
{

	return (EOPNOTSUPP);
}


static int
procdesc_ioctl(struct file *fp, struct uio *uio, struct ucred *cred,
	struct sysmsg *msg)
{

	return (EOPNOTSUPP);
}

static int
procdesc_kqfilter (struct file *fp, struct knote *kn)
{
	struct proc *p;
	/* TODO */

	return (EOPNOTSUPP);
}

static int
procdesc_stat (struct file *fp, struct stat *sb, struct ucred *cred)
{
	/* TODO */
	return (EOPNOTSUPP);
}
static int
procdesc_close (struct file *fp)
{
	return (EOPNOTSUPP);
}
static int
procdesc_shutdown (struct file *fp, int how)
{
	/* TODO */
	return (EOPNOTSUPP);
}

#else /* !PROCDESC */

int
sys_pdgetpid(struct pdgetpid_args *uap)
{

		return (ENOSYS);
}

#endif /* PROCDESC */
