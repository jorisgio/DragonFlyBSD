#include <sys/types.h>
#include <sys/systm.h>
#include <sys/ucred.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/uio.h>
#include <sys/priv.h>
#include <sys/sysproto.h>

#include <sys/spinlock2.h>
#include <sys/thread.h>

static int creddesc_read (struct file *fp, struct uio *uio,
	struct ucred *cred, int flags);
static int creddesc_write (struct file *fp, struct uio *uio,
	struct ucred *cred, int flags);
static int creddesc_ioctl (struct file *fp, u_long com, caddr_t data,
	struct ucred *cred, struct sysmsg *msg);
static int creddesc_kqfilter (struct file *fp, struct knote *kn);
static int creddesc_stat (struct file *fp, struct stat *sb,
	struct ucred *cred);
static int creddesc_close (struct file *fp);
static int creddesc_shutdown (struct file *fp, int how);

static inline struct ucred *holdcreddata(struct file *fp);

struct fileops creddescops = {
	.fo_read = creddesc_read,
	.fo_write = creddesc_write,
	.fo_ioctl = creddesc_ioctl,
	.fo_kqfilter = creddesc_kqfilter,
	.fo_stat = creddesc_stat,
	.fo_shutdown = creddesc_shutdown,
	.fo_close = creddesc_close
};

int
sys_opencred(struct opencred_args *uap)
{
	struct thread *td = curthread;
	struct lwp *lp = td->td_lwp;
	struct file *fp;
	struct ucred *cr;
	int flags;
	int fd;
	int error;

	error = falloc(lp, &fp, &fd);
	if (error)
		return (error);

	flags = FFLAGS(uap->flags);

	/* XXX credential should be protected by p_token */
	lwkt_gettoken(&proc_token);
	cr = td->td_proc->p_ucred;
	crhold(cr);
	spin_lock(&fp->f_spin);
	fp->f_data = (void *) cr;
	spin_unlock(&fp->f_spin);

	lwkt_reltoken(&proc_token);
	return(0);
}

/*
 * Returns the ucred structure assotiated to the cred descriptor.
 * The ucred is always referenced.
 */
static inline struct ucred *
holdcreddata(struct file *fp)
{
	struct ucred *cr;
	spin_lock(&fp->f_spin);
	cr = (struct ucred *)fp->f_data;
	crhold(cr);
	spin_unlock(&fp->f_spin);
	return (cr);
}


/*
 * Change effective uid and realuid to the effective uid of the
 * credential structure pointed to by the file descriptor
 */
int
sys_setuidfromfd(struct setuidfromfd_args *uap)
{
	struct proc *p = curproc;
	struct file *fp;
	struct ucred *cr, *curcr;
	uid_t uid;

	fp = holdfp(p->p_fd, uap->fd, FREAD);
	if (fp == NULL)
		return (EBADF);
	if (fp->f_type != DTYPE_CRED)
		return (EINVAL);

	cr = holdcreddata(fp);
	fdrop(fp);

	/* XXX credential should be protected by p_token */
	lwkt_gettoken(&proc_token);
	curcr = p->p_ucred;
	uid = cr->cr_uid;

	if (uid != curcr->cr_ruid) {
		curcr = change_ruid(uid);
		setsugid();
	}

	/*
	* Set saved uid
	*
	* XXX always set saved uid even if not _POSIX_SAVED_IDS, as
	* the security of seteuid() depends on it. B.4.2.2 says it
	* is important that we should do this.
	*/
	if (curcr->cr_svuid != uid) {
		cr = cratom(&p->p_ucred);
		cr->cr_svuid = uid;
		setsugid();
	}

	/*
	 * Set the euid.
	 */
	if (curcr->cr_uid != uid) {
		change_euid(uid);
		setsugid();
	}

	lwkt_reltoken(&proc_token);
	crfree(cr);

	return (0);
}

/*
 * Change effective uid and realuid to the effective uid of the
 * credential structure pointed to by the file descriptor
 */
int
sys_setgidfromfd(struct setgidfromfd_args *uap)
{
	struct proc *p = curproc;
	struct file *fp;
	struct ucred *cr, *curcr;
	gid_t gid;

	fp = holdfp(p->p_fd, uap->fd, FREAD);
	if (fp == NULL)
		return (EBADF);

	if (fp->f_type != DTYPE_CRED)
		return (EINVAL);

	cr = holdcreddata(fp);
	fdrop(fp);

	/* XXX credential should be protected by p_token */
	lwkt_gettoken(&proc_token);
	curcr = p->p_ucred;
	gid = cr->cr_uid;

	if (gid != curcr->cr_rgid) {
		curcr = cratom(&p->p_ucred);
		curcr->cr_rgid = gid;
		setsugid();
	}

	/*
	* Set saved gid
	*
	* XXX always set saved gid even if not _POSIX_SAVED_IDS, as
	* the security of seteuid() depends on it. B.4.2.2 says it
	* is important that we should do this.
	*/
	if (curcr->cr_svgid != gid) {
		cr = cratom(&p->p_ucred);
		cr->cr_svgid = gid;
		setsugid();
	}

	/*
	 * Set the egid.
	 */
	if (curcr->cr_gid != gid) {
		curcr = cratom(&p->p_ucred);
		cr->cr_groups[0] = gid;
		setsugid();
	}

	lwkt_reltoken(&proc_token);
	crfree(cr);
	return (0);
}

int
sys_setgroupsfromfd(struct setgroupsfromfd_args *uap)
{
	struct proc *p = curproc;
	struct file *fp;
	struct ucred *cr, *curcr;

	fp = holdfp(p->p_fd, uap->fd, FREAD);
	if (fp == NULL)
		return (EBADF);

	if (fp->f_type != DTYPE_CRED)
		return (EINVAL);

	cr = holdcreddata(fp);
	fdrop(fp);

	/* XXX credential should be protected by p_token */
	lwkt_gettoken(&proc_token);
	curcr = p->p_ucred;

	curcr = cratom(&p->p_ucred);
	curcr->cr_ngroups = cr->cr_ngroups;
	bcopy(cr->cr_groups, curcr->cr_groups, cr->cr_ngroups * sizeof(gid_t));

	setsugid();
	lwkt_reltoken(&proc_token);
	crfree(cr);

	return(0);
}


static int
creddesc_read(struct file *fp, struct uio *uio, struct ucred *cred,
	int flags)
{
	struct ucred *cr;
	struct xucred crbuf;
	int error;

	if (uio->uio_resid == 0) {
		error = 0;
		goto done;
	}

	/* Get the ucred structure */

	spin_lock(&fp->f_spin);
	cr = (struct ucred *) fp->f_data;
	cru2x(cr, &crbuf);
	spin_unlock(&fp->f_spin);

	/* check that read as the right length */
	if (sizeof (struct xucred) > uio->uio_resid) {
		error = ENOSPC;
		goto done;
	}

	/* check if uio has enough space to hold the structure */
	if (sizeof (struct xucred) > uio->uio_iov[0].iov_len) {
		error = ENOSPC;
		goto done;
	}

	/* copy the data */
	error = uiomove((void *) &crbuf, sizeof (struct xucred), uio);

done:
	return (error);
}


static int
creddesc_write(struct file *fp, struct uio *uio, struct ucred *cred,
	int flags)
{
	struct proc *p = curproc;
	struct ucred *cr, *creds;
	struct xucred crbuf;
	int error;

	lwkt_gettoken(&proc_token);
	creds = p->p_ucred;
	crhold(creds);
	lwkt_reltoken(&proc_token);

	if (uio->uio_resid > sizeof(struct xucred)) {
		error = EFBIG;
		goto done;
	}

	/* Get the ucred structure */
	error = uiomove((void *) &crbuf, sizeof (struct xucred), uio);
	if (error)
		goto done;

	/* Check if we have the rights to grand such permissions */

	/*
	 * Check if we can grant this uid
	 * Same policy as setuid
	 */
	if (crbuf.cr_uid != creds->cr_ruid &&
#ifdef _POSIX_SAVED_IDS
		crbuf.cr_uid != creds->cr_svuid &&
#endif
#ifdef POSIX_APPENDIX_B_4_2_2   /* Use BSD-compat clause from B.4.2.2 */
		crbuf.cr_uid != creds->cr_uid &&
#endif
	    (error = priv_check_cred(creds, PRIV_CRED_SETUID, 0)))
		goto done;

	/*
	 * Check if we can grant this gid
	 * Same policy as getuid
	 */
	if (crbuf.cr_gid != creds->cr_rgid &&
#ifdef _POSIX_SAVED_IDS
		crbuf.cr_gid != creds->cr_svgid &&
#endif
#ifdef POSIX_APPENDIX_B_4_2_2   /* Use BSD-compat clause from B.4.2.2 */
		crbuf.cr_gid != creds->cr_gid &&
#endif
	    (error = priv_check_cred(creds, PRIV_CRED_SETGID, 0)))
		goto done;

	/*
	 * Check if we can grand this set of groups
	 */

	if ((error = priv_check_cred(creds, PRIV_CRED_SETGROUPS, 0))) {

		/* Fast path */
		if (crbuf.cr_ngroups != creds->cr_ngroups) {
			goto done;
		} else {
			for (int i = 0; i < crbuf.cr_ngroups; ++i) {
				if ( crbuf.cr_groups[i] != creds->cr_groups[i] )
					goto done;
			}
		}
		error = 0;
	}



	/* allocate a new cred structure and copy informations */
	cr = crget();

	cr->cr_uid = crbuf.cr_uid;
	cr->cr_ngroups = crbuf.cr_ngroups;
	bcopy(cr->cr_groups, crbuf.cr_groups, cr->cr_ngroups * sizeof (gid_t));

	spin_lock(&fp->f_spin);
	crfree((struct ucred *) fp->f_data);
	fp->f_data = (void *) cr;
	spin_unlock(&fp->f_spin);
	error = 0;
done:
	crfree(creds);
	return (error);
}


static int
creddesc_ioctl(struct file *fp, u_long com, caddr_t data, struct ucred *cred,
	struct sysmsg *msg)

{

	return (EOPNOTSUPP);
}

static int
creddesc_kqfilter (struct file *fp, struct knote *kn)
{
	return (EOPNOTSUPP);
}

static int
creddesc_stat (struct file *fp, struct stat *sb, struct ucred *cred)
{
	return (EOPNOTSUPP);
}

static int
creddesc_shutdown (struct file *fp, int how)
{
	return (EOPNOTSUPP);
}

static int
creddesc_close (struct file *fp)
{
	return (EOPNOTSUPP);
}
