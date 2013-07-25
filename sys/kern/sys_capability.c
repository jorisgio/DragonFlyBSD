/*-
 * Copyright (c) 2008-2011 Robert N. M. Watson
 * Copyright (c) 2010-2011 Jonathan Anderson
 * Copyright (c) 2012 FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed at the University of Cambridge Computer
 * Laboratory with support from a grant from Google, Inc.
 *
 * Portions of this software were developed by Pawel Jakub Dawidek under
 * sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * kernel capability facility.
 *
 * Two kernel features are implemented here: capability mode, a sandboxed mode
 * of execution for processes, and capabilities, a refinement on file
 * descriptors that allows fine-grained control over operations on the file
 * descriptor.  Collectively, these allow processes to run in the style of a
 * historic "capability system" in which they can use only resources
 * explicitly delegated to them.  This model is enforced by restricting access
 * to global namespaces in capability mode.
 *
 * Capabilities wrap other file descriptor types, binding them to a constant
 * rights mask set when the capability is created.  New capabilities may be
 * derived from existing capabilities, but only if they have the same or a
 * strict subset of the rights on the original capability.
 *
 * System calls permitted in capability mode are defined in capabilities.conf;
 * calls must be carefully audited for safety to ensure that they don't allow
 * escape from a sandbox.  Some calls permit only a subset of operations in
 * capability mode -- for example, shm_open(2) is limited to creating
 * anonymous, rather than named, POSIX shared memory objects.
 */

#include <sys/cdefs.h>

#include "opt_capsicum.h"
#include "opt_ktrace.h"

#include <sys/param.h>
#include <sys/capability.h>
#include <sys/malloc.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/sysproto.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/ucred.h>
#include <sys/ktrace.h>

#include <sys/spinlock2.h>

#if CAPABILITY_MODE

#if 0
/*
 * System call not allowed in capability mode
 */
int
sys_notcapable(struct sys_notcapable_args *uap)
{
	return (ENOTCAPABLE)
}
#endif

/*
 * System call to enter capability mode for the process.
 */
int
sys_cap_enter(struct cap_enter_args *uap)
{
	struct ucred *newcred;
	struct proc *p = curproc;

	if (IN_CAPABILITY_MODE(p))
		return (0);

	/* XXX it looks like credential are still protected by the proc_token */
	lwkt_gettoken(&proc_token);
	newcred = cratom(&p->p_ucred);
	newcred->cr_flags |= CRED_FLAG_CAPMODE;
	lwkt_reltoken(&proc_token);

	return (0);
}

/*
 * System call to query whether the process is in capability mode.
 */
int
sys_cap_getmode(struct cap_getmode_args *uap)
{
	u_int i;
	struct proc *p = curproc;

	KKASSERT(p != NULL);

	i = IN_CAPABILITY_MODE(p) ? 1 : 0;
	return (copyout(&i, uap->modep, sizeof(i)));
}

#else /* !CAPABILITY_MODE */

int
sys_cap_enter(struct cap_enter_args *uap)
{

	return (ENOSYS);
}

int
sys_cap_getmode(struct cap_getmode_args *uap)
{

	return (ENOSYS);
}

#endif /* CAPABILITY_MODE */

#ifdef CAPABILITIES

static inline int
_cap_check(cap_rights_t have, cap_rights_t need) //, enum ktr_cap_fail_type type)
{


	if ((need & ~have) != 0) {
#if 0 //KTRACE
		if (KTRPOINT(curthread, KTR_CAPFAIL))
			ktrcapfail(type, need, have);
#endif
		return (ENOTCAPABLE);
	}
	return (0);
}

/*
 * Test whether a capability grants the requested rights.
 */
int
cap_check(cap_rights_t have, cap_rights_t need)
{

	return (_cap_check(have, need)); //, CAPFAIL_NOTCAPABLE));
}

/*
 * Convert capability rights into VM access flags.
 */
u_char
cap_rights_to_vmprot(cap_rights_t have)
{
	u_char maxprot;

	maxprot = VM_PROT_NONE;
	if (have & CAP_MMAP_R)
		maxprot |= VM_PROT_READ;
	if (have & CAP_MMAP_W)
		maxprot |= VM_PROT_WRITE;
	if (have & CAP_MMAP_X)
		maxprot |= VM_PROT_EXECUTE;

	return (maxprot);
}

/*
 * Extract rights from a capability for monitoring purposes -- not for use in
 * any other way, as we want to keep all capability permission evaluation in
 * this one file.
 */
cap_rights_t
cap_rights(struct filedesc *fdp, int fd)
{

	return (fdp->fd_files[fd].fcaps.fc_rights);
}

/*
 * System call to limit rights of the given capability.
 */
int
sys_cap_rights_limit(struct cap_rights_limit_args *uap)
{
	struct filedesc *fdp;
	cap_rights_t rights;
	struct ioctls_list *tofree = NULL;
	struct proc *p = curproc;
	int error, fd;

	KKASSERT(p != NULL);

	fd = uap->fd;
	rights = uap->rights;

	if ((rights & ~CAP_ALL) != 0)
		return (EINVAL);

	fdp = p->p_fd;
	spin_lock(&fdp->fd_spin);
	if (fdvalidate(fdp, fd)) {
		spin_unlock(&fdp->fd_spin);
		return (EBADF);
	}
	error = cap_check(cap_rights(fdp, fd), rights);// , CAPFAIL_INCREASE);
	if (error == 0) {
		fdp->fd_files[fd].fcaps.fc_rights = rights;
		if ((rights & CAP_IOCTL) == 0) {
			tofree = fdp->fd_files[fd].fcaps.fc_ioctls;
			fdp->fd_files[fd].fcaps.fc_ioctls = NULL;
		}
		if ((rights & CAP_FCNTL) == 0)
			fdp->fd_files[fd].fcaps.fc_fcntls = 0;
	}
	spin_unlock(&fdp->fd_spin);

	if (tofree)
		ioctlsdrop(tofree);
	return (error);
}

/*
 * System call to query the rights mask associated with a capability.
 */
int
sys_cap_rights_get(struct cap_rights_get_args *uap)
{
	struct filedesc *fdp;
	cap_rights_t rights;
	struct proc *p = curproc;
	int fd;

	KKASSERT(p != NULL);

	fd = uap->fd;

	fdp = p->p_fd;
	spin_lock(&fdp->fd_spin);
	if (fdvalidate(fdp, fd)) {
		spin_lock(&fdp->fd_spin);
		return (EBADF);
	}
	rights = cap_rights(fdp, fd);
	spin_unlock(&fdp->fd_spin);
	return (copyout(&rights, uap->rightsp, sizeof(*uap->rightsp)));
}

/*
 * Test whether a capability grants the given ioctl command.
 * If descriptor doesn't have CAP_IOCTL, then ioctls list is empty and
 * ENOTCAPABLE will be returned.
 */
int
cap_ioctl_check(struct filedesc *fdp, int fd, u_long cmd, const char *func)
{
	u_long *cmds;
	struct ioctl_list *l;
	ssize_t ncmds;
	ssize_t i;

	spin_lock_shared(&fdp);

	KASSERT(fd >= 0 && fd < fdp->fd_nfiles,
		("%s: invalid fd=%d", __func__, fd));

	l =  fdp->fd_files[fd].fcaps.fc_ioctls;
	KASSERT(l != NULL,
		("%s: called from %s: ioctls list is NULL", __func__, func));
	ioctlshold(l);
	spin_unlock_shared(&fdp);

	ncmds = l->io_nioctls;
	cmds = l->io_ioctls;
	/*
	 * XXX A bisect is arithmically better, but does such a small list
	 * worth it ?
	 * Or even sorting the list
	 */
	for (i = 0; i < ncmds ; i++) {
		if (cmds[i] == cmd) {
			ioctlsdrop(l);
			return (0);
		}
	}

	ioctlsdrop(l);
	return (ENOTCAPABLE);
}

/*
 * Check if the current ioctls list can be replaced by the new one.
 */
static int
cap_ioctl_limit_check(const struct ioctls_list *ol,
			const struct ioctls_list *nl)
{
	u_long i;
	long j;
	size_t oncmd, nncmd;

	oncmd = (ol == NULL) ? 0 : ol->io_nioctls;
	nncmd = (nl == NULL) ? 0 : nl->io_nioctls;

	if (oncmd < nncmd)
		return (ENOTCAPABLE);

	for (i = 0; i < nncmd; i++) {
		for (j = 0; j < nncmd; j++) {
			if (nl->io_ioctls[i] == ol->io_ioctls[j])
				break;
		}
		if (j == oncmd)
			return (ENOTCAPABLE);
	}

	return (0);
}

MALLOC_DECLARE(M_FILECAPS);

int
sys_cap_ioctls_limit(struct cap_ioctls_limit_args *uap)
{
	struct filedesc *fdp;
	struct proc *p = curproc;
	struct ioctls_list *niolist, *oiolist;
	size_t ncmds;
	int error, fd;

	KKASSERT(p != NULL);

	fd = uap->fd;
	ncmds = uap->ncmds;

	if (ncmds > 256)	/* XXX: Is 256 sane? */
		return (EINVAL);

	if (ncmds == 0) {
		niolist = NULL;
	} else {
		niolist = ioctls_list_alloc(ncmds);
		error = copyin(uap->cmds, niolist->io_ioctls, sizeof(u_long) * ncmds);
		if (error != 0) {
			kfree(niolist, M_FILECAPS);
			return (error);
		}
		niolist->io_nioctls = ncmds;
	}

	fdp = p->p_fd;
	spin_lock_shared(&fdp->fd_spin);
	if (fdvalidate(fdp, fd)) {
		error = EBADF;
		spin_unlock_shared(&fdp->fd_spin);
		goto out;
	}

	oiolist = fdp->fd_files[fd].fcaps.fc_ioctls;
	error = cap_ioctl_limit_check(oiolist, niolist);
	if (error != 0) {
		spin_unlock_shared(&fdp->fd_spin);
		goto out;
	}

	fdp->fd_files[fd].fcaps.fc_ioctls = niolist;
	ioctlshold(niolist);
	error = 0;
	spin_unlock_shared(&fdp->fd_spin);
	ioctlsdrop(oiolist);
out:
	return (error);
}

int
sys_cap_ioctls_get(struct cap_ioctls_get_args *uap)
{
	struct filedesc *fdp;
	struct filecaps *fcaps;
	struct proc *p = curproc;
	u_long *cmds;
	size_t maxcmds;
	int error, fd;

	KKASSERT(p != NULL);

	fd = uap->fd;
	cmds = uap->cmds;
	maxcmds = uap->maxcmds;

	fdp = p->p_fd;

	spin_lock_shared(&fdp->fd_spin);
	if (fdvalidate(fdp, fd)) {
		error = EBADF;
		goto out;
	}

	/*
	 * If all ioctls are allowed (fde_nioctls == -1 && fde_ioctls == NULL)
	 * the only sane thing we can do is to not populate the given array and
	 * return CAP_IOCTLS_ALL.
	 */

	fcaps = &fdp->fd_files[fd].fcaps;
	if (cmds != NULL && fcaps->fc_ioctls != NULL) {
		error = copyout(fcaps->fc_ioctls->io_ioctls, cmds,
		    sizeof(u_long) * MIN(fcaps->fc_ioctls->io_nioctls, maxcmds));
		if (error != 0)
			goto out;
	}
	if (fcaps->fc_ioctls == NULL)
		uap->sysmsg_lresult = CAP_IOCTLS_ALL;
	else
		uap->sysmsg_lresult = fcaps->fc_ioctls->io_nioctls;

	error = 0;
out:
	spin_unlock_shared(&fdp->fd_spin);
	return (error);
}

/*
 * Test whether a capability grants the given fcntl command.
 */
int
cap_fcntl_check(struct filedesc *fdp, int fd, int cmd)
{
	uint32_t fcntlcap;

	KASSERT(fdvalidate(fdp, fd) == 0,
	    ("%s: invalid fd=%d", __func__, fd));

	fcntlcap = (1 << cmd);
	KASSERT((CAP_FCNTL_ALL & fcntlcap) != 0,
	    ("Unsupported fcntl=%d.", cmd));

	if ((fdp->fd_files[fd].fcaps.fc_fcntls & fcntlcap) != 0)
		return (0);

	return (ENOTCAPABLE);
}

int
sys_cap_fcntls_limit(struct cap_fcntls_limit_args *uap)
{
	struct filedesc *fdp;
	struct proc *p = curproc;
	uint32_t fcntlrights;
	int fd;

	fd = uap->fd;
	fcntlrights = uap->fcntlrights;

	if ((fcntlrights & ~CAP_FCNTL_ALL) != 0)
		return (EINVAL);

	fdp = p->p_fd;
	spin_lock(&fdp->fd_spin);

	if (fdvalidate(fdp, fd)) {
		spin_unlock(&fdp->fd_spin);
		return (EBADF);
	}

	if ((fcntlrights & ~fdp->fd_files[fd].fcaps.fc_fcntls) != 0) {
		spin_unlock(&fdp->fd_spin);
		return (ENOTCAPABLE);
	}

	fdp->fd_files[fd].fcaps.fc_fcntls = fcntlrights;
	spin_unlock(&fdp->fd_spin);

	return (0);
}

int
sys_cap_fcntls_get(struct cap_fcntls_get_args *uap)
{
	struct filedesc *fdp;
	struct proc *p = curproc;
	uint32_t rights;
	int fd;

	fd = uap->fd;

	fdp = p->p_fd;
	spin_lock_shared(&fdp->fd_spin);
	if (fdvalidate(fdp, fd)) {
		spin_unlock_shared(&fdp->fd_spin);
		return (EBADF);
	}
	rights = fdp->fd_files[fd].fcaps.fc_fcntls;
	spin_unlock_shared(&fdp->fd_spin);

	return (copyout(&rights, uap->fcntlrightsp, sizeof(rights)));
}

#else /* !CAPABILITIES */

/*
 * Stub Capability functions for when options CAPABILITIES isn't compiled
 * into the kernel.
 */

int
sys_cap_rights_limit(struct cap_rights_limit_args *uap)
{

	return (ENOSYS);
}

int
sys_cap_rights_get(struct cap_rights_get_args *uap)
{

	return (ENOSYS);
}

int
sys_cap_ioctls_limit(struct cap_ioctls_limit_args *uap)
{

	return (ENOSYS);
}

int
sys_cap_ioctls_get(struct cap_ioctls_get_args *uap)
{

	return (ENOSYS);
}

int
sys_cap_fcntls_limit(struct cap_fcntls_limit_args *uap)
{

	return (ENOSYS);
}

int
sys_cap_fcntls_get(struct cap_fcntls_get_args *uap)
{

	return (ENOSYS);
}

int
sys_cap_new(struct cap_new_args *uap)
{

	return (ENOSYS);
}

#endif /* CAPABILITIES */
