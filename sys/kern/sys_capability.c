#include "opt_capsicum.h"

#include <sys/capability.h>
#include <sys/file.h>
#include <sys/filedesc.h>

#ifdef CAPABILITIES
enum ktr_cap_fail_type { CAPFAIL_NOTCAPABLE = 1 } ;

#define ENOTCAPABLE 22

static inline int
_cap_check(cap_rights_t have, cap_rights_t need, enum ktr_cap_fail_type unused __unused)
{

  if ((need & ~have) != 0) {
#if 0
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

  return (_cap_check(have, need, CAPFAIL_NOTCAPABLE));
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
 * Test whether a capability grants the given fcntl command.
 */
int
cap_fcntl_check(struct filedesc *fdp, int fd, int cmd)
{
  uint32_t fcntlcap;

  KASSERT(fd >= 0 && fd < fdp->fd_nfiles,
      ("%s: invalid fd=%d", __func__, fd));

  fcntlcap = (1 << cmd);
  KASSERT((CAP_FCNTL_ALL & fcntlcap) != 0,
      ("Unsupported fcntl=%d.", cmd));

  if ((fdp->fd_files[fd].fcaps.fc_fcntls & fcntlcap) != 0)
    return (0);

  return (ENOTCAPABLE);
}
#endif /* CAPABILITIES */
