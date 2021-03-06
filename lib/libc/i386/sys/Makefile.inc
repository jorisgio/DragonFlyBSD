#	from: Makefile.inc,v 1.1 1993/09/03 19:04:23 jtc Exp
# $FreeBSD: src/lib/libc/i386/sys/Makefile.inc,v 1.17.2.3 2002/10/15 19:46:46 fjoe Exp $
# $DragonFly: src/lib/libc/i386/sys/Makefile.inc,v 1.8 2007/01/17 02:17:36 corecode Exp $

SRCS+=	i386_clr_watch.c i386_get_ioperm.c i386_get_ldt.c i386_set_ioperm.c \
	i386_set_ldt.c i386_set_watch.c i386_vm86.c

MDASM=	Ovfork.S brk.S cerror.S exect.S fork.S getcontext.S pipe.S ptrace.S \
	reboot.S rfork.S sbrk.S setlogin.S sigreturn.S syscall.S

# Don't generate default code for these syscalls:
NOASM=	__semctl.o break.o exit.o ftruncate.o getdomainname.o getlogin.o \
	lseek.o mmap.o msgctl.o msgget.o msgrcv.o msgsnd.o \
	openbsd_poll.o semconfig.o semget.o \
	semop.o setdomainname.o sstk.o \
	truncate.o uname.o vfork.o yield.o

PSEUDO=	_getlogin.o _exit.o

# getcontext.S needs certain offsets
#
# XXX this should be moved to a non-arch directory
SRCS+= asmcontext.h
CLEANFILES+= asmcontext.h asmcontext.o

GENASSYM= NM=nm sh ${.CURDIR}/../../sys/kern/genassym.sh
asmcontext.h: asmcontext.o
	${GENASSYM} ${.ALLSRC} > ${.TARGET}

.if ${LIB} == "c"
MAN+=	i386_get_ioperm.2 i386_get_ldt.2 i386_vm86.2
MAN+=	i386_set_watch.3

MLINKS+=i386_get_ioperm.2 i386_set_ioperm.2
MLINKS+=i386_get_ldt.2 i386_set_ldt.2
MLINKS+=i386_set_watch.3 i386_clr_watch.3
.endif
