/*
 * Written by J.T. Conklin <jtc@NetBSD.org>.
 * Public domain.
 *
 * $NetBSD: e_asin.S,v 1.7 2003/07/26 19:24:58 salo Exp $
 */

#include <machine/asm.h>

#include "abi.h"

/* asin = atan (x / sqrt(1 - x^2)) */
ENTRY(asin)
	XMM_ONE_ARG_DOUBLE_PROLOGUE
	fldl	ARG_DOUBLE_ONE		/* x */
	fld	%st(0)
	fmul	%st(0)			/* x^2 */
	fld1
	fsubp				/* 1 - x^2 */
	fsqrt				/* sqrt (1 - x^2) */
	fpatan
	XMM_DOUBLE_EPILOGUE
	ret
END(asin)

	.section .note.GNU-stack,"",%progbits
