/*
 * tcapTcl.h --
 * 
 *	Common definitions for WinTcap/LibTcap Tcl extensions.
 *
 *
 * Copyright (c) 2005-2006 Netprowise Consulting
 *
 * See the file "license.terms" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

#ifndef _TCAPH
#define _TCAPH

/*
 *----------------------------------------------------------------
 * Here start the common definitions for the Tcap extension:
 *----------------------------------------------------------------
 */


#include <tcl.h>


/*
 * The support follows the convention that a macro called BUILD_xxxx, where
 * xxxx is the name of a library we are building, is set on the compile line
 * for sources that are to be placed in the library.
 */

#ifdef TCL_STORAGE_CLASS
# undef TCL_STORAGE_CLASS
#endif
#ifdef BUILD_tcap
# define TCL_STORAGE_CLASS DLLEXPORT
#else
# define TCL_STORAGE_CLASS DLLIMPORT
#endif

/*
 *----------------------------------------------------------------
 * Tcl command procedure  provided by the Tcap extension:
 *----------------------------------------------------------------
 */


int 
TcapCmd	(ClientData clientData, Tcl_Interp *interp, 
										int argc,  const char *argv[]);

#endif /* _TCAPTCL */
