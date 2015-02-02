/*
 * tcapTcl.h --
 * 
 *	Declarations of things used internally by the tcap 
 *  extension.
 *
 *
 * Copyright (c) 2005-2006 Netprowise Consulting
 *
 * See the file "license.terms" for information on usage 
 * and redistribution of this file, and for a DISCLAIMER 
 * OF ALL WARRANTIES.
 * Changes from Version 1.1 to 1.2:
 * ================================
 * 1.  Constantification! There are a number of functions
 *     where *argv need to be defined as const. Otherwise
 *     Tcl_CreateCommand will fail.  
 * 2.  Help message updated 
 * 3.  List option -sa changed to -rip
 * 4.  Help message options extended to -h and -help
 * 5.  upgraded to Tcl 8.4
 * 6.  ActiveTcl and Scotty - test
 * 7.  pcap is changed to tcap (Tcl Pcap)!!
 * 8.  Utility files are grouped into tcaputil.c
 * 9.  EOF problem fixed with offline file capture
 * 10. Whitespace and indentations cleaned to some extent
 * 11. Handle validation bug fixed - returning 0xff instead of -1
 * The above Changes are minor and made on Aug 2014
 * ================================================
 * Extensions planned:
 *	Support for V6 address (5)
 *  Tcap 64 bit version with Tcl 64 bit and Winpcap 64 bit
 *	Support for Linux, Net BSD, Free BSD (6)
 *  Support for host name instead of IP address (4)
 *  DO NOT fix the warning messages strcpy_s etc are not 
 *  supported on other platforms!
 *  Remove hardcoded remote capture port (2002 now). (3)
 *  Add an option to specify remote port in open command
 *  Replace tcap_findalldevs_ex with tcap_findalldevs (1)
 *  Code commands to support datalink extensions of winpcap (2)

 *  Changes to be ported to new TCAP
	1. define _CRT_SECURE_NO_WARNINGS
	2. itoa to _itoa
	3. remove some unused variable
	4. Get rid off all the warnings
	5. Add _USE_TCL_STUB to Project Settings under Preprocessor Defn.
 */

#define _CRT_SECURE_NO_WARNINGS 

#ifndef _TCAPI
#define _TCAPI

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#define HAVE_REMOTE


#ifdef WIN32
#include <remote-ext.h>
#include <winsock2.h>
#include <Win32-Extensions.h>
#else
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include </usr/include/libnet.h> 
#endif
 
#ifndef _TCAPH
#include "tcapTcl.h"
#endif

#define TCAP_VERSION			"1.2"
#define TCAP_VERSION_INT		1.2
#ifndef TCAP_URL
#define TCAP_URL				"http://www.netprowise.com/"
#endif

/*
 * Some constant definitions
 * 
 */
#define TCAP_SRC_LOCAL              3
#define TCAP_SRC_RMOTE              4
#define TCAP_BUF_SIZE_16			16
#define TCAP_BUF_SIZE_32			32
#define TCAP_BUF_SIZE_64			64
#define TCAP_BUF_SIZE_128			128
#define TCAP_BUF_SIZE_256			256
#define TCAP_SIZE_1024				1024
#define TCAP_BUF_SIZE_3000          3000
#define TCAP_IF_ID_LEN				256
#define TCAP_IF_DESCRIPTION_LEN		256
#define TCAP_HNDL_TABLE_SIZE		10
#define TCAP_CB_FUNCTION_SIZE		8192
#define TCAP_FILTER_SIZE			512
#define TCAP_MAX_PACKET_SIZE		65535
#define TCAP_DEFAULT_READ_TIMEOUT	10000  //10 seconds
#define TCAP_HNDL_PREFIX			"tcap" //less than 8 chars
#define TCAP_NULL_IP_ADDRS			"0.0.0.0"
#define TCAP_DUMP_FILE_SUFFIX		"DumpFile"
#define TCAP_FILE_INTERFACE			"File "
#define TCAP_NET_INTERFACE			"Interface "
#define TCAP_DECIMAL_FORMAT			"decimal "
#define TCAP_HEXDECIMAL_FORMAT		"hexadecimal "
#define TCAP_FILE					1
#define TCAP_INTERFACE				0
#define TCAP_OPENFLAG_PROMISCUOUS	1
#define TCAP_IP4_CHAR_BUFFER		16
#define TCAP_REMOTE_PORT			"2005"


/* Constants for non-Windows platforms */
#ifndef WIN32
#define TRUE						1
#define FALSE						0
//#define AF_INET						1
#endif

/*
 * IF Handle Flag
 * Indicates if a handle is in use or closed
 * 
 */
#define TCAP_IN_USE					0X01
#define TCAP_NOT_IN_USE				0X00


/*
 *  Error Message definitions
 * 
 */
#define TCAP_TOO_MANY_HANDLES	 "too many handles, limit is 10"
#define TCAP_SENDING_FAILED		 "failed to send packet"
#define TCAP_INVALID_HANDLE		 "invalid handle "
#define TCAP_SET_FAILED			 "failed to update the handle "
#define TCAP_INVALID_PACKET		 "incorrect packet specification"
#define TCAP_INVALID_OPTION		 "unknown option "
#define TCAP_FIND_DEV_FAILED	 "check your input, specified host/interface not found"
#define TCAP_INVALID_IPVALUE	 "incorrect IP address "
#define TCAP_NO_CALLBACK		 "loop requires the specification of a callback function"
#define TCAP_UNABLE_TO_COMPILE	 "unable to compile the packet filter. Check the syntax"
#define TCAP_ERROR_BIND_FILTER	 "error binding the filter"
#define TCAP_GET_HELP			 "type <tcap -h> for command line syntax!"
#define TCAP_VALID_SEND_OPTIONS	 "handle <pktstr>"
#define TCAP_FILE_OPEN_FAILED    "error opening file "
#define TCAP_CAPTURE_TIMEOUT	 "capture timedout "
#define TCAP_NO_STATSFORFILE	 "no stats for file type"
#define TCAP_FAILED_TO_OPEN		 "output file failed to open"
#define TCAP_LOOP_FAILED		 "failed - interface disabled or stale handle"
#define TCAP_INVALID_IFSPEC		 "valid interface range is 1 - 16 "
#define TCAP_INVALID_IFID		 "unknown interface ID "
#define TCAP_INVALID_ARGUMENT    "invalid number of arguments "
#define TCAP_DUMP_FILE           "dump file not found "
#define TCAP_OPEN_FILE_ERROR     "unable open the file"
#define TCAP_INCORRECT_SPEC		 "error in specification"

//The following errors less likely to be seen! But they can occur!

#define TCAP_CAPTURE_EOF		 "EOF "
#define TCAP_CAPTURE_ERROR		 "error in capturing "
#define TCAP_SEND_NOT_SUPPORTED	 "send not supported on this platform "
#define TCAP_BUFFER_WARNING      "warning: packet buffer too small, not all the packets will be sent"
#define TCAP_FILE_CORRUPTED      "corrupt input file"
#define TCAP_ERROR_OCCURRED      "an error occurred sending the packets"
#define TCAP_STRING_ERROR        "error creating source string "

 /*
 *  Informational Message definitions
 * 
 */
#define TCAP_HANDLE_REMOVED			" removed"
#define TCAP_SENDING_SUCCESSFUL		"packet sent succesfully"


/* typedef unsigned char u_char; */

/* <Key, Value> generic table */
typedef struct TcapTable {
    unsigned key;
    char	 *value;
} TcapTable;

 

/* Handle strcture - this struct defines attributes of       */
/* Tcl handle. The key is row number.                        */
/* This handle is for supporting Tcl syntax. It is different */
/* from the handle that one gets when tcap_open API is used  */
/* Tcl handle helps to retain the association between various*/
/* Tcl commands. For instance, one can open a device and     */
/* bind attributes (timeout, snaplen, mode, etc) using handle*/

struct TcapHndl {
	        int             tcaphandno;
	        char	        tcapIfIpAddress [16];   
			char	        tcapIfID [TCAP_IF_ID_LEN]; //same as device ID	
			char	        tcapIfIpMask [16];
			char	        tcapIfDescription [TCAP_IF_DESCRIPTION_LEN];
		    u_char	        tcapHndlType;
			unsigned int    tcapHndlSnapLen;
			unsigned int  	tcapHndlRdTimeout;
			pcap_t			*tcapDHndl; //winpcap or libpcap handle
			pcap_dumper_t   *tcapHndlDumpfile;
			u_char	        tcapHndlFlag;	
			u_char	        tcapHndlPromisc;
			u_char	        tcapHndlFormat;
			int		        tcapHndlFrameCount;
			char	        tcapHndlFilter[TCAP_SIZE_1024];
			char	        tcapHndlOutFile[TCAP_SIZE_1024];
			char	        *tcapHndlCallback;	
			char	        tcapHndlInFile[TCAP_SIZE_1024];
			#ifndef WIN32
			libnet_t        *libDHndl;      //libnet handle
			#endif
};

struct TcapHndl tcapHndlTbl[TCAP_HNDL_TABLE_SIZE];

enum commands {
				cmdList, cmdOpen, cmdClose, cmdInfo,
				cmdSet, cmdCapture, cmdSend, cmdSQueue, cmdLoop, cmdStats,
				cmdHandle, cmdVersion,  cmdH, cmdHelp, cmdHelp1, cmdReset,
				};

static TcapTable tcapCmdTable[] = {
		{ cmdList,		"list"		},
		{ cmdOpen,		"open"		},
		{ cmdClose,		"close"		},
		{ cmdInfo,		"info"		},
		{ cmdSet,		"set"		},
		{ cmdCapture,	"capture"	},
		{ cmdSend,		"send"		},
		{ cmdSQueue,    "squeue"    },
		{ cmdLoop,		"loop"		},
		{ cmdStats,		"stats"		},
		{ cmdHandle,	"handle"	},
		{ cmdVersion,	"version"	},
		{ cmdH,			"-h"		},
		{ cmdHelp,		"help"		},
		{ cmdHelp1,		"-help"		},
		{ cmdReset,		"reset"		},
		{ 0,			 NULL		}
    };

enum options {
				optRemoteIp, optPromiscuous,	optSnapLen, optFilter,	optIpAddress, 
			    optInFile, optDecimal, optHex, optIfId, optTimeout, 
				optCallback, optOutFile, optCount, optOutputFormat,
			};


static TcapTable tcapOptionTable[] = {
	    { optRemoteIp,      "-rip" },
		{ optPromiscuous,	"-pr"	},
		{ optIfId,          "-id"   },
		{ optSnapLen,		"-sn"	},
		{ optFilter,		"-fi"	},
		{ optIpAddress,		"-ip"	},
		{ optInFile,		"-in"   },
		{ optDecimal,		"-de"	},
		{ optHex,			"-he"	},
		{ optTimeout,		"-ti"	},
		{ optCallback,		"-ca"	},
		{ optOutFile	,	"-ou"	},
		{ optCount	,		"-co"	},
		{ optOutputFormat,	"-fo"	},
		{ 0,				 NULL	}
    };

#define ckstrdup(s)	strcpy(ckalloc(strlen(s)+1), s)

// functions:
int      TcapCheckIpAddress     (Tcl_Interp *interp, CONST84 char *address); 
int      TcapValidateIpAddress	(Tcl_Interp *interp, const char *address);
void     TcapWrongNumArgs		(Tcl_Interp *interp, int argc, const char **argv, char *message);
void     TcapBadOption			(Tcl_Interp *interp, char *option, char *message);
int      TcapDecStr2Oct		    (const char *s, char *d); 
int      TcapHexStr2Oct		    (const char *s, char *d);
void     TcapCreateIfList		(Tcl_Interp *interp, int ifNum);
void     TcapCreateHndlList	    (Tcl_Interp *interp, int hndl);
int      TcapGetTableKey	    (TcapTable *table, const char *value);
u_char   TcapHndlInit	        ();
int	     TcapCheckHndl	        (const char *inhndl);
int		 TcapIfInit             (Tcl_Interp* interp);
int		 TcapBindFilter         (Tcl_Interp *interp, u_char hndl); 
int	     TcapHandleCmd	        (Tcl_Interp *interp,int argc, const char *argv[]);
void	 Tcap_PH                (u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
char	 TcapIfTable            (Tcl_Interp *interp,const char *address,const char *IfId);
int		 TcapBindFilter         (Tcl_Interp *interp, u_char hndl);

#ifndef WIN32
void itoa (int val, char *buf, int len);
#endif

#define IPTOSBUFFERS	12
char *iptos				(unsigned int in);


/*
 * Mutex used to serialize access to static variables in this module.
 */

TCL_DECLARE_MUTEX(tcapMutex);

/* Some global variables  used to pass handle and */
/* Interpretter to callback functions             */
static u_char			globalHndl;
static Tcl_Interp		*globalInterp;

#endif /* _TCAPINT */

