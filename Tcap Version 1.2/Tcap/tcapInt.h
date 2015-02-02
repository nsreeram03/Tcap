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
 *  Open with ifnumber and IPv6

 *  Changes to be ported to new TCAP
	1. define _CRT_SECURE_NO_WARNINGS
	2. itoa to _itoa
	3. remove some unused variable
	4. Get rid off all the warnings
	5. Add _USE_TCL_STUB to Project Settings under Preprocessor Defn.
	6. NO WILDCARD SUPPORT - LET TCL SCRIPT DO THAT!

	Tasks for Sree Ram:
		1. Help message
		2. Arranging things alphabetically, options, commands, functions, and 
		   whereever possible
		3. API documentation is needed - output requires description
		4. Some Use cases or reference development needed
		5. Description of the structures should also be made in API
		6. Free alldevices - check
		7. Use errbuf value on PCAP errors
		8. Unify two IP addresses in structure?
		9. match against either of the IP address for remote

Bugs Fixed
1. close tcap was closing tcap0, due to bug in TcapCheckHndl function
2. Version command was returning non-list results due to missing space after Tcap
3. Info command also had similar problem - incorrect list structure
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
#define TCAP_BUF_SIZE_3000          3000
#define TCAP_HNDL_TABLE_SIZE		11
#define TCAP_CB_FUNCTION_SIZE		8192
#define TCAP_FILTER_SIZE			512
#define TCAP_MAX_PACKET_SIZE		65535
#define TCAP_DEFAULT_READ_TIMEOUT	2000  //2 seconds
#define TCAP_HNDL_PREFIX			"tcap" //less than 8 chars
#define TCAP_DUMP_FILE_SUFFIX		"DumpFile"
#define TCAP_DECIMAL_FORMAT			"decimal "
#define TCAP_HEXDECIMAL_FORMAT		"hexadecimal "
#define TCAP_DECIMAL				1
#define TCAP_HEXADECIMAL			0
#define TCAP_FILE					1
#define TCAP_NET_INTERFACE			2
#define TCAP_RMT_INTERFACE			3
#define TCAP_FILE_STR				"1 "
#define TCAP_NET_INTERFACE_STR		"2 "
#define TCAP_RMT_INTERFACE_STR		"3 "
#define TCAP_OPENFLAG_PROMISCUOUS	1
#define TCAP_IP4_CHAR_BUFFER		16
#define TCAP_REMOTE_PORT			"2002"
#define TCAP_LIB_VERSION_SIZE		26

// Match found in devlist 
#define NO_MATCH_FOUND				0
#define DEVLIST_UNAVAILABLE			1
#define IP4_MATCH					2
#define IP6_MATCH					3
#define IP_MATCH					4
#define DEVID_MATCH					5
#define	IFNUM_MATCH					6

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
#define TCAP_INVALID_OPTION		 "unknown or incomplete option "
#define TCAP_FIND_DEV_FAILED	 "check your input, specified host/interface not found"
#define TCAP_INVALID_IPVALUE	 "incorrect IP address "
#define TCAP_NO_CALLBACK		 "loop requires the specification of a callback function"
#define TCAP_UNABLE_TO_COMPILE	 "unable to compile the packet filter. Check the syntax"
#define TCAP_ERROR_BIND_FILTER	 "error binding the filter"
#define TCAP_GET_HELP			 "Invalid Option-type <tcap -h> for command line syntax!"
#define TCAP_VALID_SEND_OPTIONS	 "handle <pktstr>"
#define TCAP_FILE_OPEN_FAILED    "error opening file "
#define TCAP_CAPTURE_TIMEOUT	 "capture timedout "
#define TCAP_NO_STATSFORFILE	 "no stats for file type"
#define TCAP_FAILED_TO_OPEN		 "output file failed to open"
#define TCAP_LOOP_FAILED		 "failed - interface disabled or stale handle"
#define TCAP_INVALID_IFSPEC		 "invalid interface, check validity of - "
#define TCAP_INVALID_IFID		 "unknown interface ID "
#define TCAP_INVALID_ARGUMENT    "invalid number of arguments "
#define TCAP_DUMP_FILE           "dump file not found "
#define TCAP_OPEN_ERROR			 "unable open the interface"
#define TCAP_INCORRECT_SPEC		 "error in specification"
#define TCAP_INVALID_PORT		 "remote port not in valid range "


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
#define TCAP_SENDING_SUCCESSFUL		"packet send succesfull"


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
	        char	        tcapIfIpAddress [16];   //v4
			char	        tcapIfIpAddress6 [128]; //v6
			char	        tcapIfID [128]; //same as device ID	
			int				tcapIfNumber;
			char	        tcapRemoteHost[64]; 
			unsigned short	tcapRemotePort;
			char	        tcapIfIpMask [16];
			char	        tcapIfDescription [128];
		    u_char	        tcapHndlType;
			unsigned int    tcapSnapLen                                                        ;
			unsigned int  	tcapRdTimeOut;
			pcap_t			*tcapPcapHndl; //winpcap or libpcap handle
			pcap_dumper_t   *tcapDumpfile;
			u_char	        tcapStatusFlag;	
			u_char	        tcapCaptureMode;
			u_char	        tcapDispFormat;
			int		        tcapFrameCount;
			char	        tcapDisplayFilter[1024];
			char	        tcapOutputFile[1024];
			char	        *tcapCallbackFun;	
			char	        tcapInputFile[1024];
			int				tcapSampleMethod;
			int				tcapSampleValue;
			#ifndef WIN32
			libnet_t        *libDHndl;      //libnet handle
			#endif
};

struct TcapHndl tcapHndlTbl[TCAP_HNDL_TABLE_SIZE];

enum commands {
				cmdList, cmdOpen, cmdClose, cmdInfo,cmdLink, cmdType,
				cmdSet, cmdCapture, cmdSend, cmdSQueue, cmdLoop, cmdStats,
				cmdHandle, cmdVersion,  cmdH, cmdHelp, cmdHelp1, cmdReset,
				cmdShow
			  };

static TcapTable tcapCmdTable[] = {
		{ cmdList,		"list"		},
		{ cmdOpen,		"open"		},
		{ cmdClose,		"close"		},
		{ cmdInfo,		"info"		},
		{ cmdInfo,		"show"		},
		{ cmdSet,		"set"		},
		{ cmdCapture,	"capture"	},
		{ cmdSend,		"send"		},
		{ cmdSQueue,    "squeue"    },
		{ cmdLoop,		"loop"		},
		{ cmdStats,		"stats"		},
		{ cmdHandle,	"handle"	},
		{ cmdVersion,	"version"	},
		{ cmdH,			"?"			},
		{ cmdHelp,		"help"		},
		{ cmdHelp1,		"-help"		},
		{ cmdReset,		"reset"		},
		{ cmdLink,		"link"		},
		{ cmdType,		"type"		},
		{ 0,			 NULL		}
    };

enum options {
				optRemoteHostIp, optPromiscuous,optSnapLen, optFilter,	 
			    optInFile, optIfId, optTimeout, 
				optCallback, optOutFile, optCount, optOutputFormat,
				optRemotePort, optSampleMethod, 
				optSampleValue, optIpAddress,optIfNumber, 
				optIpAddress6,
			};


static TcapTable tcapOptionTable[] = {
	    { optRemoteHostIp,  "-ho"  },
		{ optRemotePort,	"-po"	},
		{ optPromiscuous,	"-pr"	},
		{ optIfId,          "-id"   },
		{ optSnapLen,		"-sn"	},
		{ optFilter,		"-fi"	},
		{ optIpAddress,		"-ip"	},	
		{ optIpAddress6,	"-i6"	},	
		{ optInFile,		"-in"   },
		{ optTimeout,		"-ti"	},
		{ optCallback,		"-ca"	},
		{ optOutFile,		"-ou"	},
		{ optCount	,		"-co"	},
		{ optOutputFormat,	"-fo"	},		
		{ optSampleMethod,	"-sm"	},
		{ optSampleValue,	"-sv"	},
		{ optIfNumber,		"-if"	},
		{ 0,				 NULL	},
    };

#define ckstrdup(s)	strcpy(ckalloc(strlen(s)+1), s)

// functions:
int      TcapCheckIpAddress     (CONST84 char *address); 
int      TcapValidateIpAddress	(Tcl_Interp *interp, const char *address);
void     TcapWrongNumArgs		(Tcl_Interp *interp, int argc, const char **argv, char *message);
void     TcapBadOption			(Tcl_Interp *interp, char *option, char *message);
int      TcapDecStr2Oct		    (const char *s, char *d); 
int      TcapHexStr2Oct		    (const char *s, char *d);
void     TcapCreateIfList		(Tcl_Interp *interp, int ifNum);
void     TcapCreateHndlList	    (Tcl_Interp *interp, int hndl);
int      TcapGetTableKey	    (TcapTable *table, const char *value);
u_char   TcapHndlInit	        ();
u_char	 TcapHndlInitEntry		(int i);
int	     TcapCheckHndl	        (const char *inhndl);
int		 TcapIfInit             (Tcl_Interp* interp);
int		 TcapBindFilter         (Tcl_Interp *interp, u_char hndl); 
int	     TcapHandleCmd	        (Tcl_Interp *interp,int argc, const char *argv[]);
void	 Tcap_PH                (u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
char	 TcapIfTable            (Tcl_Interp *interp,const char *address,const char *IfId);
int		 TcapBindFilter         (Tcl_Interp *interp, u_char hndl);

static int TcapOpenFile(Tcl_Interp *interp,int argc, const char *argv[]) ;
static int TcapOpenInterface(Tcl_Interp *interp,int argc, const char *argv[]) ;
static int TcapOpenRmtInterface(Tcl_Interp *interp,int argc, const char *argv[]);
int match(char *first, char * second);


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

