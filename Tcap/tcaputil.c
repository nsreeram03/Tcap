/*
 *tcaputil.c --
 *
 *	This file a number of utility functions used by 
 *  Tcl Packet capture (tcap) library.
 *  Copyright (c) 2005-2006 Netprowise Consulting.
 *		 
 */
#include "tcapInt.h"
#ifndef WIN32

/*----------------------------------------------------------------------
 *
 * _itoa --
 *
 *	This function is developed for non-Windows systems.
 *  It converts a given integer to its ASCII representation
 *  That is integer 1897 is converted to string "1897"
 *  Input cannot have leading 0s, otherwise it will be treated
 *  as Octal number.
 *	Windows uses _itoa function provided by the stdlib.
 *
 *	Inputs: an integer less than or equal to 9 digits
 *          a buffer pointer to hold the result
 * Result:
 *	A buffer that contains the equivalent ASCII string
 *
 *----------------------------------------------------------------------
 */
void itoa (int val, char *buf, int len) {
	int i, digit, flag = 1, div=100000000;

	for (i=1; i <= len-1; i++) {
		digit = val/div;
		val = val - digit*div;
		div /= 10;
		if (flag) {
			if (!digit) continue;
			flag = 0;
		}	
		*buf++ = digit + 48;/* digit converted to ASCII */

	}
	if (flag) *buf++ = 48;
	*buf = '\0';
	return;

}
#endif

/*----------------------------------------------------------------------
 *
 * TcapValidateIpAddress --
 *
 *	This procedure called to validate IPv4 addresses.  An
 *	IP address is accepted as valid if and only if it consists of
 *	a string with the format [0-9]+.[0-9]+.[0-9]+.[0-9]+ where
 *	each number is in the range [0-255].
 *
 *	Note: This function currently supports only IPv4 address
 *
 * Result:
 *	A standard Tcl result. An error message is left in the Tcl
 *	interpreter if it is not NULL.
 *----------------------------------------------------------------------
 */

int  TcapValidateIpAddress(Tcl_Interp *interp, const char *address)
{
    const char *p = address;
    unsigned dots, a;
  
	for (dots = 0, a = 0; isdigit(*p) || *p == '.'; p++) {
		if (*p == '.') {
		  dots++, a = 0;
		} else {
		 a = 10 * a + *p - '0';
		}
		if (dots > 3 || a > 255) {
		 goto error;
		}
    }

    if (*p == '\0' && dots == 3) {
		return TCL_OK;
    }

 error:
    if (interp) {
		Tcl_ResetResult(interp);
    }
    return TCL_ERROR;
}
/*---------------------------------------------------------------------
 * This procedure is used to check if an IP address is local or remote
 *
 * Result:
 *   Returns 0 or 1 to the called function; 0 means ip is local,
 *   1 means ip is remote. 
 *
 *----------------------------------------------------------------------
 */
int TcapCheckIpAddress (const char *address){

   char ip[TCAP_IP4_CHAR_BUFFER];
   int i,test;
   struct hostent *phe;
   struct in_addr addr;

#ifdef WIN32
   WSADATA wsaData;
   int wsaret=WSAStartup(MAKEWORD(2,2),&wsaData);
   if(wsaret!=0)
    return 0;
#endif

   test = gethostname(ip, TCAP_IP4_CHAR_BUFFER);
   if (test == 0){
       phe = gethostbyname(ip);
   	   for ( i = 0; phe->h_addr_list[i] != 0; i++){
		   memcpy(&addr, phe->h_addr_list[i], sizeof(struct in_addr));
		   strcpy(ip,(char *)inet_ntoa(addr));
		   if(!(strcmp(ip,address)))  return 0;
		   }
	   }
   return 1;
}
/*----------------------------------------------------------------------
 * TcapWrongNumArgs -
 *
 *	This function is used to report number of parameters mis-match
 *
 * Result:
 *	A standard Tcl result. An error message is left in the Tcl
 *	interpreter if it is not NULL.
 *
 *----------------------------------------------------------------------
 */

void TcapWrongNumArgs (Tcl_Interp *interp, int argc, const char **argv, char *message)
{
    int i;

    if (argc == 0) {
		Tcl_SetResult(interp, "wrong # args", TCL_STATIC);
		return;
    }

    Tcl_AppendResult(interp,  "wrong # args: should be \"", argv[0],
		     (char *) NULL);
    for (i = 1; i < argc; i++) {
		Tcl_AppendResult(interp, " ", argv[i], (char *) NULL);
    }
    if (message) {
		Tcl_AppendResult(interp, " ", message, (char *) NULL);
    }
    Tcl_AppendResult(interp, "\"", (char *) NULL);
}

/*----------------------------------------------------------------------
 *
 * TcapBadOption -
 *
 *	This procedure is used to report wrong options
 *
 * Result:
 *	A standard Tcl result. An error message is left in the Tcl
 *	interpreter if it is not NULL.
 *----------------------------------------------------------------------
 */
void TcapBadOption (Tcl_Interp *interp, char *option, char *message)
{
    if (! option) {
		Tcl_SetResult(interp, "bad option", TCL_STATIC);
		return;
    }

    Tcl_AppendResult(interp, "bad option \"", option, "\"", (char *) NULL);
    if (message) {
		Tcl_AppendResult(interp, ": should be ", message, (char *) NULL);
    }
}

/*----------------------------------------------------------------------
 * iptos -
 *
 *	This procedure converts an IPv4 address to its ASCII form.
 *
 * Input:
 *	IP v4 number as unsigned integer
 * Result:
 *	The result is IP number in dotted decimal printable form.
 *
 *----------------------------------------------------------------------
 */
char *iptos(unsigned int in)
{
	static char output[IPTOSBUFFERS][3*4+3+1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
	socklen_t sockaddrlen;
	sockaddrlen = sizeof(struct sockaddr_in6);

	if(getnameinfo(sockaddr, 
		sockaddrlen, 
		address, 
		addrlen, 
		NULL, 
		0, 
		2) != 0) address = NULL;

	return address;
}
/*----------------------------------------------------------------------
 *
 * TcapDecStr2Oct -
 *
 *	This procedure prepares the given decimal string of the following form
 *  to Byte stream by removing the intermediate blanks and converting ASCII
 *  characters to decimal value.
 *  Input looks like this: "255 255 255 255 255 255 0 128 250 14 20 ..."
 *
 *  Input: Packet in ASCII form, where each byte value is seperated by space
 *	Result: Equivalent Byte buffer, returns the number of bytes,
 *          and the pointer to the byte buffer.
 *
 *----------------------------------------------------------------------
 */
int TcapDecStr2Oct(const char *s, char *d)
{
    int		 i=0, n=0;
    char	 hex[4];

    while (*s ) {
		hex[i] = *s;
		if (*s++ == ' ') {
			if (i) {
				hex[i] = '\0';
				*d++ = atoi(hex); n++;
			}	
			i = 0;
			continue;
		}
		i++;
	}

	if (i)  {
		*d++ = atoi(hex); n++;
	}
	return n;
}

/*----------------------------------------------------------------------
 *
 * TcapHexStr2Oct -
 *
 *	This procedure prepares the given hexadecimal string of the given form
 *  to Octet stream by removing the intermediate blanks and converting ASCII
 *  hexa characters to decimal value.
 *  Input looks like this: "ff ff ff ff ff ff 00 80 fa 0e 14 ..."
 *
 *  Input:  Packet in hexa ASCII form where each byte value is 
 *          seperated by a blank
 *	Result: Equivalent byte(octet) stream, returns the number of bytes 
 *          and the pointer to the byte stream
 *  Limits: each input digit
 *
 *----------------------------------------------------------------------
 */
int TcapHexStr2Oct(const char *s, char *d)
{
    int		 msd=1, n=0;
    u_char	result=0;	 

    while (*s ) {
		switch (*s) {
			case 32: //blank
				if (!msd) {  
					msd = 1; d[n++] = result; result = 0;
				} 
				break;
			
			case 102:/* ASCII F or f */
			case 70:
				if (msd) {  /* most significant digit */
				   result = 0xf; msd = 0;
				} else {    /* least significant digit */
				   result <<= 4; result += 0xf; msd = 1; 
				   d[n++] = result;result = 0;
				}
				break;

			case 101: /* ASCII E or e */
			case 69:
				if (msd) {
				   result = 0xe; msd = 0;
				} else {
				   result <<= 4; result += 0xe; msd = 1; 
				   d[n++] = result;result = 0;
				}
				break;

			case 100: /* you get the idea! */
			case 68:
				if (msd) {
				   result = 0xd; msd = 0;
				} else {
				   result <<= 4; result += 0xd; msd = 1; 
				   d[n++] = result;result = 0;
				}
				break;

			case 99:
			case 67:
				if (msd) {
				   result = 0xc; msd = 0;
				} else {
				   result <<= 4; result += 0xc; msd = 1; 
				   d[n++] = result;result = 0;
				}
				break;

			case 98:
			case 66:
				if (msd) {
				   result = 0xb; msd = 0;
				} else {
				   result <<= 4; result += 0xb; msd = 1; 
				   d[n++] = result;result = 0;	
				}
				break;

			case 97:
			case 65:
				if (msd) {
				   result = 0xa; msd = 0;
				} else {
				   result <<= 4; result += 0xa; msd = 1; 
				   d[n++] = result;result = 0;	
				}
				break;

			default: /* one of the decimal (0-9) digits */
				if ( (*s > 47) && (*s < 58) ) { 
					if (!msd) {
						result <<= 4; result += *s-48; msd = 1;  /* ascii -> int */ 
						d[n++] = result;result = 0;
					} else {
						result = *s-48; msd = 0;
					}
				} else if (msd) {
					return -1;
				}
				break;
		}
		*s++;
	}
	if (!msd) { /* the last number is a single digit and no trailing blanks */
		d[n++] = result;
	}
	d[n] = '\0';
	return n;
}
/*----------------------------------------------------------------------
 *
 * TcapGetTableKey -
 *
 *	This procedure find the entry index in a table for the 
 *  specified value
 *
 * Input:
 *	A Table and an entry value
 * Result:
 *	Row number where the value is found or -1
 *----------------------------------------------------------------------
 */
int TcapGetTableKey	(TcapTable *table, const char *value) 
{
    TcapTable *elemPtr;
	
	if (strcmp (value,"?")==0) {
		  if (table) {
			for (elemPtr = table; elemPtr->value; elemPtr++) {
			if  (value[0] == elemPtr->value[0]) 
				 {
					return elemPtr->key;
				 }
				}
			  }  
	} else {
		 if (table) {
		for (elemPtr = table; elemPtr->value; elemPtr++) {
		  if  ( (value[0] == elemPtr->value[0]) && 
				(value[1] == elemPtr->value[1]) &&
				(value[2] == elemPtr->value[2])) {
					return elemPtr->key;
		  }
		}
	  }  
	}
    return -1;
}

/*----------------------------------------------------------------------
 *
 * TcapCreateHndlList -
 *
 *	This procedure creates a Tcl list with the specified Handle 
 *  attributes.
 *
 * Input:
 *	Tcl Interpretter and Handle Number
 * Result:
 *	Handle attributes appended to result (Tcl interpretter)
 *----------------------------------------------------------------------
 */
void TcapCreateHndlList (Tcl_Interp *interp, int hndl){
	
//	u_char i;
	char buf[16];

	//i = tcapHndlTbl[hndl].tcapIfNum;

	if (tcapHndlTbl[hndl].tcapHndlType == TCAP_FILE) 
		Tcl_AppendResult(interp, TCAP_FILE_STR, (char *)NULL);
	else if (tcapHndlTbl[hndl].tcapHndlType == TCAP_NET_INTERFACE) 
		Tcl_AppendResult(interp, TCAP_NET_INTERFACE_STR, (char *)NULL);
	else if (tcapHndlTbl[hndl].tcapHndlType == TCAP_RMT_INTERFACE) 
		Tcl_AppendResult(interp, TCAP_RMT_INTERFACE_STR, (char *)NULL);
	
	_itoa (tcapHndlTbl[hndl].tcapSnapLen                                                        ,  buf,10);

	Tcl_AppendResult(interp, buf, " ", (char *)NULL);

	_itoa (tcapHndlTbl[hndl].tcapRdTimeOut, buf,10);
	Tcl_AppendResult(interp, buf, " ", (char *)NULL);

	if (tcapHndlTbl[hndl].tcapCaptureMode == 1) 
		Tcl_AppendResult(interp, "y", " ", (char *)NULL);
	else 
		Tcl_AppendResult(interp, "n", " ", (char *)NULL);

	if (tcapHndlTbl[hndl].tcapDispFormat == TCAP_DECIMAL) 
		Tcl_AppendResult(interp, TCAP_DECIMAL_FORMAT, (char *)NULL);
	else 
		Tcl_AppendResult(interp, TCAP_HEXDECIMAL_FORMAT, (char *)NULL);

	_itoa (tcapHndlTbl[hndl].tcapFrameCount, buf,10);
	Tcl_AppendResult(interp, buf, " ", (char *)NULL);

	Tcl_AppendResult(interp, "{", (char *)tcapHndlTbl[hndl].tcapDisplayFilter, 
		                     "} ", (char *)NULL);

	if (tcapHndlTbl[hndl].tcapCallbackFun )
		Tcl_AppendResult(interp,"{", (char *)tcapHndlTbl[hndl].tcapCallbackFun, 
							"} ", (char *)NULL);
	else
		Tcl_AppendResult(interp,"{} ",  (char *)NULL);

	Tcl_AppendResult(interp, "{", (char *)tcapHndlTbl[hndl].tcapOutputFile, 
		                     "} ", (char *)NULL);
	if (tcapHndlTbl[hndl].tcapHndlType == TCAP_FILE) 
	    Tcl_AppendResult(interp, "{", (char *)tcapHndlTbl[hndl].tcapInputFile, 
		                     "} ", (char *)NULL);
	// call create IF list
	//if (tcapHndlTbl[hndl].tcapHndlType == TCAP_NET_INTERFACE) {
		Tcl_AppendResult(interp,"{",tcapHndlTbl[hndl].tcapIfID,"} ",(char *)NULL);
                if(tcapHndlTbl[hndl].tcapIfDescription[0]!= '\0')
		Tcl_AppendResult(interp,"{",tcapHndlTbl[hndl].tcapIfDescription ,"} ",(char *)NULL);
                Tcl_AppendResult(interp,"{",tcapHndlTbl[hndl].tcapIfIpAddress ,"} ",(char *)NULL);
		Tcl_AppendResult(interp,"{",tcapHndlTbl[hndl].tcapIfIpMask ,"} ",(char *)NULL);

		//new ones
		_itoa (tcapHndlTbl[hndl].tcapSampleMethod, buf,10);
		Tcl_AppendResult(interp, buf, " ", (char *)NULL);
		_itoa (tcapHndlTbl[hndl].tcapSampleValue, buf,10);
		Tcl_AppendResult(interp, buf, " ", (char *)NULL);
		_itoa (tcapHndlTbl[hndl].tcapIfNumber, buf,10);
		Tcl_AppendResult(interp, buf, " ", (char *)NULL);

	//}
	//if (tcapHndlTbl[hndl].tcapHndlType == TCAP_RMT_INTERFACE) {
		Tcl_AppendResult(interp,"{",tcapHndlTbl[hndl].tcapRemoteHost ,"} ",(char *)NULL);
        _itoa (tcapHndlTbl[hndl].tcapRemotePort, buf,10);
		Tcl_AppendResult(interp, buf, " ", (char *)NULL);
	//}
}

/*----------------------------------------------------------------------
 *
 * TcapHndlInit -
 *
 *	This procedure initializes the handle table
 *
 * Input:
 *	 
 * Result:
 *	initialized handle table
 *----------------------------------------------------------------------
 */
u_char TcapHndlInit () {
  int i;

  for (i = 0; i < TCAP_HNDL_TABLE_SIZE; i++) {
		TcapHndlInitEntry (i);
  }		

  return TCL_OK;
}

u_char TcapHndlInitEntry (int i) {

	  tcapHndlTbl[i].tcaphandno           = '\0';
	  tcapHndlTbl[i].tcapIfIpAddress[0]   = '\0';
	  tcapHndlTbl[i].tcapIfIpAddress6[0]  = '\0';
	  tcapHndlTbl[i].tcapIfID[0]          = '\0';
	  tcapHndlTbl[i].tcapIfDescription[0] = '\0';
	  tcapHndlTbl[i].tcapIfIpMask[0]      = '\0';
      tcapHndlTbl[i].tcapHndlType         = TCAP_NET_INTERFACE;
	  tcapHndlTbl[i].tcapPcapHndl         = '\0';
	  tcapHndlTbl[i].tcapStatusFlag       = 0;
	  tcapHndlTbl[i].tcapSnapLen          = TCAP_MAX_PACKET_SIZE; 
      tcapHndlTbl[i].tcapCallbackFun      = Tcl_Alloc(1024);
	  tcapHndlTbl[i].tcapDisplayFilter[0] = '\0';
	  tcapHndlTbl[i].tcapInputFile[0]     = '\0';
	  tcapHndlTbl[i].tcapOutputFile[0]    = '\0';
	  tcapHndlTbl[i].tcapCaptureMode	  = TCAP_OPENFLAG_PROMISCUOUS;
	  tcapHndlTbl[i].tcapRdTimeOut        = TCAP_DEFAULT_READ_TIMEOUT;
	  tcapHndlTbl[i].tcapDispFormat       = 0;
	  tcapHndlTbl[i].tcapFrameCount       = 0;
	  //new ones
	  tcapHndlTbl[i].tcapIfNumber		= 0;
	  tcapHndlTbl[i].tcapSampleMethod	= 0;
	  tcapHndlTbl[i].tcapSampleValue	= 0;

	  tcapHndlTbl[i].tcapRemoteHost[0]	= '\0'; 
	  tcapHndlTbl[i].tcapRemotePort		= 0;

	  return TCL_OK;
}
/*----------------------------------------------------------------------
 *
 * TcapCheckHndl -
 *
 *	This procedure validates a given handle
 *
 * Input:
 *	handle (e.g. tcap5) 
 * Result:
 *	Row number of the handle number where handle info is saved or -1
 *----------------------------------------------------------------------
 */
int  TcapCheckHndl (const char *inhndl) {

	int  i, len1,len2;
	char prefix[16];

	// check if handle length is <=  4 (t c a p + digits) -bug fixed
	if ((strlen(inhndl)) <= (strlen(TCAP_HNDL_PREFIX))) return -1;

	//extract the suffix part of the handle - the number part
	len1 = strlen(TCAP_HNDL_PREFIX);
	for (i = 0; i < len1 ; i++) {prefix[i] = inhndl[i];}
	prefix[i] = '\0';
    //check if the handle prefix is "tcap"
	if  (strcmp(prefix, TCAP_HNDL_PREFIX)) {  return -1;}

	//extract and convert the number part from the given handle
	len2 = strlen(inhndl);
	for (i = len1; i < len2; i++) {prefix[i-len1] = inhndl[i];}
	prefix[i-len1] = '\0';
    
	i = atoi(prefix);
	//check if the handle is a valid one
	if ((i >= 0) && (i <= TCAP_HNDL_TABLE_SIZE)) {
		if (tcapHndlTbl[i].tcapStatusFlag != 0) 
				return i;
	}

	return -1;

}

/*----------------------------------------------------------------------
 *
 * TcapHandleCmd-
 *
 * This procedure implements tcap handle command
 * when "tcap info" command is invoked without any handle,
 * this function lists all the live handles  
 *
 * Result:
 *	A standard Tcl result. An error message is left in the Tcl
 *	interpreter if it is not NULL.
 *----------------------------------------------------------------------
 */
int TcapHandleCmd(Tcl_Interp *interp,int argc, const char *argv[]){

	u_char  i;
	char hndlId[3];
	
	if (argc != 2) {	
		TcapWrongNumArgs(interp, 2, argv, " <handle>");	
		return TCL_ERROR;
	}
	Tcl_AppendResult(interp, "", (char *)NULL);
	for (i = 0; i < TCAP_HNDL_TABLE_SIZE; i++) {
		
		if (tcapHndlTbl[i].tcapStatusFlag != 0) {
			sprintf((char *)hndlId, "%d",  i);
			Tcl_AppendResult(interp, TCAP_HNDL_PREFIX, (char *)hndlId, " ", (char *)NULL);	;
		}
		
	}
	Tcl_AppendResult(interp, "",  (char *)NULL);

	return TCL_OK;
}

 
// The main function that checks if two given strings match. The first
// string may contain wildcard characters
// This code is copied from Internet - http://www.geeksforgeeks.org/wildcard-character-matching
int match(char *first, char * second)
{
    // If we reach at the end of both strings, we are done
    if (*first == '\0' && *second == '\0')
        return 1;
 
    // Make sure that the characters after '*' are present in second string.
    // This function assumes that the first string will not contain two
    // consecutive '*' 
    if (*first == '*' && *(first+1) != '\0' && *second == '\0')
        return 0;
 
    // If the first string contains '?', or current characters of both 
    // strings match
    if (*first == '?' || *first == *second)
        return match(first+1, second+1);
 
    // If there is *, then there are two possibilities
    // a) We consider current character of second string
    // b) We ignore current character of second string.
    if (*first == '*')
        return match(first+1, second) || match(first, second+1);
    return 0;
}

pcap_if_t * matchInterface(pcap_if_t *alldevs, int keytype, char *key ) 
{
	pcap_if_t		*d;
	pcap_addr_t		*a;
	int				foundmatch = 0;
	int				i;
	char			ip6str[128];
	
	i = 1; foundmatch = 0;
	for(d=alldevs; d; d=d->next) {
		if ((keytype == DEVID_MATCH) && (!strcmp(key, d->name))){
			foundmatch = 1; return d;
		}
		if ((keytype == IFNUM_MATCH) && (i == atoi(key))){
			foundmatch = 1; return d;
		}
		i++;
		for(a=d->addresses;a;a=a->next) {
		   switch(a->addr->sa_family){
				case AF_INET:
					if (a->addr) {
						if ((keytype == IP4_MATCH) && (!strcmp(key, 
							iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr)))) 
								foundmatch = 2;
					} 
					break; 
			    case AF_INET6:
				    if (a->addr) {
						if ((keytype == IP6_MATCH) && (!strcmp(key, 
							ip6tos(a->addr, ip6str, sizeof(ip6str)))))
								foundmatch = 3;
					}
				    break;
			}
		    if (foundmatch) break;
		}
		if (foundmatch) break;
	}
	if (foundmatch) return d;
	else return NULL;
}
