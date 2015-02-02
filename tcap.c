/*
 *tcap.c 
 *
 *	This is the implementation of Tcl tcap commands 
 *	to send and capture packets.This implementation is
 *	thread-safe.
 *
 * Copyright (c) 2005-2006 Netprowise Consulting.
 *
 * See the file "license.terms" for information on usage 
 * and redistribution of this file, and for a DISCLAIMER 
 * OF ALL WARRANTIES.
 *		 
 */

/*----------------------------------------------------------------------
 *
 * TcapHelpCmd-
 *
 * This procedure implements Tcl - tcap help command
 *
 * Result:
 *	A standard Tcl result. An error message is left in the Tcl
 *	interpreter if it is not NULL.
 *----------------------------------------------------------------------
 */
#include "tcapInt.h"

static int TcapHelpCmd(Tcl_Interp *interp,int argc, const char *argv[]){

	Tcl_AppendResult(interp,  " ", (char *)NULL);
	Tcl_AppendResult(interp,  "		tcap commands \n", (char *)NULL);
	Tcl_AppendResult(interp,  "		============= \n", (char *)NULL);
	Tcl_AppendResult(interp,  "	tcap help 	help command\n\n", (char *)NULL);
	Tcl_AppendResult(interp,  "	tcap list [-rip <remote IP>]\n", (char *)NULL);
	Tcl_AppendResult(interp,  "	  Lists interfaces on the specified (IP) host\n", (char *)NULL);
	Tcl_AppendResult(interp,  "	  If -rip option is not present, local interfaces are listed\n\n", (char *)NULL);
	Tcl_AppendResult(interp,  "	tcap open -ip <ip-address>\n", (char *)NULL);
	Tcl_AppendResult(interp,  "	tcap open -ip <ip-address> [-rport <portnum>] [-id <interface-id>]\n", (char *)NULL);
	Tcl_AppendResult(interp,  "	tcap open -infile <filename> \n", (char *)NULL);
	Tcl_AppendResult(interp,  "	  Opens an interface for capture, loop, stats, & send commands\n", (char *)NULL);
	Tcl_AppendResult(interp,  "	  The open with ip & id combination is used in remote capture\n", (char *)NULL);
	Tcl_AppendResult(interp,  "	  The open with infile is used to capture from a file\n\n", (char *)NULL);
	Tcl_AppendResult(interp,  "	tcap info [<handle>] \n", (char *)NULL);
	Tcl_AppendResult(interp,  "	  lists handles or handle data\n\n", (char *)NULL);
	Tcl_AppendResult(interp,  "	tcap capture <handle> \n", (char *)NULL);
	Tcl_AppendResult(interp,  "	  captures a single packet\n\n", (char *)NULL);
	Tcl_AppendResult(interp,  "	tcap loop <handle> \n", (char *)NULL);
	Tcl_AppendResult(interp,  "	  keeps capturing packets using a callback\n\n", (char *)NULL);
	Tcl_AppendResult(interp,  "	tcap stats <handle> \n", (char *)NULL);
	Tcl_AppendResult(interp,  "	  reports stats of captured frame\n\n", (char *)NULL);
	Tcl_AppendResult(interp,  "	tcap close <handle> \n", (char *)NULL);
	Tcl_AppendResult(interp,  "	  closes the specified handle\n\n", (char *)NULL);
	Tcl_AppendResult(interp,  "	tcap version\n", (char *)NULL);
	Tcl_AppendResult(interp,  "	  lists tcap version and more\n\n", (char *)NULL);
	Tcl_AppendResult(interp,  "	tcap send <handle> <pktdata> \n", (char *)NULL);
	Tcl_AppendResult(interp,  "	  sends a packet using given handle\n\n", (char *)NULL);
	Tcl_AppendResult(interp,  "	tcap set <handle> -snaplen <sl>    -promiscuous <y|n>\n", (char *)NULL);
	Tcl_AppendResult(interp,  "		          -filter  <fspec> -callback <cbspec>\n", (char *)NULL);
	Tcl_AppendResult(interp,  "		          -timeout <to>    -count <pktcount> \n", (char *)NULL);
	Tcl_AppendResult(interp,  "		          -outfile <filename>  -format <hex|decimal>\n", (char *)NULL);
	Tcl_AppendResult(interp,  "	  updates the handle configuration\n\n", (char *)NULL);
	Tcl_AppendResult(interp,  "	tcap squeue <handle> <dump filename>\n ", (char *)NULL);
	return TCL_OK;
}

/*----------------------------------------------------------------------
 *
 * TcapInfoCmd-
 *
 * This procedure implements tcap info command
 *
 * Result:
 *	A standard Tcl result. An error message is left in the Tcl
 *	interpreter if it is not NULL.
 *----------------------------------------------------------------------
 */
static int TcapInfoCmd(Tcl_Interp *interp,int argc, const char *argv[]){

	int  hndl;

	if(argc == 2)
		return (TcapHandleCmd(interp,argc,argv));
	else 
	if (argc != 3) {	
		TcapWrongNumArgs(interp, 2, argv, " [<handle>]");	
		return TCL_ERROR;
	}
	
	hndl = TcapCheckHndl(argv[2]);
	if ( hndl == -1 ) {
		Tcl_AppendResult(interp, TCAP_INVALID_HANDLE, argv[2], (char *)NULL);	
		return TCL_ERROR;
	}

	//printf ("Handle Value %d\n", hndl);
	if (tcapHndlTbl[hndl].tcapHndlFlag > 0) 	
			TcapCreateHndlList (interp, hndl); 
	
	return TCL_OK;
}

/*----------------------------------------------------------------------
 * TcapCloseCmd-
 *
 * This procedure implements tcap close command
 * Removes/closes a tcap handle
 *
 * Result:
 *	A standard Tcl result. An error message is left in the Tcl
 *	interpreter if it is not NULL.
 *----------------------------------------------------------------------
 */
static int TcapCloseCmd(Tcl_Interp *interp,int argc, const char *argv[]){

	int  hndl;
	
	if (argc != 3) {	
		TcapWrongNumArgs(interp, 2, argv, " <handle>");	
		return TCL_ERROR;
	}

	hndl = TcapCheckHndl(argv[2]);
	if ( hndl == -1 )  {
		Tcl_AppendResult(interp, TCAP_INVALID_HANDLE, argv[2], (char *)NULL);	
		return TCL_ERROR;
	}

	if (tcapHndlTbl[hndl].tcapHndlFlag   > 0) {
		if (tcapHndlTbl[hndl].tcapHndlDumpfile)
			pcap_dump_close(tcapHndlTbl[hndl].tcapHndlDumpfile);
		pcap_close  (tcapHndlTbl[hndl].tcapDHndl);

		Tcl_MutexLock(&tcapMutex);
        tcapHndlTbl[hndl].tcapHndlFlag = 0;
		tcapHndlTbl[hndl].tcapDHndl = '\0';
        tcapHndlTbl[hndl].tcapIfID[0]='\0';
		tcapHndlTbl[hndl].tcapIfIpAddress[0] = '\0';
		tcapHndlTbl[hndl].tcaphandno  = '\0';
		Tcl_MutexUnlock(&tcapMutex);

		Tcl_AppendResult(interp, argv[2],TCAP_HANDLE_REMOVED,(char *)NULL);
	}

	return TCL_OK;
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
		
		if (tcapHndlTbl[i].tcapHndlFlag != 0) {
			sprintf((char *)hndlId, "%d",  i);
			Tcl_AppendResult(interp, TCAP_HNDL_PREFIX, (char *)hndlId, " ", (char *)NULL);	;
		}
		
	}
	Tcl_AppendResult(interp, "",  (char *)NULL);

	return TCL_OK;
}

/*----------------------------------------------------------------------
 *
 * TcapSendCmd-
 *
 * This procedure implements tcap send command
 * 
 * Result:
 *	A standard Tcl result. An error message is left in the Tcl
 *	interpreter if it is not NULL.
 *----------------------------------------------------------------------
 */
static int TcapSendCmd(Tcl_Interp *interp,int argc, const char *argv[]){

	int hndl;
	int  opt, len;
	char *name;
	
	if (argc != 4) {	
		TcapWrongNumArgs(interp, 2, argv, TCAP_VALID_SEND_OPTIONS);	
		return TCL_ERROR;
	}

	hndl = TcapCheckHndl(argv[2]);
	if ( hndl == -1 ) {
		Tcl_AppendResult(interp, TCAP_INVALID_HANDLE, argv[2], (char *)NULL);	
		return TCL_ERROR;
	}

	if (!argv[3]) {
#ifndef TCL_VERSION8DOT6
		interp->result =  TCAP_VALID_SEND_OPTIONS;	
#else 
		Tcl_SetObjResult(interp, TCAP_VALID_SEND_OPTIONS);
#endif
		return TCL_ERROR;
	}

	name = ckstrdup(argv[3]);	
	len = strlen(argv[3]);
	if (tcapHndlTbl[hndl].tcapHndlFlag > 0) {
	
		char *name = ckstrdup(argv[3]);
		if (tcapHndlTbl[hndl].tcapHndlFormat == 0) 
			len = TcapHexStr2Oct(argv[3], name);
		else 
			len = TcapDecStr2Oct(argv[3], name);

		if (len > 0 ) {

#ifdef WIN32          
			opt = pcap_sendpacket(tcapHndlTbl[hndl].tcapDHndl,(u_char *)name, len);
#else
		    opt = libnet_write_link( tcapHndlTbl[hndl].libDHndl, (u_int8_t*)name, len);	//Linux, Unix			
#endif
			if ( opt == -1)
			{
				Tcl_AppendResult(interp, TCAP_SENDING_FAILED, (char *)NULL);
				return TCL_ERROR;
			} 
		} else {
				Tcl_AppendResult(interp, TCAP_INVALID_PACKET, (char *)NULL);
				return TCL_ERROR; 
		}	
	}
	
	return TCL_OK;
}

/*----------------------------------------------------------------------
 *
 * TcapSQueueCmd -
 *
 *----------------------------------------------------------------------
 */
static int TcapSQueueCmd(Tcl_Interp *interp, int argc, const char *argv[]) {

	int		hndl;
	pcap_t *indesc;
    char	errbuf[PCAP_ERRBUF_SIZE];
    char	source[PCAP_BUF_SIZE];
    FILE	*capfile;
    int		caplen;
    u_int	res;
    pcap_send_queue *squeue;				
    struct	pcap_pkthdr *pktheader;
    const	u_char *pktdata;
    u_int	npacks = 0;

    /* Check the validity of the command line */
    
	if (argc <= 3 || argc >= 6)
    {	
		Tcl_AppendResult(interp, TCAP_INVALID_ARGUMENT, (char *)NULL);	
		return TCL_ERROR;
    }
        
	hndl = TcapCheckHndl(argv[2]);
	
	if ( hndl == -1 ) {
		Tcl_AppendResult(interp, TCAP_INVALID_HANDLE, argv[2], (char *)NULL);	
		return TCL_ERROR;
	}

    /* Retrieve the length of the capture file */

    capfile=fopen(argv[3],"rb");
    if(!capfile){
		Tcl_AppendResult(interp, TCAP_DUMP_FILE, argv[3], (char *)NULL);	
        return TCL_ERROR;
    }
    
    fseek(capfile , 0, SEEK_END); 
    caplen= ftell(capfile)- sizeof(struct pcap_file_header);
    fclose(capfile);
            
    /* Open the capture */
    /* Create the source string according to the new WinTcap syntax */
    if ( pcap_createsrcstr( source,         // variable that will keep the source string
                            PCAP_SRC_FILE,  // we want to open a file
                            NULL,           // remote host
                            NULL,           // port on the remote host
                            argv[3],        // name of the file we want to open
                            errbuf          // error buffer
                            ) != 0)
							
    {
		Tcl_AppendResult(interp, TCAP_STRING_ERROR, (char *)NULL);	
        return TCL_ERROR;
    }
    
    /* Open the capture file */
    if ( (indesc= pcap_open(source, 65536, TCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf) ) == NULL)
    {
		Tcl_AppendResult(interp, TCAP_OPEN_FILE_ERROR, argv[3], (char *)NULL);	
        return TCL_ERROR;
    }

    /* Allocate a send queue */
    squeue = pcap_sendqueue_alloc(caplen);

    /* Fill the queue with the packets from the file */
    while ((res = pcap_next_ex( indesc, &pktheader, &pktdata)) == 1)
    {
        if (pcap_sendqueue_queue(squeue, pktheader, pktdata) == -1)
        {
			Tcl_AppendResult(interp, TCAP_BUFFER_WARNING, (char *)NULL);	      
            break;
        }
        npacks++;
    }

    if (res == -1)
    {
		Tcl_AppendResult(interp, TCAP_FILE_CORRUPTED, argv[3], (char *)NULL);		      
		pcap_sendqueue_destroy(squeue);
        return 0;
    }

    if ((res = pcap_sendqueue_transmit(tcapHndlTbl[hndl].tcapDHndl, squeue, 0)) < squeue->len)
    {
		Tcl_AppendResult(interp, TCAP_ERROR_OCCURRED, (char *)NULL);	
    }
    
    /* free the send queue */
    pcap_sendqueue_destroy(squeue);

    /* Close the input file */
    pcap_close(indesc);

    return TCL_OK;
}

/*----------------------------------------------------------------------
 *
 * TcapCaptureCmd-
 *
 * This procedure implements tcap capture command
 *
 * Result:
 *	A standard Tcl result. An error message is left in the Tcl
 *	interpreter if it is not NULL.
 *----------------------------------------------------------------------
 */
static int TcapCaptureCmd(Tcl_Interp *interp,int argc, const char *argv[]){

	int  hndl,res;
	unsigned int	i, len;
	char	timestr[TCAP_BUF_SIZE_16];
	struct	pcap_pkthdr *header; 
	const	u_char *pkt_data;
	struct	tm *ltime;
	time_t local_tv_sec;

#ifndef WIN32
        const u_char *packet;
        struct pcap_pkthdr hdr;   
#endif

	char resultBuffer[TCAP_BUF_SIZE_32];

	if (argc != 3) {	
		TcapWrongNumArgs(interp, 2, argv, " <handle>");	
		return TCL_ERROR;
	}

	hndl = TcapCheckHndl(argv[2]);
	if ( hndl == -1 ) {
		Tcl_AppendResult(interp, TCAP_INVALID_HANDLE, argv[2], (char *)NULL);	
		return TCL_ERROR;
	}

#ifdef WIN32
	res = pcap_next_ex(tcapHndlTbl[hndl].tcapDHndl , &header, &pkt_data);
#else 
	res = 0;
	packet = pcap_next(tcapHndlTbl[hndl].tcapDHndl,  &hdr);
	if (packet != NULL){
		   /* this change is not tested yet */
		   local_tv_sec = header->ts.tv_sec;
		   ltime=localtime(&local_tv_sec); /* shorter assignment */
           //ltime= (struct tm *)localtime((const time_t*)&hdr.ts.tv_sec);
           strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
           sprintf(resultBuffer, "{%s %.6d %d %d} ", timestr, hdr.ts.tv_usec, 
                                     hdr.len,hdr.caplen);
           Tcl_AppendResult(interp, resultBuffer, (char *)NULL);
           Tcl_AppendResult(interp, " {", (char *)NULL);
           i = 1; len = hdr.caplen;
           if (tcapHndlTbl[hndl].tcapHndlFormat == 1) {
              while(i < len + 1 ) 
              {
                sprintf(resultBuffer, "%.2d ", packet[i-1]); i++;
                Tcl_AppendResult(interp, resultBuffer, (char *)NULL);
              }
           } else {
              while(i < len + 1 ) 
              {
                sprintf(resultBuffer, "%.2x ", packet[i-1]); i++;
                Tcl_AppendResult(interp, resultBuffer, (char *)NULL);
              }
           } 		
           Tcl_AppendResult(interp, "}", (char *)NULL);   
	   return TCL_OK;
        } 
#endif

	if(res == 1) { 
		sprintf(resultBuffer, "{%ld %ld %ld} ", header->ts.tv_sec, header->ts.tv_usec, header->len);          
		
		/* the old ltime assignment statement is replaced by the shorter one 
		   to rebase the code for new Wintcap and VS 2008 */
		local_tv_sec = header->ts.tv_sec;
		ltime=localtime(&local_tv_sec); /* shorter assignment */
	    //ltime = (struct tm *)localtime((const time_t*)&header->ts.tv_sec); old one
		strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
		sprintf(resultBuffer, "{%s %.6d %d %d} ", timestr, header->ts.tv_usec,  
							header->len,header->caplen);
		Tcl_AppendResult(interp, resultBuffer, (char *)NULL);  

//	 Print the packet
		Tcl_AppendResult(interp, " {", (char *)NULL);
		i = 1; len = header->caplen;
		if (tcapHndlTbl[hndl].tcapHndlFormat == 1) {
			while(i < len + 1 ) 
			{
				sprintf(resultBuffer, "%.2d ", pkt_data[i-1]); i++;
				Tcl_AppendResult(interp, resultBuffer, (char *)NULL);
			}
		} else {
			while(i < len + 1 ) 
			{
				sprintf(resultBuffer, "%.2x ", pkt_data[i-1]); i++;
				Tcl_AppendResult(interp, resultBuffer, (char *)NULL);
			}
		} 		
 		Tcl_AppendResult(interp, "}", (char *)NULL);   
	} else if (res == 0)  {
		 Tcl_AppendResult(interp, TCAP_CAPTURE_TIMEOUT, (char *)NULL);
	} else if (res == -1) {
		 Tcl_AppendResult(interp, TCAP_CAPTURE_ERROR, (char *)NULL);
	} else if (res == -2) {
		 Tcl_AppendResult(interp, TCAP_CAPTURE_EOF, (char *)NULL);
	}	

	if (res == 1) return TCL_OK;
	return TCL_ERROR;
}

/*----------------------------------------------------------------------
 *
 * pcap_PH -
 *
 * This procedure implements Packet Handler - TcapLoopCmd uses this.
 *	
 * Result:
 *	A standard Tcl result. An error message is left in the Tcl
 *	interpreter if it is not NULL.
 *
 *----------------------------------------------------------------------
 */
void Tcap_PH(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    unsigned int	i;
	int				code;
	struct			tm *ltime;
    char timestr[TCAP_BUF_SIZE_16], hbuf[TCAP_BUF_SIZE_128], buf[TCAP_BUF_SIZE_64];
	char *			cmd, *startPtr, *scanPtr;
    Tcl_DString		tclCmd;
	time_t			local_tv_sec;
/*
#ifdef WIN32
	int bloop;
	printf("inside loop\n");
	bloop = atoi(Tcl_GetVar(globalInterp, "tcap_bloop", TCL_GLOBAL_ONLY));
	if (bloop != 0) {
		Tcl_SetVar(globalInterp, "tcap_bloop", 0, TCL_GLOBAL_ONLY);
		pcap_breakloop (tcapHndlTbl[globalHndl].tcapDHndl);
	}
#endif*/
    
    /* convert the timestamp to readable format */
	if (header) {
		local_tv_sec = header->ts.tv_sec;
		ltime=localtime(&local_tv_sec); /* shorter assignment */
		//ltime= (struct tm *)localtime((const time_t*)&header->ts.tv_sec);
		strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	}
     
    /* optionally dump the packet to a dump file - if there is one */
	if(tcapHndlTbl[globalHndl].tcapHndlDumpfile != NULL)
			 pcap_dump((u_char *)tcapHndlTbl[globalHndl].tcapHndlDumpfile, header, pkt_data);

	cmd = tcapHndlTbl[globalHndl].tcapHndlCallback;
    Tcl_DStringInit(&tclCmd);
	startPtr = cmd;

	for (scanPtr = startPtr; *scanPtr != '\0'; scanPtr++) {
		if (*scanPtr != '%') continue;
		Tcl_DStringAppend(&tclCmd, startPtr, scanPtr - startPtr);
		scanPtr++;
		startPtr = scanPtr + 1;

		switch (*scanPtr) {
		 case 'H':  
			if (header) {
				sprintf(hbuf, " {%s %.6d %d %d} ", timestr, 
					header->ts.tv_usec,  header->len, header->caplen);
				Tcl_DStringAppend(&tclCmd, hbuf, -1);
			}
		 break;
		 case 'D':
			if ((pkt_data != NULL)  && (header != NULL)) {
				sprintf(buf, "{", "");
				Tcl_DStringAppend(&tclCmd, buf, -1);

				for (i=0; i < header->caplen ; i++)
				{
					if (tcapHndlTbl[globalHndl].tcapHndlFormat == 1) 
						sprintf(buf, "%.2d ", pkt_data[i]);
					else
						sprintf(buf, "%.2x ", pkt_data[i]);
					//sprintf(buf, "%x ", pkt_data[i]);
					Tcl_DStringAppend(&tclCmd,buf, -1);
				}
				sprintf(buf, "}", "");
				Tcl_DStringAppend(&tclCmd,buf, -1);	
			}
			break;
		case '%':
			Tcl_DStringAppend(&tclCmd, "%", -1);
		 break;
		default:
			sprintf(buf, "%%%c", *scanPtr);
			Tcl_DStringAppend(&tclCmd, buf, -1);
		}
    }

    Tcl_DStringAppend(&tclCmd, startPtr, scanPtr - startPtr);
    
    Tcl_AllowExceptions(globalInterp);
    code = Tcl_GlobalEval(globalInterp, Tcl_DStringValue(&tclCmd));
	Tcl_DStringFree(&tclCmd);
}

/*----------------------------------------------------------------------
 *
 * TcapLoopCmd -
 *
 * This procedure implements pcpa loop command
 *	
 * Result:
 *	A standard Tcl result. An error message is left in the Tcl
 *	interpreter if it is not NULL.
 *
 * Side effects:
 *	Tcl variables %H and %D are populated in Tcl callback funtion
 *  with header and payload data.
 *
 *----------------------------------------------------------------------
 */
static int TcapLoopCmd(Tcl_Interp *interp,int argc, const char *argv[]){

	int  rval, hndl;
     	if (argc != 3) {	
		TcapWrongNumArgs(interp, 2, argv, "<handle>");	
		return TCL_ERROR;
	}

	hndl = TcapCheckHndl(argv[2]);
	//printf("Loop handle %d\n", hndl);
	if ( hndl == -1 ) {
		Tcl_AppendResult(interp, TCAP_INVALID_HANDLE, argv[2], (char *)NULL);	
		return TCL_ERROR;
	}

	if ( !tcapHndlTbl[hndl].tcapHndlCallback ) { /* if it is null */
		Tcl_AppendResult(interp, TCAP_NO_CALLBACK, (char *)NULL);	
		return TCL_ERROR;
	} 

	tcapHndlTbl[hndl].tcapHndlDumpfile  = NULL;
	if ( tcapHndlTbl[hndl].tcapHndlOutFile ) {
		/* Open the dump file */
   		tcapHndlTbl[hndl].tcapHndlDumpfile = 
			pcap_dump_open(tcapHndlTbl[hndl].tcapDHndl, 
								tcapHndlTbl[hndl].tcapHndlOutFile);
      }

	/* start the capture */
	Tcl_MutexLock(&tcapMutex);
	globalHndl = hndl;
	globalInterp = interp;
	Tcl_MutexUnlock(&tcapMutex);
	
    rval = pcap_loop(  tcapHndlTbl[hndl].tcapDHndl, 
				tcapHndlTbl[hndl].tcapHndlFrameCount, Tcap_PH, NULL);
        if (rval == 0){
              pcap_dump_close( tcapHndlTbl[hndl].tcapHndlDumpfile);
        } 
	if  (rval == 254) { // later check for -1 or -2
		Tcl_AppendResult(interp, TCAP_CAPTURE_EOF, (char *)NULL);	
		return TCL_ERROR;
	}
	if  (rval == 255) { // later check for -1 or -2
		Tcl_AppendResult(interp, TCAP_LOOP_FAILED, (char *)NULL);	
		return TCL_ERROR;
	}
	
	return TCL_OK;
}

/*----------------------------------------------------------------------
 *
 * TcapStatsCmd-
 *
 * This procedure implements tcap stats command
 * This command is supported only for interface types, not for file types
 *	
 * Result:
 *	A standard Tcl result. An error message is left in the Tcl
 *	interpreter if it is not NULL.
 *
 *----------------------------------------------------------------------
 */
static int TcapStatsCmd(Tcl_Interp *interp,int argc, const char *argv[]){

	int  hndl;
	int	rval;
	struct pcap_stat ps;
	char buf[32];


	if (argc != 3) {	
		TcapWrongNumArgs(interp, 2, argv, "<handle>");	
		return TCL_ERROR;
	}

	hndl = TcapCheckHndl(argv[2]);

	if ( hndl == -1 ) {
		Tcl_AppendResult(interp, TCAP_INVALID_HANDLE, argv[2], (char *)NULL);	
		return TCL_ERROR;
	}

	if ( tcapHndlTbl[hndl].tcapHndlType == TCAP_FILE ) {
		Tcl_AppendResult(interp, TCAP_NO_STATSFORFILE, (char *)NULL);	
		return TCL_ERROR;
	}

	rval = pcap_stats (tcapHndlTbl[hndl].tcapDHndl, &ps);

	sprintf (buf, "{ %u %u %u}", ps.ps_recv, ps.ps_drop, ps.ps_ifdrop); 

	Tcl_AppendResult(interp, buf, (char *)NULL);
	return TCL_OK;
}

/*----------------------------------------------------------------------
 *
 * TcapListCmd -
 *
 * This procedure implements Tcl tcap list command
 *	
 * Result:
 *	A standard Tcl result. An error message is left in the Tcl
 *	interpreter if it is not NULL.
 *
 *----------------------------------------------------------------------
 */
static int TcapListCmd(Tcl_Interp *interp,int argc, const char *argv[]){
    
	char source[TCAP_BUF_SIZE_3000];
	pcap_if_t *alldevs;
	pcap_if_t *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_addr_t *adr;
	int len,opt;    
	char rmtPort[] = TCAP_REMOTE_PORT;
			
   /* if ((argc != 2) && (argc != 4))
	{
		TcapWrongNumArgs(interp, 2, argv, "[-rip <address>]");	
		return TCL_ERROR;
	} */
	if (argv[5]) strcpy(rmtPort, argv[5]);
#ifdef WIN32	
	if( argc <= 6)
	{
		opt = TcapGetTableKey(tcapOptionTable, argv[2]);
		if (opt == -1) 
		{
#ifndef TCL_VERSION8DOT6
			interp->result =  TCAP_INVALID_OPTION;	
#else
			Tcl_SetObjResult(interp, TCAP_INVALID_OPTION);
#endif
			return TCL_ERROR;
		}
		switch ((enum options) opt) 
		{
			case optRemoteIp:
				len = strlen (argv[3]);	

				if ((!argv[3]) || (TcapValidateIpAddress(interp,argv[3]))) 
				{
					Tcl_AppendResult(interp, TCAP_INVALID_IPVALUE, argv[3], (char *)NULL);
					return TCL_ERROR;
				}
				if(TcapCheckIpAddress(interp, argv[3])== 1)
					pcap_createsrcstr(source,TCAP_SRC_RMOTE ,argv[3],rmtPort,NULL,errbuf); 
				else
					pcap_createsrcstr(source,TCAP_SRC_LOCAL, NULL,NULL,NULL,errbuf); 
				break;
			default:
				Tcl_AppendResult(interp,TCAP_INVALID_OPTION,  (char *)NULL);
				return TCL_ERROR;
				break;
		}
	}

	else if(argc == 2) 
		pcap_createsrcstr(source,TCAP_SRC_LOCAL,NULL,NULL,NULL,errbuf);
	else
	{
		Tcl_AppendResult(interp,TCAP_GET_HELP,(char *)NULL);
		return TCL_ERROR;      
	}
	    
	if( pcap_findalldevs_ex  ( source, NULL,&alldevs, errbuf) == -1)
	{
		Tcl_AppendResult(interp,TCAP_FIND_DEV_FAILED,(char *)NULL);
		return TCL_ERROR;
	}

#else
	if(pcap_findalldevs(&alldevs,errbuf)== -1)
	{
		Tcl_AppendResult(interp,TCAP_FIND_DEV_FAILED,(char *)NULL);
		return TCL_ERROR;    
	} 
#endif
	      
	for(dev=alldevs;dev;dev=dev->next)
	{
		Tcl_AppendResult(interp,"{"," ",(char *)NULL );
		Tcl_AppendResult(interp,"{",dev->name,"}"," ", (char *)NULL );  
		if(dev->description)
			Tcl_AppendResult(interp,"{",dev->description,"}"," ", (char *)NULL ); 
		  for(adr=dev->addresses;adr;adr=adr->next)
		  {
			  Tcl_AppendResult(interp,"{"," ",(char *)NULL);  
			    if (adr->addr)     
					Tcl_AppendResult(interp,iptos(((struct sockaddr_in *)adr->addr)->sin_addr.s_addr)," ",(char *)NULL);
				if (adr->netmask)
					Tcl_AppendResult(interp,iptos(((struct sockaddr_in *)adr->netmask)->sin_addr.s_addr)," ",(char *)NULL);
			   Tcl_AppendResult(interp,"}"," ",(char *)NULL);
		  }
         Tcl_AppendResult(interp,"} ",(char *)NULL);
	}
	
    pcap_freealldevs(alldevs);
    return TCL_OK;
}
/*----------------------------------------------------------------------
 *
 * TcapIfTable -
 *
 * This procedure refreshes the IF table every time tcap list is invoked
 *	
 * Result:
 *	A standard Tcl result. An error message is left in the Tcl
 *	interpreter if it is not NULL. Returns e on error, m on maxed, 
 *  and s on success.
 *
 *----------------------------------------------------------------------
 */
char TcapIfTable(Tcl_Interp *interp,const char *address,const char *IfId){

	char source[TCAP_BUF_SIZE_3000];
	pcap_if_t *alldevs;
	pcap_if_t *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_addr_t *adr;
	int sel;
	char rmtPort[] = TCAP_REMOTE_PORT;
	
#ifdef WIN32 
	   if(TcapCheckIpAddress(interp, address)== 1)
		   pcap_createsrcstr(source,TCAP_SRC_RMOTE, address,rmtPort,NULL,errbuf); 
	   else
		   pcap_createsrcstr(source,TCAP_SRC_LOCAL, NULL,NULL,NULL,errbuf); 

	   if( pcap_findalldevs_ex  ( source, NULL,&alldevs, errbuf) == -1) 
		   return 'e';
#else
       if(pcap_findalldevs(&alldevs,errbuf) == -1)
		   return 'e';
#endif

	   if(IfId != NULL)
	   {
		   for(sel=0;sel<=TCAP_HNDL_TABLE_SIZE;sel++)
		   {
			   if(tcapHndlTbl[sel].tcapIfIpAddress[0] == '\0'&& tcapHndlTbl[sel].tcapDHndl == '\0')
				   break;
		   }
		   if(sel>= TCAP_HNDL_TABLE_SIZE)
		   {
			   return 'm';
		   }
		   
		   for(dev=alldevs;dev;dev=dev->next)
		   {   
			   if(!strcmp(dev->name,IfId))
			   {
				   Tcl_MutexLock(&tcapMutex);
				   strcpy(tcapHndlTbl[sel].tcapIfID,dev->name);
				   Tcl_MutexUnlock(&tcapMutex);
				     if(dev->description)
					 {
						 Tcl_MutexLock(&tcapMutex);
						 strcpy(tcapHndlTbl[sel].tcapIfDescription ,dev->description);
						 Tcl_MutexUnlock(&tcapMutex);
					 }
					 adr=dev->addresses;
					 if (adr->addr)
					 {          
						 Tcl_MutexLock(&tcapMutex);
						 strcpy(tcapHndlTbl[sel].tcapIfIpAddress,iptos(((struct sockaddr_in *)adr->addr)->sin_addr.s_addr) );
						 Tcl_MutexUnlock(&tcapMutex);
					 }
					 if (adr->netmask)
					 {
						 Tcl_MutexLock(&tcapMutex);
						 strcpy(tcapHndlTbl[sel].tcapIfIpMask,iptos(((struct sockaddr_in *)adr->netmask)->sin_addr.s_addr) ); 
						 Tcl_MutexUnlock(&tcapMutex);
					 }
				 return 's';	
			   }
		   }
		   return 'e';
	   }

       else
	   {
		   for(sel=0;sel<=TCAP_HNDL_TABLE_SIZE;sel++)
		   {
			   if(tcapHndlTbl[sel].tcapIfIpAddress[0]== '\0' && tcapHndlTbl[sel].tcapDHndl == '\0' )
			   break;
		   }
		   if(sel>=TCAP_HNDL_TABLE_SIZE)return 'm';
		   
		   for(dev=alldevs;dev;dev=dev->next)
		   {
			   for(adr=dev->addresses;adr;adr=adr->next)
			   {
				   if(adr->addr)
				   {
					   if( strcmp(address,iptos(((struct sockaddr_in *)adr->addr)->sin_addr.s_addr))== 0 )
					   {
						   Tcl_MutexLock(&tcapMutex);
						   strcpy(tcapHndlTbl[sel].tcapIfIpAddress,address);
						   Tcl_MutexUnlock(&tcapMutex);
						     if(adr->netmask)
							 {
								 Tcl_MutexLock(&tcapMutex);
								 strcpy(tcapHndlTbl[sel].tcapIfIpMask,iptos(((struct sockaddr_in *)adr->netmask)->sin_addr.s_addr));
								 Tcl_MutexUnlock(&tcapMutex);
							 }
							 Tcl_MutexLock(&tcapMutex);
							 strcpy(tcapHndlTbl[sel].tcapIfID,dev->name);
							 Tcl_MutexUnlock(&tcapMutex);
							 if(dev->description)
							 {
								 Tcl_MutexLock(&tcapMutex); 
								 strcpy(tcapHndlTbl[sel].tcapIfDescription,dev->description);                           
								 Tcl_MutexUnlock(&tcapMutex);
							 }
							 return 's';
					   }
				   }
			   }
		   }
		   return 'e';
	   }

	//	 Free the device list 
    pcap_freealldevs(alldevs);

    return TCL_OK;
}

/*----------------------------------------------------------------------
 *
 * TcapVersionCmd -
 *
 * This procedure implements Tcl pcap version command
 *	
 * Result:
 *	A standard Tcl result. An error message is left in the Tcl
 *	interpreter if it is not NULL.
 *
 *----------------------------------------------------------------------
 */
static int TcapVersionCmd(Tcl_Interp *interp,int argc, const char *argv[]){
	
	char ver1[TCAP_BUF_SIZE_32],*ver;
	int i;

#ifdef WIN32
	ver=(char *)pcap_lib_version();
	for(i=0;i<26;i++)
		ver1[i]=ver[i];
		ver1[i]='\0';
	Tcl_AppendResult(interp,  "{Tcl ", TCL_VERSION, "} ", (char *)NULL);
	Tcl_AppendResult(interp,  "{", &ver1, ")}", (char *)NULL);
	Tcl_AppendResult(interp,  "{Tcap ", TCAP_VERSION, "} ", (char *)NULL);
	Tcl_AppendResult(interp,  " ", (char *)NULL); 
#else
	Tcl_AppendResult(interp,  "{Tcap ", TCAP_VERSION, "} ", (char *)NULL);
#endif
	return TCL_OK;
}

/*----------------------------------------------------------------------
 *
 * TcapBindFilter -
 *
 * This procedure binds a filter to a handle. This is used by tcap set
 * command.
 *	
 * Result:
 *	A standard Tcl result. An error message is left in the Tcl
 *	interpreter if it is not NULL.
 *
 *----------------------------------------------------------------------
 */
int TcapBindFilter (Tcl_Interp *interp, u_char hndl) {

	struct bpf_program fcode;
	unsigned int netmask;

	/* Retrieve the mask of the first address of the interface 
	if (d != NULL)
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else */
	netmask=0xffffff; 
   
	if (tcapHndlTbl[hndl].tcapHndlFilter[0] != 0) {
		if (pcap_compile(tcapHndlTbl[hndl].tcapDHndl, 
						&fcode, tcapHndlTbl[hndl].tcapHndlFilter, 1, netmask) <0 )
		{
			Tcl_AppendResult(interp, "", TCAP_UNABLE_TO_COMPILE, (char *)NULL);

			Tcl_MutexLock(&tcapMutex);
			tcapHndlTbl[hndl].tcapHndlFilter[0] = 0;
			Tcl_MutexUnlock(&tcapMutex);

			return TCL_ERROR;
		}
    
		if (pcap_setfilter(tcapHndlTbl[hndl].tcapDHndl, &fcode)<0)
		{
			Tcl_AppendResult(interp, "", TCAP_ERROR_BIND_FILTER, (char *)NULL);
			Tcl_MutexLock(&tcapMutex);
			tcapHndlTbl[hndl].tcapHndlFilter[0] = 0;
			Tcl_MutexUnlock(&tcapMutex);

		  return TCL_ERROR;
		} 
	}
	return TCL_OK;
}


/*----------------------------------------------------------------------
 *
 * TcapSetCmd -
 *
 * This procedure implements Tcl tcap set command
 *	
 * Result:
 *	A standard Tcl result. An error message is left in the Tcl
 *	interpreter if it is not NULL.
 *
 *----------------------------------------------------------------------
 */
static int TcapSetCmd(Tcl_Interp *interp,int argc, const char *argv[]){

	int hndl;
	struct bpf_program;
	int i, opt, val;
	char **bindingPtr = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
  	if (argc < 5) {	
		TcapWrongNumArgs(interp, 2, argv, "handle -promiscuous y/n -snaplen int ...");	
		return TCL_ERROR;
	}
   
	hndl = TcapCheckHndl(argv[2]);
	
	if ( hndl == -1 ) {
		Tcl_AppendResult(interp, TCAP_INVALID_HANDLE, argv[2], (char *)NULL);	
		return TCL_ERROR;
	}

	if (tcapHndlTbl[hndl].tcapHndlFlag > 0) {
		if (tcapHndlTbl[hndl].tcapHndlFlag == 0X00) {
			pcap_close  (tcapHndlTbl[hndl].tcapDHndl);
			Tcl_AppendResult(interp, TCAP_INVALID_HANDLE, argv[2], (char *)NULL);
			return TCL_ERROR;
		}
	}
	
	for (i = 3; i < argc; i += 2) {
		opt = TcapGetTableKey(tcapOptionTable, argv[i]);
		if (opt == -1) {
			Tcl_AppendResult(interp, TCAP_INVALID_OPTION, argv[i], (char *)NULL);
			return TCL_ERROR;
		}
		switch (opt) {
			case optPromiscuous: //ascii values of 'y' and 'n' are used
				if ( (!argv[i+1]) && ((argv[i+1][0] != 121) || (argv[i+1][0] != 110))) {
#ifndef TCL_VERSION8DOT6
					interp->result =  " -promiscuous y|n";	
#else
					Tcl_SetObjResult(interp, " -promiscuous y|n");
#endif				
					return TCL_ERROR;
				} else {
					if (argv[i+1][0] == 121) tcapHndlTbl[hndl].tcapHndlPromisc = 1;
					else tcapHndlTbl[hndl].tcapHndlPromisc = 0;
				}
			break;
			case optOutputFormat: //ascii values of 'h' and 'd' are used
				if ( (!argv[i+1]) && ((argv[i+1][0] != 104) || (argv[i+1][0] != 100))) {
#ifndef TCL_VERSION8DOT6
					interp->result =  " -format hexa|deci";	
#else
					Tcl_SetObjResult(interp, " -format hexa|deci");
#endif					
					return TCL_ERROR;
				} else {
					if (argv[i+1][0] == 104) tcapHndlTbl[hndl].tcapHndlFormat = 0;
					else tcapHndlTbl[hndl].tcapHndlFormat = 1;
				}
			break;
			case optTimeout:
				if ( ( val = atoi (argv[i+1])) > 0 ) {

					Tcl_MutexLock(&tcapMutex);
					tcapHndlTbl[hndl].tcapHndlRdTimeout = val;
					Tcl_MutexUnlock(&tcapMutex);

				} else {
#ifndef TCL_VERSION8DOT6
					interp->result =  " -timeout <int>";	
#else
					Tcl_SetObjResult(interp, " -timeout <int>");
#endif	
					return TCL_ERROR;			
				}
			break;
			case optSnapLen:
				if ( ( val = atoi (argv[i+1])) > 0 ) {

					Tcl_MutexLock(&tcapMutex);
					tcapHndlTbl[hndl].tcapHndlSnapLen = val;
					Tcl_MutexUnlock(&tcapMutex);

				} else {
#ifndef TCL_VERSION8DOT6
					interp->result =  " -snaplen <int>";	
#else
					Tcl_SetObjResult(interp, " -snaplen <int>");
#endif	
					return TCL_ERROR;			
				}
			break;
			case optCount:                                                          
				if ( ( val = atoi (argv[i+1])) > 0 ) {

					Tcl_MutexLock(&tcapMutex);
					tcapHndlTbl[hndl].tcapHndlFrameCount = val;
					Tcl_MutexUnlock(&tcapMutex);

				} else {
#ifndef TCL_VERSION8DOT6
					interp->result =  " -count <int>";	
#else
					Tcl_SetObjResult(interp, " -count <int>");
#endif
					return TCL_ERROR;			
				}
			break;
			case optFilter:
				if ( (!argv[i+1]) ) {
#ifndef TCL_VERSION8DOT6
					interp->result =  " -filter <filterspec>";	
#else
					Tcl_SetObjResult(interp, " -filter <filterspec>");
#endif
					return TCL_ERROR;
				} else {

					Tcl_MutexLock(&tcapMutex);
					strcpy(tcapHndlTbl[hndl].tcapHndlFilter, argv[i+1]);
					Tcl_MutexUnlock(&tcapMutex);
				}
			break;
			case optOutFile:
				if ( (!argv[i+1]) ) {
#ifndef TCL_VERSION8DOT6
					interp->result =  " -outfile <filename>";	
#else
					Tcl_SetObjResult(interp, " -outfile <filename>");
#endif
					return TCL_ERROR;
				} else {

					Tcl_MutexLock(&tcapMutex);
					strcpy(tcapHndlTbl[hndl].tcapHndlOutFile, argv[i+1]);
					Tcl_MutexUnlock(&tcapMutex);
				}
			break;
			case optCallback:		
				if ( (!argv[i+1]) ) {
#ifndef TCL_VERSION8DOT6
					interp->result =  " -callback <script>";	
#else
					Tcl_SetObjResult(interp, " -callback <script>");
#endif
					return TCL_ERROR;
				}
				bindingPtr = &(tcapHndlTbl[hndl].tcapHndlCallback);
				if ((argv[i+1])) {

					if (*bindingPtr) {
							 ckfree(*bindingPtr);
							*bindingPtr = NULL;
					}
					if (argv[i+1][0] != '\0') {
						    *bindingPtr = ckstrdup(argv[i+1]);
					}
				}	
			break;
			default:
#ifndef TCL_VERSION8DOT6
					interp->result =  "Usage: tcap ?arg arg ...?";	
#else
					Tcl_SetObjResult(interp, "Usage: tcap ?arg arg ...?");
#endif
				return TCL_ERROR;
			break;
		}
	}

	Tcl_MutexLock(&tcapMutex);

	if (tcapHndlTbl[hndl].tcapHndlType == TCAP_INTERFACE) {
  		pcap_close  (tcapHndlTbl[hndl].tcapDHndl);
#ifdef WIN32
		if ( (tcapHndlTbl[hndl].tcapDHndl  = pcap_open(tcapHndlTbl[hndl].tcapIfID,
				                             tcapHndlTbl[hndl].tcapHndlSnapLen, 
											 tcapHndlTbl[hndl].tcapHndlPromisc ,
                                             tcapHndlTbl[hndl].tcapHndlRdTimeout ,
											 NULL,
											 errbuf))== NULL)
		{
			Tcl_AppendResult(interp, TCAP_SET_FAILED, argv[2], (char *)NULL);
			Tcl_MutexUnlock(&tcapMutex);
			return TCL_ERROR;
		}
#else
        if((tcapHndlTbl[hndl].tcapDHndl = pcap_open_live((char *)tcapHndlTbl[hndl].tcapIfID,
                                                         tcapHndlTbl[hndl].tcapHndlSnapLen,
                                                         tcapHndlTbl[hndl].tcapHndlPromisc,
                                                         tcapHndlTbl[hndl].tcapHndlRdTimeout,
                                                         errbuf  )) == NULL )
        {
             Tcl_AppendResult(interp,TCAP_SET_FAILED,argv[2],(char *)NULL);
             return TCL_ERROR;   
        }
#endif
	} else {
		if ( (tcapHndlTbl[hndl].tcapDHndl  = pcap_open_offline(
								tcapHndlTbl[hndl].tcapHndlInFile,	
								errbuf          ) ) == NULL) 
		{
			Tcl_AppendResult(interp, TCAP_SET_FAILED, argv[2], (char *)NULL);
			Tcl_MutexUnlock(&tcapMutex);
			return TCL_ERROR;
		}
	}

	if ( TcapBindFilter(interp, hndl) != TCL_OK) 
		return TCL_ERROR;
	tcapHndlTbl[hndl].tcapHndlFlag |= TCAP_IN_USE;
	Tcl_MutexUnlock(&tcapMutex);

	return TCL_OK;
}

/*----------------------------------------------------------------------
 *
 * TcapOpenCmd -
 *
 * This procedure implements Tcl tcap open command
 *	
 * Result:
 *	A standard Tcl result. An error message is left in the Tcl
 *	interpreter if it is not NULL.
 *
 *----------------------------------------------------------------------
 */
static int TcapOpenCmd(Tcl_Interp *interp,int argc, const char *argv[]){
	char errbuf[PCAP_ERRBUF_SIZE],hndlId[3],chk;
    int opt,len,i=0,sel;
	int fileFlag = 0;

    if (( argc != 4 )&& ( argc != 6 )) {	
		TcapWrongNumArgs(interp, 2, argv, TCAP_INVALID_OPTION);
		return TCL_ERROR;
	}
    if(argc == 4){
       if((strcmp(argv[2],"-ip") != 0) && (strcmp(argv[2],"-infile") != 0)){
              TcapWrongNumArgs(interp,2,argv, "-ip or -infile"); 
              return TCL_ERROR;
       }
   }
   if(argc == 6){
     if((strcmp(argv[2],"-ip") != 0) || (strcmp(argv[4],"-id") != 0)){
            TcapWrongNumArgs(interp,2,argv, "-ip <addrs> -id <ifid>");
            return TCL_ERROR;
     }
   }
   for(i=2;i<argc-1;i+=2) {
	    opt = TcapGetTableKey(tcapOptionTable, argv[i]);
        if (opt == -1) {  
#ifndef TCL_VERSION8DOT6
					interp->result =  TCAP_INVALID_OPTION;	
#else
					Tcl_SetObjResult(interp, TCAP_INVALID_OPTION);
#endif
			return TCL_ERROR;
        }
	    switch ((enum options) opt) {
	  	  case optIpAddress:                                                       
			 len = strlen (argv[3]);	

			 if ((!argv[3]) || (TcapValidateIpAddress(interp,argv[3]))) {
				Tcl_AppendResult(interp, TCAP_INVALID_IPVALUE, argv[3], (char *)NULL);
				return TCL_ERROR;
			 }
             if( argc == 4){                                   
                chk = TcapIfTable(interp,argv[3],NULL);
                if(chk == 'e') {
                   Tcl_AppendResult(interp, TCAP_FIND_DEV_FAILED, (char *)NULL);
                   return TCL_ERROR;
                }
                else if(chk == 'm') {
                   Tcl_AppendResult(interp,TCAP_TOO_MANY_HANDLES,(char *)NULL);
                   return TCL_ERROR;
                }
                else if(chk != 's'){
                   Tcl_AppendResult(interp,TCAP_INVALID_IPVALUE,(char *)NULL);
                   return TCL_ERROR;
                }

                for(sel=0;sel<= TCAP_HNDL_TABLE_SIZE;sel++){
				    if(!strcmp(tcapHndlTbl[sel].tcapIfIpAddress,argv[3]) )
					break;
			    }
			    if (sel>= TCAP_HNDL_TABLE_SIZE) {
			    	Tcl_AppendResult(interp, TCAP_TOO_MANY_HANDLES, (char *)NULL);
			    	return TCL_ERROR;
			    }
            } 
	        break;
          case optIfId:
             len=strlen(argv[5]);
             // *(argv[5]+len) = '\0';
             chk = TcapIfTable(interp, argv[3],argv[5]);
             if(chk  == 'e'){
                Tcl_AppendResult(interp,TCAP_FIND_DEV_FAILED,(char *)NULL);
                return TCL_ERROR;
             } 
             else if(chk == 'm'){
                Tcl_AppendResult(interp,TCAP_TOO_MANY_HANDLES,(char *)NULL);
                return TCL_ERROR;
             }  
             else if(chk != 's'){
                Tcl_AppendResult(interp,TCAP_INVALID_IFID,(char *)NULL);
                return TCL_ERROR;
             }  
             for(sel=0;sel<=TCAP_HNDL_TABLE_SIZE;sel++){
                if(!strcmp(tcapHndlTbl[sel].tcapIfID,argv[5]))
                break;
             }
             if(sel>=TCAP_HNDL_TABLE_SIZE){
                Tcl_AppendResult(interp,TCAP_TOO_MANY_HANDLES,(char *)NULL);
                return TCL_ERROR;
             }
             break;
	
		  case optInFile:	
			len = strlen (argv[3]);	
			fileFlag = 1;
			break;

		  default:
			Tcl_AppendResult(interp, TCAP_INVALID_IFSPEC, argv[3], (char *)NULL);
			return TCL_ERROR;
			break;
	    }//end of switch
	}//end of for

	for ( i = 0; i < TCAP_HNDL_TABLE_SIZE; i++) {
		if (tcapHndlTbl[i].tcapHndlFlag == 0) {
                  	Tcl_MutexLock(&tcapMutex);
			tcapHndlTbl[i].tcapHndlSnapLen = TCAP_MAX_PACKET_SIZE;
			tcapHndlTbl[i].tcapHndlPromisc = TCAP_OPENFLAG_PROMISCUOUS;
			tcapHndlTbl[i].tcapHndlRdTimeout = TCAP_DEFAULT_READ_TIMEOUT;
			tcapHndlTbl[i].tcapHndlCallback = NULL;
			Tcl_MutexUnlock(&tcapMutex);

			if (!fileFlag) {
#ifdef WIN32   
		       tcapHndlTbl[i].tcapDHndl  =  pcap_open((char *)tcapHndlTbl[sel].tcapIfID,
				                               tcapHndlTbl[i].tcapHndlSnapLen, 
											   TCAP_OPENFLAG_PROMISCUOUS,
											   tcapHndlTbl[i].tcapHndlRdTimeout ,
											   NULL,
											   errbuf);
#else         
       
               tcapHndlTbl[i].tcapDHndl = pcap_open_live((char *)tcapHndlTbl[sel].tcapIfID,
                                                  tcapHndlTbl[i].tcapHndlSnapLen,
                                                  tcapHndlTbl[i].tcapHndlPromisc,
                                                  tcapHndlTbl[i].tcapHndlRdTimeout,
                                                  errbuf        );
               tcapHndlTbl[i].libDHndl = libnet_init(LIBNET_LINK,tcapHndlTbl[sel].tcapIfID,errbuf); 
                                       
#endif 
				 
			} else {
				Tcl_MutexLock(&tcapMutex);
				strcpy(tcapHndlTbl[i].tcapHndlInFile, argv[3]);
				Tcl_MutexUnlock(&tcapMutex);
				if ((tcapHndlTbl[i].tcapDHndl  = pcap_open_offline( argv[3], errbuf) ) == NULL) {
					Tcl_AppendResult(interp, TCAP_FILE_OPEN_FAILED, argv[3], (char *)NULL);
					return TCL_ERROR;
				}
			}
		   	if ( tcapHndlTbl[i].tcapDHndl == NULL )  return TCL_ERROR;
			if (fileFlag) {		
                Tcl_MutexLock(&tcapMutex);
			    tcapHndlTbl[i].tcapHndlType = TCAP_FILE;
			    strcpy(tcapHndlTbl[i].tcapHndlInFile, argv[3]);
                Tcl_MutexUnlock(&tcapMutex);			
			}
			else {
                Tcl_MutexLock(&tcapMutex);
				tcapHndlTbl[i].tcapHndlType = TCAP_INTERFACE;
                Tcl_MutexUnlock(&tcapMutex);
			}
            Tcl_MutexLock(&tcapMutex);
			sprintf(errbuf, "%s%d%s", TCAP_HNDL_PREFIX, i, TCAP_DUMP_FILE_SUFFIX);
			strcpy(tcapHndlTbl[i].tcapHndlOutFile, errbuf);
			tcapHndlTbl[i].tcapHndlFlag |= TCAP_IN_USE;

			tcapHndlTbl[i].tcaphandno = i;
            Tcl_MutexUnlock(&tcapMutex);
			sprintf((char *)hndlId, "%d",  i);
			Tcl_AppendResult(interp, TCAP_HNDL_PREFIX, (char *)hndlId, (char *)NULL);
			return TCL_OK;
		}
		else continue;
	}
       
	if (i >= TCAP_HNDL_TABLE_SIZE) {
		Tcl_AppendResult(interp, TCAP_TOO_MANY_HANDLES, (char *)NULL);
		return TCL_ERROR;
	}

	if (TcapBindFilter (interp, i) != TCL_OK) return TCL_ERROR;
           
    return TCL_OK;
}

/*----------------------------------------------------------------------
 *
 * TcapCmd -
 *
 * This is the tcap command. 
 * It demultiplexes to other functions to handle requested action.
 *	
 * Result:
 *	A standard Tcl result. An error message is left in the Tcl
 *	interpreter if it is not NULL.
 *----------------------------------------------------------------------
 */
int TcapCmd(ClientData clientData,Tcl_Interp *interp, int  argc, const char *argv[])
{
	int   rvalue, cmd;
	
	if (argc < 2) {	
		TcapWrongNumArgs(interp, 1, argv, "arg? arg?...");
		return TCL_ERROR;
	}

	cmd = TcapGetTableKey(tcapCmdTable, argv[1]);

    if (cmd == -1) {
#ifndef TCL_VERSION8DOT6
					interp->result =  TCAP_GET_HELP;	
#else
					Tcl_SetObjResult(interp, TCAP_GET_HELP);
#endif
			return TCL_ERROR;
    }
	 switch ((enum commands) cmd) {
		case cmdList:
			rvalue = TcapListCmd(interp, argc, argv);
			break;
		case cmdOpen:
			rvalue = TcapOpenCmd(interp, argc, argv);
			break;
		case cmdClose:
			rvalue = TcapCloseCmd(interp, argc, argv);
			break;
		case cmdInfo:
			rvalue = TcapInfoCmd(interp, argc, argv);
			break;
		case cmdCapture: 
			rvalue = TcapCaptureCmd(interp, argc, argv);
			break;
		case cmdSend:
			rvalue = TcapSendCmd(interp, argc, argv);
			break;
		case cmdSet:
			rvalue = TcapSetCmd(interp, argc, argv);
			break;
		case cmdLoop:
			rvalue = TcapLoopCmd(interp, argc, argv);
			break;
		case cmdStats:
			rvalue = TcapStatsCmd(interp, argc, argv);
			break;
		case cmdHandle:
			rvalue = TcapHandleCmd(interp, argc, argv);
			break;
		case cmdH:
		case cmdHelp:
		case cmdHelp1:
			rvalue = TcapHelpCmd(interp, argc, argv);
			break;
		case cmdSQueue:
			rvalue = TcapSQueueCmd(interp, argc, argv);
			break;
		case cmdVersion:
			rvalue = TcapVersionCmd(interp, argc, argv);
			break;
		default:
			rvalue = TcapHelpCmd(interp, argc, argv);
			break;
	}
	return rvalue;
}

#ifndef DECLSPEC_EXPORT
#define DECLSPEC_EXPORT __declspec(dllexport)
#endif // DECLSPEC_EXPORT

#ifdef  WIN32
 BOOL APIENTRY
 DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
 {
     return TRUE;
 }

 EXTERN_C int DECLSPEC_EXPORT
 Tcap_Init(Tcl_Interp* interp)
#else 
int Tcap_Init(Tcl_Interp* interp)
#endif
 {
	int r;
	Tcl_Obj *tcap_bloop, *version;


 #ifdef USE_TCL_STUBS
     Tcl_InitStubs(interp, TCL_VERSION, 0);
 #endif
     version = Tcl_SetVar2Ex(interp, "tcap_version", NULL,
                                      Tcl_NewDoubleObj(TCAP_VERSION_INT), TCL_LEAVE_ERR_MSG);
     if (version == NULL)
         return TCL_ERROR;
     r = Tcl_PkgProvide(interp, "Tcap", Tcl_GetString(version));

	 //Initialize  handle table 
	 TcapHndlInit ();
	 
	 tcap_bloop = Tcl_SetVar2Ex(interp, "tcap_bloop", NULL,
                                      Tcl_NewDoubleObj(0), TCL_LEAVE_ERR_MSG);
     // Call Tcl_CreateObjCommand etc.
	 Tcl_CreateCommand(interp, "tcap", TcapCmd,(ClientData) NULL,  (Tcl_CmdDeleteProc *)NULL);
	 
     return r;
 }

#ifdef WIN32
 EXTERN_C int DECLSPEC_EXPORT
 Tcap_SafeInit(Tcl_Interp* interp)
#else 
int Tcap_SafeInit(Tcl_Interp* interp)
#endif
 {
     // We don't need to be specially safe so...
     return Tcap_Init(interp);
 }
