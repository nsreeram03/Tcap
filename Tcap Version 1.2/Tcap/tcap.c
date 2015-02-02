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
	Tcl_AppendResult(interp,  "	\n		tcap Help commands \n", (char *)NULL);
	Tcl_AppendResult(interp,  "		=================== \n", (char *)NULL);
	Tcl_AppendResult(interp,  "		tcap help | ?    \n",  (char *)NULL);
	Tcl_AppendResult(interp,  "\n o	tcap list [-host <rpcapd server host> [-port <server port>]] \n",(char *)NULL);
	Tcl_AppendResult(interp,  "\n o	tcap info|show [<handle> ] \n",(char *)NULL); 
	Tcl_AppendResult(interp,  "\n o	tcap version  \n",(char *)NULL);
	Tcl_AppendResult(interp,  "\n o	tcap close <handle> \n",(char *)NULL);  
	Tcl_AppendResult(interp,  "\n o	tcap send <handle> <data in hex>|<data in decimal> \n",(char *)NULL);  
	Tcl_AppendResult(interp,  "\n o	tcap capture <handle> \n",(char *)NULL);
	Tcl_AppendResult(interp,  "\n o	tcap loop <handle> \n",(char *)NULL); 
	Tcl_AppendResult(interp,  "\n o	tcap stats <handle> \n",(char *)NULL);
	Tcl_AppendResult(interp,  "\n o	tcap handle [<handle>] \n",(char *)NULL);
	Tcl_AppendResult(interp,  "\n o	tcap squeue <handle> -infile <pcap file> \n",(char *)NULL);
	Tcl_AppendResult(interp,  "\n o	tcap open -infile <input file> \n",(char *)NULL);
	Tcl_AppendResult(interp,  "\n o	tcap open -ip4 <ip4 address> | -id <interface id> | \n",(char *)NULL);
	Tcl_AppendResult(interp,  "               -if <interface number>| -i6 <ipv6 address> \n",(char *)NULL);
	Tcl_AppendResult(interp,  "\n o	tcap open -host <rpcapd server host> [-port <server port> \n",(char *)NULL);
    Tcl_AppendResult(interp,  "	  [-ip4 <ip4 address>|-id <interface id>|-if<interface number>]] \n",(char *)NULL);
	Tcl_AppendResult(interp,  "\n o	tcap set <handle>  - snaplen <snap length>	| \n",(char *)NULL);
	Tcl_AppendResult(interp,  "			   - promiscuous <y|n>		| \n",(char *)NULL);
	Tcl_AppendResult(interp,  "           		   - filter  <capture filter>	| \n",(char *)NULL);
	Tcl_AppendResult(interp,  "			   - timeout <timeout in ms>	| \n",(char *)NULL);
	Tcl_AppendResult(interp,  "			   - samplemethd <0|1|2>	| \n",(char *)NULL);
	Tcl_AppendResult(interp,  "			   - samplevalue <integer>	| \n",(char *)NULL);
	Tcl_AppendResult(interp,  "			   - count <frame count>	| \n",(char *)NULL);
	Tcl_AppendResult(interp,  "		           - outfile <file name>	| \n",(char *)NULL);
	Tcl_AppendResult(interp,  "			   - format <hex|decimal>	| \n",(char *)NULL);
	Tcl_AppendResult(interp,  "			   - callback <Tcl script>	| \n",(char *)NULL);
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
	
	
	if(argc == 2){
	printf("",TcapHandleCmd(interp,argc,argv));
	return TCL_OK;
	} else  {
	if (argc != 3) {	
		TcapWrongNumArgs(interp, 2, argv, " [<handle>]");	
		return TCL_ERROR;
	}
	}
	hndl = TcapCheckHndl(argv[2]);
	
	if ( hndl == -1 ) {
		Tcl_AppendResult(interp, TCAP_INVALID_HANDLE, argv[2], (char *)NULL);	
		return TCL_ERROR;
	}
	
	if (tcapHndlTbl[hndl].tcapStatusFlag > 0)
		TcapCreateHndlList (interp, hndl); 
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
	int i, hosttype,opt;    
	char rmtPort[7] = TCAP_REMOTE_PORT;
	char rip[128];
			
   if ((argc != 2) && (argc != 4) && (argc != 6))
	{
		TcapWrongNumArgs(interp, 2, argv, "[-rip <address> [-port <portnum>]]");	
		return TCL_ERROR;
	} 

#ifdef WIN32	
	if( argc > 2 )
	{
		for(i=2;i<argc-1;i+=2) {
			opt = TcapGetTableKey(tcapOptionTable, argv[i]);

			switch ((enum options) opt) 
			{
				case optRemoteHostIp:
					strcpy(rip, argv[i+1]);
					hosttype = PCAP_SRC_IFREMOTE ;
					break;
				case optRemotePort:
					strcpy(rmtPort, argv[i+1]);
					break;
				default:
					Tcl_AppendResult(interp,TCAP_INVALID_OPTION,  (char *)NULL);
					return TCL_ERROR;
					break;
			}
		}
	}
	else if(argc == 2) 
		hosttype = PCAP_SRC_IFLOCAL ;
	else
	{
		Tcl_AppendResult(interp,TCAP_GET_HELP,(char *)NULL);
		return TCL_ERROR;      
	}
	pcap_createsrcstr(source,hosttype,rip,rmtPort,NULL,errbuf);

	if( pcap_findalldevs_ex  ( source, NULL, &alldevs, errbuf) == -1)
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

	if (tcapHndlTbl[hndl].tcapStatusFlag   > 0) {
		if (tcapHndlTbl[hndl].tcapDumpfile)
			pcap_dump_close(tcapHndlTbl[hndl].tcapDumpfile);
		pcap_close  (tcapHndlTbl[hndl].tcapPcapHndl);

		Tcl_MutexLock(&tcapMutex);
        tcapHndlTbl[hndl].tcapStatusFlag = 0;
		tcapHndlTbl[hndl].tcapPcapHndl = '\0';
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
	printf("The packet sent is |%s| \n",name);
	printf("Length of the packet is %d \n ",len);
	if (tcapHndlTbl[hndl].tcapStatusFlag > 0) {
	
		char *name = ckstrdup(argv[3]);
		if (tcapHndlTbl[hndl].tcapDispFormat == TCAP_HEXADECIMAL) {
			len = TcapHexStr2Oct(argv[3], name);
			printf("%d",len);
		} else {
			len = TcapDecStr2Oct(argv[3], name);
			printf("Decimal %d",len);
		}
		if (len > 0 ) {

#ifdef WIN32          
			opt = pcap_sendpacket(tcapHndlTbl[hndl].tcapPcapHndl,(u_char *)name, len);
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
		Tcl_AppendResult(interp, TCAP_OPEN_ERROR, argv[3], (char *)NULL);	
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

    if ((res = pcap_sendqueue_transmit(tcapHndlTbl[hndl].tcapPcapHndl, squeue, 0)) < squeue->len)
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
	char	timestr[16];
	struct	pcap_pkthdr *header; 
	const	u_char *pkt_data;
	struct	tm *ltime;
	time_t local_tv_sec;

#ifndef WIN32
        const u_char *packet;
        struct pcap_pkthdr hdr;   
#endif

	char resultBuffer[32];

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
	res = pcap_next_ex(tcapHndlTbl[hndl].tcapPcapHndl , &header, &pkt_data);
#else 
	res = 0;
	packet = pcap_next(tcapHndlTbl[hndl].tcapPcapHndl,  &hdr);
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
           if (tcapHndlTbl[hndl].tcapDispFormat == TCAP_DECIMAL) {
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
		if (tcapHndlTbl[hndl].tcapDispFormat == TCAP_DECIMAL) {
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
    char timestr[16], hbuf[128], buf[64];
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
		pcap_breakloop (tcapHndlTbl[globalHndl].tcapPcapHndl);
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
	if(tcapHndlTbl[globalHndl].tcapDumpfile != NULL)
			 pcap_dump((u_char *)tcapHndlTbl[globalHndl].tcapDumpfile, header, pkt_data);

	cmd = tcapHndlTbl[globalHndl].tcapCallbackFun;
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
					if (tcapHndlTbl[globalHndl].tcapDispFormat == TCAP_DECIMAL) 
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
 * This procedure implements tcap loop command
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

	if ( !tcapHndlTbl[hndl].tcapCallbackFun ) { /* if it is null */
		Tcl_AppendResult(interp, TCAP_NO_CALLBACK, (char *)NULL);	
		return TCL_ERROR;
	} 

	tcapHndlTbl[hndl].tcapDumpfile  = NULL;
	if ( tcapHndlTbl[hndl].tcapOutputFile ) {
		/* Open the dump file */
   		tcapHndlTbl[hndl].tcapDumpfile = 
			pcap_dump_open(tcapHndlTbl[hndl].tcapPcapHndl, 
								tcapHndlTbl[hndl].tcapOutputFile);
      }

	/* start the capture */
	Tcl_MutexLock(&tcapMutex);
	globalHndl = hndl;
	globalInterp = interp;
	Tcl_MutexUnlock(&tcapMutex);
	
    rval = pcap_loop(  tcapHndlTbl[hndl].tcapPcapHndl, 
				tcapHndlTbl[hndl].tcapFrameCount, Tcap_PH, NULL);
    printf("",rval);    
		if (rval == 0){
              pcap_dump_close( tcapHndlTbl[hndl].tcapDumpfile);
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

	rval = pcap_stats (tcapHndlTbl[hndl].tcapPcapHndl, &ps);

	sprintf (buf, "{ %u %u %u}", ps.ps_recv, ps.ps_drop, ps.ps_ifdrop); 

	Tcl_AppendResult(interp, buf, (char *)NULL);
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
	
	char ver1[32],*ver;
	int i;

#ifdef WIN32
	ver=(char *)pcap_lib_version();
	for(i=0;i < TCAP_LIB_VERSION_SIZE;i++) ver1[i]=ver[i];
	ver1[i]='\0';
	Tcl_AppendResult(interp,  "{Tcl ", TCL_VERSION, "} ", (char *)NULL);
	Tcl_AppendResult(interp,  "{", ver1, ")} ", (char *)NULL);
	Tcl_AppendResult(interp,  "{Tcap ", TCAP_VERSION, "} ", (char *)NULL);
	Tcl_AppendResult(interp,  " ", (char *)NULL); 
#else
	Tcl_AppendResult(interp,  "{Tcap ", TCAP_VERSION, "} ", (char *)NULL);
#endif
	return TCL_OK;
}

/*----------------------------------------------------------------------
 *
 * TcapLinkCmd -
 *
 * This command returns the link layer type associated with the 
 * specified handle
 *	
 * Result:
 *	A standard Tcl result. An error message is left in the Tcl
 *	interpreter if it is not NULL.
 *
 *----------------------------------------------------------------------
 */
static int TcapLinkCmd(Tcl_Interp *interp,int argc, const char *argv[]){
	int  hndl;
	int  link;
	int  linkbuf[128];
	
	if (argc != 3) {	
		TcapWrongNumArgs(interp, 2, argv, " <handle>");	
		return TCL_ERROR;
	}

	hndl = TcapCheckHndl(argv[2]);
	if ( hndl == -1 )  {
		Tcl_AppendResult(interp, TCAP_INVALID_HANDLE, argv[2], (char *)NULL);	
		return TCL_ERROR;
	}

	if (tcapHndlTbl[hndl].tcapStatusFlag   > 0) {
		link = pcap_datalink (tcapHndlTbl[hndl].tcapPcapHndl);
		sprintf(linkbuf, "%d %s {%s}", link, pcap_datalink_val_to_name(link),
			    pcap_datalink_val_to_description(link));
		Tcl_AppendResult(interp, linkbuf,(char *)NULL);
		Tcl_AppendResult(interp,  " ", (char *)NULL); 
	}

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
   
	if (tcapHndlTbl[hndl].tcapDisplayFilter[0] != 0) {
		if (pcap_compile(tcapHndlTbl[hndl].tcapPcapHndl, 
						&fcode, tcapHndlTbl[hndl].tcapDisplayFilter, 1, netmask) <0 )
		{
			Tcl_AppendResult(interp, "", TCAP_UNABLE_TO_COMPILE, (char *)NULL);

			Tcl_MutexLock(&tcapMutex);
			tcapHndlTbl[hndl].tcapDisplayFilter[0] = 0;
			Tcl_MutexUnlock(&tcapMutex);

			return TCL_ERROR;
		}
    
		if (pcap_setfilter(tcapHndlTbl[hndl].tcapPcapHndl, &fcode)<0)
		{
			Tcl_AppendResult(interp, "", TCAP_ERROR_BIND_FILTER, (char *)NULL);
			Tcl_MutexLock(&tcapMutex);
			tcapHndlTbl[hndl].tcapDisplayFilter[0] = 0;
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
  	if (argc != 5) {	
		TcapWrongNumArgs(interp, 2, argv, "handle -promiscuous y/n -snaplen int ...");	
		return TCL_ERROR;
	}
   
	hndl = TcapCheckHndl(argv[2]);
	
	if ( hndl == -1 ) {
		Tcl_AppendResult(interp, TCAP_INVALID_HANDLE, argv[2], (char *)NULL);	
		return TCL_ERROR;
	}

	if (tcapHndlTbl[hndl].tcapStatusFlag > 0) {
		if (tcapHndlTbl[hndl].tcapStatusFlag == 0X00) {
			pcap_close  (tcapHndlTbl[hndl].tcapPcapHndl);
			Tcl_AppendResult(interp, TCAP_INVALID_HANDLE, argv[2], (char *)NULL);
			return TCL_ERROR;
		}
	}
	

	opt = TcapGetTableKey(tcapOptionTable, argv[3]);
	if (opt == -1) {
		Tcl_AppendResult(interp, TCAP_INVALID_OPTION, argv[3], (char *)NULL);
		return TCL_ERROR;
	}
	switch (opt) {
		case optPromiscuous: //ascii values of 'y' and 'n' are used
			if ( (!argv[4]) && ((argv[4][0] != 'y') || (argv[4][0] != 'n'))) {
#ifndef TCL_VERSION8DOT6
				interp->result =  " -promiscuous y|n";	
#else
				Tcl_SetObjResult(interp, " -promiscuous y|n");
#endif				
				return TCL_ERROR;
			} else {
				if (argv[4][0] == 'y') tcapHndlTbl[hndl].tcapCaptureMode = 1;
				else tcapHndlTbl[hndl].tcapCaptureMode = 0;
			}
			break;
		case optOutputFormat: //ascii values of 'h' and 'd' are used
			if ( (!argv[4]) && ((argv[4][0] != 'h') || (argv[4][0] != 'd'))) {
#ifndef TCL_VERSION8DOT6
				interp->result =  " -format hexa|deci";	
#else
				Tcl_SetObjResult(interp, " -format hexa|deci");
#endif					
				return TCL_ERROR;
			} else {
				if (argv[4][0] == 'd') tcapHndlTbl[hndl].tcapDispFormat = TCAP_DECIMAL;
				else tcapHndlTbl[hndl].tcapDispFormat = TCAP_HEXADECIMAL;
			}
			break;
		case optTimeout:
			if ( ( val = atoi (argv[4])) > 0 ) {
				Tcl_MutexLock(&tcapMutex);
				tcapHndlTbl[hndl].tcapRdTimeOut = val;
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
			if ( ( val = atoi (argv[4])) > 0 ) {
				Tcl_MutexLock(&tcapMutex);
				tcapHndlTbl[hndl].tcapSnapLen = val;
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
			if ( ( val = atoi (argv[4])) > 0 ) {
				Tcl_MutexLock(&tcapMutex);
				tcapHndlTbl[hndl].tcapFrameCount = val;
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
			if ( (!argv[4]) ) {
#ifndef TCL_VERSION8DOT6
				interp->result =  " -filter <filterspec>";	
#else
				Tcl_SetObjResult(interp, " -filter <filterspec>");
#endif
				return TCL_ERROR;
			} else {
				Tcl_MutexLock(&tcapMutex);
				strcpy(tcapHndlTbl[hndl].tcapDisplayFilter, argv[4]);
				Tcl_MutexUnlock(&tcapMutex);
			}
		break;
		case optOutFile:
			if ( (!argv[4]) ) {
#ifndef TCL_VERSION8DOT6
				interp->result =  " -outfile <filename>";	
#else
				Tcl_SetObjResult(interp, " -outfile <filename>");
#endif
				return TCL_ERROR;
			} else {
				Tcl_MutexLock(&tcapMutex);
				strcpy(tcapHndlTbl[hndl].tcapOutputFile, argv[4]);
				Tcl_MutexUnlock(&tcapMutex);
			}
		break;
		case optCallback:		
			if ( (!argv[4]) ) {
#ifndef TCL_VERSION8DOT6
				interp->result =  " -callback <script>";	
#else
				Tcl_SetObjResult(interp, " -callback <script>");
#endif
				return TCL_ERROR;
			}
			bindingPtr = &(tcapHndlTbl[hndl].tcapCallbackFun);
			if ((argv[4])) {
				if (*bindingPtr) {
					ckfree(*bindingPtr);
					*bindingPtr = NULL;
				}
				if (argv[4][0] != '\0') {
					*bindingPtr = ckstrdup(argv[4]);
				}
			}	
		break;
		case optSampleMethod:    
			val = atoi (argv[4]);
			if ( (val  >= PCAP_SAMP_NOSAMP) && (val <= PCAP_SAMP_FIRST_AFTER_N_MS ) )  {
				Tcl_MutexLock(&tcapMutex);
				tcapHndlTbl[hndl].tcapSampleMethod = val;
				Tcl_MutexUnlock(&tcapMutex);
			} else {
#ifndef TCL_VERSION8DOT6
				interp->result =  " -sam <int> ; range 0-2 ";	
#else
				Tcl_SetObjResult(interp, " -sam <int>; range 0-2");
#endif
				return TCL_ERROR;			
			}
		break;
		case optSampleValue:    
			val = atoi (argv[4]);
			if (val  >= 0 )  {
				Tcl_MutexLock(&tcapMutex);
				tcapHndlTbl[hndl].tcapSampleValue = val;
				Tcl_MutexUnlock(&tcapMutex);
			} else {
#ifndef TCL_VERSION8DOT6
				interp->result =  " -sav <int> ";	
#else
				Tcl_SetObjResult(interp, " -sam <int> ");
#endif
				return TCL_ERROR;			
			}
		break;
		case optIfNumber:    
			val = atoi (argv[4]);
			if (val  >= 0 )  {
				Tcl_MutexLock(&tcapMutex);
				tcapHndlTbl[hndl].tcapIfNumber = val;
				Tcl_MutexUnlock(&tcapMutex);
			} else {
#ifndef TCL_VERSION8DOT6
				interp->result =  " -ifn <int> ";	
#else
				Tcl_SetObjResult(interp, " -ifn <int> ");
#endif
				return TCL_ERROR;			
			}
		break;
		default:
#ifndef TCL_VERSION8DOT6
			interp->result =  "Usage: tcap ?arg arg ...?";	
#else
			Tcl_SetObjResult(interp, "Usage: tcap set <handle> <option> <value>");
#endif
			return TCL_ERROR;
		break;
	}
	//} end of for

	Tcl_MutexLock(&tcapMutex);

	if (tcapHndlTbl[hndl].tcapHndlType != TCAP_FILE) {
  		pcap_close  (tcapHndlTbl[hndl].tcapPcapHndl);
#ifdef WIN32
		if ( (tcapHndlTbl[hndl].tcapPcapHndl  = pcap_open(tcapHndlTbl[hndl].tcapIfID,
				                             tcapHndlTbl[hndl].tcapSnapLen                                                        , 
											 tcapHndlTbl[hndl].tcapCaptureMode ,
                                             tcapHndlTbl[hndl].tcapRdTimeOut ,
											 NULL,
											 errbuf))== NULL)
		{
			Tcl_AppendResult(interp, TCAP_SET_FAILED, argv[2], (char *)NULL);
			Tcl_MutexUnlock(&tcapMutex);
			return TCL_ERROR;
		}
#else
        if((tcapHndlTbl[hndl].tcapPcapHndl = pcap_open_live((char *)tcapHndlTbl[hndl].tcapIfID,
                                                         tcapHndlTbl[hndl].tcapSnapLen                                                        ,
                                                         tcapHndlTbl[hndl].tcapCaptureMode,
                                                         tcapHndlTbl[hndl].tcapRdTimeOut,
                                                         errbuf  )) == NULL )
        {
             Tcl_AppendResult(interp,TCAP_SET_FAILED,argv[2],(char *)NULL);
             return TCL_ERROR;   
        }
#endif
	} else {
		if ( (tcapHndlTbl[hndl].tcapPcapHndl  = pcap_open_offline(
								tcapHndlTbl[hndl].tcapInputFile,	
								errbuf          ) ) == NULL) 
		{
			Tcl_AppendResult(interp, TCAP_SET_FAILED, argv[2], (char *)NULL);
			Tcl_MutexUnlock(&tcapMutex);
			return TCL_ERROR;
		}
	}

	if ( TcapBindFilter(interp, hndl) != TCL_OK) 
		return TCL_ERROR;
	tcapHndlTbl[hndl].tcapStatusFlag |= TCAP_IN_USE;
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
	int retValue;

    if (( argc != 4 )&& ( argc != 6 ) && (argc != 8)) {	
		Tcl_AppendResult(interp, "Error: ", TCAP_INVALID_OPTION, (char *)NULL);
		return TCL_ERROR;
	}

    if(argc == 4){
		if (TcapGetTableKey(tcapOptionTable, argv[2]) == optInFile){    
             retValue = TcapOpenFile(interp, argc, argv);  
		} else if (TcapGetTableKey(tcapOptionTable, argv[2]) == optRemoteHostIp){  
		     retValue = TcapOpenRmtInterface(interp, argc, argv);
	   } else {
		     retValue = TcapOpenInterface(interp, argc, argv);
	   }
	} else {
	   retValue = TcapOpenRmtInterface(interp, argc, argv);
	}
	return retValue;
}

static int TcapOpenFile(Tcl_Interp *interp,int argc, const char *argv[]){
	char errbuf[PCAP_ERRBUF_SIZE],hndlId[3];
    int  i;
	
	for ( i = 0; i < TCAP_HNDL_TABLE_SIZE; i++) {
		if (tcapHndlTbl[i].tcapStatusFlag == 0) {
            Tcl_MutexLock(&tcapMutex);
			TcapHndlInitEntry (i);
			tcapHndlTbl[i].tcapHndlType = TCAP_FILE;
			strcpy(tcapHndlTbl[i].tcapInputFile, argv[3]);
			Tcl_MutexUnlock(&tcapMutex);

			if ((tcapHndlTbl[i].tcapPcapHndl  = pcap_open_offline( argv[3], errbuf) ) == NULL) {
				Tcl_AppendResult(interp, TCAP_FILE_OPEN_FAILED, argv[3], (char *)NULL);
				return TCL_ERROR;
			}
	
            Tcl_MutexLock(&tcapMutex);
			sprintf(errbuf, "%s%d%s", TCAP_HNDL_PREFIX, i, TCAP_DUMP_FILE_SUFFIX);
			strcpy(tcapHndlTbl[i].tcapOutputFile, errbuf);
			tcapHndlTbl[i].tcaphandno = i;
			tcapHndlTbl[i].tcapStatusFlag |= TCAP_IN_USE;
            Tcl_MutexUnlock(&tcapMutex);

			sprintf((char *)hndlId, "%d",  i);
			Tcl_AppendResult(interp, TCAP_HNDL_PREFIX, (char *)hndlId, (char *)NULL);
			return TCL_OK;
		}
	}
       
	if (i >= TCAP_HNDL_TABLE_SIZE) {
		Tcl_AppendResult(interp, TCAP_TOO_MANY_HANDLES, (char *)NULL);
		return TCL_ERROR;
	}

	if (TcapBindFilter (interp, i) != TCL_OK) return TCL_ERROR;
           
    return TCL_OK;
}

static int TcapOpenInterface (Tcl_Interp *interp,int argc, const char *argv[]){
	char errbuf[PCAP_ERRBUF_SIZE];
    int  opt, i, match;
	pcap_if_t *d, *alldevs;
	char	hndlId[7], ipstr[128], ip6str[128];
	pcap_addr_t *a;

	if(pcap_findalldevs(&alldevs, errbuf) == -1) {
		Tcl_AppendResult(interp, TCAP_FIND_DEV_FAILED, (char *)NULL);
		pcap_freealldevs(alldevs);
		return TCL_ERROR;
	} 

	opt = TcapGetTableKey(tcapOptionTable, argv[2]);    
	switch ((enum options) opt) {
	  	  case optIpAddress:   
		    match = IP4_MATCH;
			break;

          case optIfId:
			 match = DEVID_MATCH;
             break;

		  case optIfNumber: 
			match = IFNUM_MATCH;
			break;

          case optIpAddress6:
			match = IP6_MATCH;
			break;

		  default:
			Tcl_AppendResult(interp, TCAP_INVALID_OPTION, argv[3], (char *)NULL);
			pcap_freealldevs(alldevs);
			return TCL_ERROR;
			break;
	}//end of switch


	for ( i = 0; i < TCAP_HNDL_TABLE_SIZE; i++) {
		if (tcapHndlTbl[i].tcapStatusFlag == 0) {
				d = matchInterface(alldevs, match, argv[3]);
				if (!d) {
					Tcl_AppendResult(interp, TCAP_INVALID_IFSPEC, argv[3], (char *)NULL);
					pcap_freealldevs(alldevs);
					return TCL_ERROR;
				}
				Tcl_MutexLock(&tcapMutex);
				tcapHndlTbl[i].tcapSnapLen     = TCAP_MAX_PACKET_SIZE;
				tcapHndlTbl[i].tcapCaptureMode = TCAP_OPENFLAG_PROMISCUOUS;
				tcapHndlTbl[i].tcapRdTimeOut = TCAP_DEFAULT_READ_TIMEOUT; 
				tcapHndlTbl[i].tcapCallbackFun = NULL;
				strcpy(tcapHndlTbl[i].tcapIfID, d->name); 
		        tcapHndlTbl[i].tcapPcapHndl  =  pcap_open((char *)tcapHndlTbl[i].tcapIfID,
				                               tcapHndlTbl[i].tcapSnapLen                                                        , 
											   TCAP_OPENFLAG_PROMISCUOUS,
											   tcapHndlTbl[i].tcapRdTimeOut ,
											   NULL,
											   errbuf);
				Tcl_MutexUnlock(&tcapMutex);

				if ( tcapHndlTbl[i].tcapPcapHndl == NULL ) {
					pcap_freealldevs(alldevs); return TCL_ERROR;
				}

				Tcl_MutexLock(&tcapMutex);
				tcapHndlTbl[i].tcapHndlType = TCAP_NET_INTERFACE;
				sprintf(errbuf, "%s%d%s", TCAP_HNDL_PREFIX, i, TCAP_DUMP_FILE_SUFFIX);
				strcpy(tcapHndlTbl[i].tcapOutputFile, errbuf);
				tcapHndlTbl[i].tcapStatusFlag |= TCAP_IN_USE;
				for(a=d->addresses;a;a=a->next) {
					switch(a->addr->sa_family){
						case AF_INET:
							if (a->addr) {
								strcpy(tcapHndlTbl[i].tcapIfIpAddress, 
									iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr)) ;
								strcpy(tcapHndlTbl[i].tcapIfIpMask,
									iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr) ); 
							} 
						break; 
						case AF_INET6:
							if (a->addr) {
								strcpy(tcapHndlTbl[i].tcapIfIpAddress6,
									ip6tos(a->addr, ip6str, sizeof(ip6str)));
							}
						break;
					}
				}
				tcapHndlTbl[i].tcaphandno = i;
				tcapHndlTbl[i].tcapStatusFlag |= TCAP_IN_USE;
				Tcl_MutexUnlock(&tcapMutex);

				sprintf((char *)hndlId, "%d",  i);
				Tcl_AppendResult(interp, TCAP_HNDL_PREFIX, (char *)hndlId, (char *)NULL);
				pcap_freealldevs(alldevs);
				return TCL_OK;
		}
		else continue;
	}      
	Tcl_AppendResult(interp, TCAP_TOO_MANY_HANDLES, (char *)NULL);
	return TCL_ERROR;
}

static int TcapOpenRmtInterface (Tcl_Interp *interp,int argc, const char *argv[]){
	char errbuf[PCAP_ERRBUF_SIZE], source[TCAP_BUF_SIZE_3000];
    int  opt, i;
	pcap_if_t *d, *alldevs;
	char	hndlId[7], ipstr[128], ifstr[128];
	char	rmtPort[7] = TCAP_REMOTE_PORT;
	int		port, match = IP4_MATCH;

	for(i=2;i<argc-1;i+=2) {
		opt = TcapGetTableKey(tcapOptionTable, argv[i]);
		if (opt == -1) {  
			Tcl_AppendResult(interp, TCAP_INVALID_OPTION, (char *)NULL);
			return TCL_ERROR;
		}
	    switch ((enum options) opt) {
	  		case optRemoteHostIp:  
				strcpy(ipstr, argv[i+1]);
				strcpy(ifstr, ipstr);
	        break;
			case optRemotePort:
				port = atoi(argv[i+1]);
				if ((port > 0) && (port < 65536) )
					strcpy(rmtPort, argv[i+1]);
				else {
					Tcl_AppendResult(interp, TCAP_INVALID_PORT, (char *)NULL);
					return TCL_ERROR;
				}
            break;
	  	  case optIpAddress:  
		    strcpy(ifstr, argv[i+1]);
		    match = IP4_MATCH;
			break;

          case optIfId:
			 strcpy(ifstr, argv[i+1]);
			 match = DEVID_MATCH;
             break;

		  case optIfNumber: 
			strcpy(ifstr, argv[i+1]);
			match = IFNUM_MATCH;
			break;

          case optIpAddress6:
			strcpy(ifstr, argv[i+1]);
			match = IP6_MATCH;
			break;
		  default:
			Tcl_AppendResult(interp, TCAP_INVALID_IFSPEC, argv[i], (char *)NULL);
			return TCL_ERROR;
			break;
	    }//end of switch
	}//end of for

	
	for ( i = 0; i < TCAP_HNDL_TABLE_SIZE; i++) {
		if (tcapHndlTbl[i].tcapStatusFlag == 0) {
				pcap_createsrcstr(source,PCAP_SRC_IFREMOTE,ipstr,rmtPort,NULL,errbuf);
				if( pcap_findalldevs_ex  (source, NULL, &alldevs, errbuf) == -1)
				{
					Tcl_AppendResult(interp,TCAP_FIND_DEV_FAILED, errbuf,(char *)NULL);
					pcap_freealldevs(alldevs);
					return TCL_ERROR;
				}
				d =  matchInterface(alldevs, match, ifstr);
				if (!d) {
					Tcl_AppendResult(interp, TCAP_INVALID_IFSPEC, ipstr, (char *)NULL);
					pcap_freealldevs(alldevs);
					return TCL_ERROR;
				}
				Tcl_MutexLock(&tcapMutex);
				tcapHndlTbl[i].tcapSnapLen     = TCAP_MAX_PACKET_SIZE;
				tcapHndlTbl[i].tcapCaptureMode = TCAP_OPENFLAG_PROMISCUOUS;
				tcapHndlTbl[i].tcapRdTimeOut	= TCAP_DEFAULT_READ_TIMEOUT; 
				tcapHndlTbl[i].tcapCallbackFun = NULL;
				tcapHndlTbl[i].tcapRemotePort = port;


				tcapHndlTbl[i].tcapPcapHndl	= pcap_open(d->name,		
														TCAP_MAX_PACKET_SIZE,				
														TCAP_OPENFLAG_PROMISCUOUS,			
														TCAP_DEFAULT_READ_TIMEOUT+1000,	
														NULL,
														errbuf);	

				if ( tcapHndlTbl[i].tcapPcapHndl == NULL ) {
					Tcl_AppendResult(interp, TCAP_OPEN_ERROR, (char *)NULL);
					return TCL_ERROR;
				}
				   
				strcpy(tcapHndlTbl[i].tcapIfIpAddress,ipstr);
				strcpy(tcapHndlTbl[i].tcapIfID, d->name);
				pcap_freealldevs(alldevs);

				tcapHndlTbl[i].tcapHndlType = TCAP_RMT_INTERFACE;
				sprintf(errbuf, "%s%d%s", TCAP_HNDL_PREFIX, i, TCAP_DUMP_FILE_SUFFIX);
				tcapHndlTbl[i].tcapStatusFlag |= TCAP_IN_USE;
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
		case cmdShow:
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
		case cmdLink:
			rvalue = TcapLinkCmd(interp, argc, argv);
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
