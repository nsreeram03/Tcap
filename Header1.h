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


static int TcapOpenInterface(Tcl_Interp *interp,int argc, const char *argv[]){

	return TCL_OK;

}


static int TcapOpenRInterface(Tcl_Interp *interp,int argc, const char *argv[]){

	return TCL_OK;

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
		if (tcapHndlTbl[i].tcapStatusFlag == 0) {
                  	Tcl_MutexLock(&tcapMutex);
			tcapHndlTbl[i].tcapSnapLen     = TCAP_MAX_PACKET_SIZE;
			tcapHndlTbl[i].tcapCaptureMode = TCAP_OPENFLAG_PROMISCUOUS;
			tcapHndlTbl[i].tcapRdTimeOut = TCAP_DEFAULT_READ_TIMEOUT;
			tcapHndlTbl[i].tcapCallbackFun = NULL;
			Tcl_MutexUnlock(&tcapMutex);

			if (!fileFlag) {
#ifdef WIN32   
		       tcapHndlTbl[i].tcapPcapHndl  =  pcap_open((char *)tcapHndlTbl[sel].tcapIfID,
				                               tcapHndlTbl[i].tcapSnapLen                                                        , 
											   TCAP_OPENFLAG_PROMISCUOUS,
											   tcapHndlTbl[i].tcapRdTimeOut ,
											   NULL,
											   errbuf);
#else         
       
               tcapHndlTbl[i].tcapPcapHndl = pcap_open_live((char *)tcapHndlTbl[sel].tcapIfID,
                                                  tcapHndlTbl[i].tcapSnapLen                                                        ,
                                                  tcapHndlTbl[i].tcapCaptureMode,
                                                  tcapHndlTbl[i].tcapRdTimeOut,
                                                  errbuf        );
               tcapHndlTbl[i].libDHndl = libnet_init(LIBNET_LINK,tcapHndlTbl[sel].tcapIfID,errbuf); 
                                       
#endif 
				 
			} else {
				Tcl_MutexLock(&tcapMutex);
				strcpy(tcapHndlTbl[i].tcapInputFile, argv[3]);
				Tcl_MutexUnlock(&tcapMutex);
				if ((tcapHndlTbl[i].tcapPcapHndl  = pcap_open_offline( argv[3], errbuf) ) == NULL) {
					Tcl_AppendResult(interp, TCAP_FILE_OPEN_FAILED, argv[3], (char *)NULL);
					return TCL_ERROR;
				}
			}
		   	if ( tcapHndlTbl[i].tcapPcapHndl == NULL )  return TCL_ERROR;
			if (fileFlag) {		
                Tcl_MutexLock(&tcapMutex);
			    tcapHndlTbl[i].tcapHndlType = TCAP_FILE;
			    strcpy(tcapHndlTbl[i].tcapInputFile, argv[3]);
                Tcl_MutexUnlock(&tcapMutex);			
			}
			else {
                Tcl_MutexLock(&tcapMutex);
				tcapHndlTbl[i].tcapHndlType = TCAP_INTERFACE;
                Tcl_MutexUnlock(&tcapMutex);
			}
            Tcl_MutexLock(&tcapMutex);
			sprintf(errbuf, "%s%d%s", TCAP_HNDL_PREFIX, i, TCAP_DUMP_FILE_SUFFIX);
			strcpy(tcapHndlTbl[i].tcapOutputFile, errbuf);
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