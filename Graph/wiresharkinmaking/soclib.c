/***
  SocLibc.c - Convenient functions for simple socket communications. 
 ***/

#include "soclib.h"


#ifdef _WIN32

 /* Setup_client_socket - If successful, returns Socket_record, else 0. */
 /*   If ipaddress == "", then uses local-host. */
Socket_record *Setup_Client_Socket( char *ipaddress, int socnum )
{
 WSADATA wsaData;
 SOCKET ConnectSocket = INVALID_SOCKET;
 struct addrinfo *result=0, hints;
 int iResult;
 char portnum[60];
 Socket_record *socrec;

 // Initialize Winsock
 iResult = WSAStartup( MAKEWORD(2,2), &wsaData );
 if (iResult != 0) { printf("WSAStartup failed 1.\n");  return 0; }

 ZeroMemory( &hints, sizeof(hints) );
 hints.ai_family = AF_UNSPEC;
 hints.ai_socktype = SOCK_STREAM;
 hints.ai_protocol = IPPROTO_TCP;

 if ((ipaddress == 0) || (ipaddress[0] == '\0')) ipaddress = strdup( "localhost" );
 sprintf( portnum, "%d", socnum );
 // Resolve the server address and port
 iResult = getaddrinfo( ipaddress, portnum, &hints, &result );
 if ( iResult != 0 ) { printf("getaddrinfo failed 2.\n");  return 0; }

 ConnectSocket = socket( result->ai_family, result->ai_socktype, result->ai_protocol );
 if (ConnectSocket == INVALID_SOCKET) { printf("socket failed 3.\n");  return 0; }

 // Connect to server.
 iResult = connect( ConnectSocket, result->ai_addr, (int)(result->ai_addrlen) );
 freeaddrinfo(result);
 if (ConnectSocket == INVALID_SOCKET) { printf("Unable to connect to server! 4\n");  return 0; } 
 if (iResult == SOCKET_ERROR)
  { closesocket(ConnectSocket); printf("Unable to connect to server! 5\n");  return 0; }

 socrec = (Socket_record *)malloc( sizeof(Socket_record ) );
 socrec->socnum = socnum;
 socrec->confd = ConnectSocket;
 socrec->status = 1;
 return socrec;
}


void Send_Socket( Socket_record *socrec, char *line )
{ int err;
 if (socrec == 0) { printf("socrec=null. Exiting.\n");  exit(1); }
 if (socrec->status != 1) { printf("Socket %d closed.\n", socrec->socnum );  return; }
printf("Client sending: '%s'\n", line );
 if (strstr( line, "\n" ) == 0) printf("Warning: Sending line on socket with no <cr>.\n");
 err = send( socrec->confd, line, strlen( line ), 0 );
 if (err == SOCKET_ERROR) printf("Socket error 6.\n");
}


void Close_Socket( Socket_record *socrec )
{
 if (socrec == 0) { printf("socrec=null. Exiting.\n");  exit(1); }
 if (socrec->status != 1) { printf("Socket %d already closed.\n", socrec->socnum );  return; }
shutdown( socrec->confd, SD_SEND );
 closesocket( socrec->confd );
 socrec->status = 0;
 WSACleanup();		/* Terminates all sockets. */
}

#else	/* Posix */

 /* Setup_client_socket - If successful, returns Socket_record, else 0. */
 /*   If ipaddress == "", then uses local-host. */
Socket_record *Setup_Client_Socket( char *ipaddress, int socnum )
{
 int k, socfd, confd, so_reuseaddr=1;
 struct sockaddr_in serv_addr;
 char *server_ipaddr="127.0.0.1";
 Socket_record *socrec;

 printf("Client creating socket %d.\n", socnum );

 /* Create the socket of type TCP/IP. */
 socfd = socket( AF_INET, SOCK_STREAM, 0 );
 if (socfd < 0)
  {
   printf("\n Error: Client could not create socket.\n");
   return 0;
  }

 /* Initialize the server_address structure. */
 if (ipaddress[0] == '\0')
  {
   memset( &serv_addr, '0', sizeof(serv_addr) ); 	
	/* Since sin_addr.s_addr is left zero, a way of saying local addr. */
  }
 else
  {
   serv_addr.sin_addr.s_addr = inet_addr( ipaddress );
	/* Alt: serv_addr.sin_addr.s_addr = htonl( INADDR_ANY );  or inet_addr( "91.32.38.2" ); */
   server_ipaddr = strdup( ipaddress );
  }
 serv_addr.sin_family = AF_INET;
 serv_addr.sin_port = htons( socnum ); 

 if (inet_pton(AF_INET, server_ipaddr, &serv_addr.sin_addr) <= 0)	/* Like bind ? */
  {
   printf("\n Client: inet_pton error occured\n");
   return 0;
  }

 printf("Client waiting to connect socket.\n");
 k = 0;
 do	/* If server is not ready, periodically retry until it is. */
  {
   confd = connect( socfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr) );
   if (confd < 0) usleep( 300000 );
  }
 while ((confd < 0) && (k < 100));	/* Wait as long as:  100 * 0.3 seconds = 30 seconds. */
 if (confd < 0)
  {
   printf("\n Error: Client connect Failed.\n");
   return 0;
  }

 socrec = (Socket_record *)malloc( sizeof(Socket_record ) );
 socrec->socnum = socnum;
 socrec->socfd = socfd;
 socrec->confd = confd;
 socrec->status = 1;
 return socrec;
}


void Send_Socket( Socket_record *socrec, char *line )
{
 if (socrec == 0) { printf("socrec=null. Exiting.\n");  exit(1); }
 if (socrec->status != 1) { printf("Socket %d closed.\n", socrec->socnum );  return; }
 send( socrec->socfd, line, strlen( line ), 0 );
}


void Close_Socket( Socket_record *socrec )
{
 if (socrec == 0) { printf("socrec=null. Exiting.\n");  exit(1); }
 if (socrec->status != 1) { printf("Socket %d already closed.\n", socrec->socnum );  return; }
 close( socrec->confd );
 socrec->status = 0;
}

#endif
