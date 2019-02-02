/***
  SocLib.h - Header file for convenient socket communications.
 ***/

#ifdef _WIN32

 #define _WIN32_WINNT 0x501
 #define WIN32_LEAN_AND_MEAN
 #include <winsock2.h>
 #include <ws2tcpip.h>
 #include <stdlib.h>
 #include <stdio.h>

 typedef struct socket_record Socket_record;
 struct socket_record
  {
   int socnum, status;
   SOCKET confd;
  };

#else	/* Posix */

 #include <sys/socket.h>
 #include <sys/types.h>
 #include <netinet/in.h>
 #include <netdb.h>
 #include <unistd.h>
 #include <errno.h>
 #include <arpa/inet.h> 

 typedef struct socket_record Socket_record;
 struct socket_record
  {
   int socnum, socfd, confd, status;
  };

#endif


 /* Function Prototypes: */

  /* Setup_client_socket - If successful, returns Socket_record, else 0. */
  /*   If ipaddress == "", then uses local-host. */
 Socket_record *Setup_Client_Socket( char *ipaddress, int socnum );

  /* Send data over socket. */
 void Send_Socket( Socket_record *socrec, char *line );
 
  /* Close socket. */
 void Close_Socket( Socket_record *socrec );

