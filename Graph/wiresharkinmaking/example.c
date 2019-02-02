/***
  Socket Example - livetest.c

  This is an example of a client application that sends plot-data to
  XGraph via a socket.

  It expects to see a socket number on the command-line.
  Otherwise it will use the default socket, 8000.

  Compile:
    Linux:
	cc -O livetest.c -lm -o livetest.exe
    MS-Windows:
        cc -O livetest.c -lm -lws2_32 -o livetest.exe

  Run:		xgraph -x_range 0 100 -y_range 0 1 -soc 8001 &
		livetest.exe 8001

   (It is also convenient to start the two programs in separate windows.)

 ***/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>

#include "soclib.c"

int socnum=8000;


/********************************************************/
/* RAND() - Return a uniform random variate between 0.0 */
/* and 1.0.  If global seed is not set, then it         */
/* initializes it to a known value.                     */
/********************************************************/
int seed=-1;
float RAND()
{
 float pick;
 #ifdef _WIN32
  float RCONST=(float)1.0/(float)RAND_MAX;  /* normalizing constant */
  if (seed<0) { seed = socnum * 5713;  srand(seed); }
  pick = (float) rand() * RCONST;
 #else
  float RCONST=(double)1.0/(double)RAND_MAX;  /* normalizing constant */
  if (seed<0) { seed = socnum * 45713;  srandom(seed); }
  pick = (float) random() * RCONST;
 #endif
 return pick;
}



int main( int argc, char *argv[] )
{
 int k=1, j, num=0;
 char line[8192];
 Socket_record *socrec;

 while (k < argc)	/* Look for socket number to use on the command-line. */
  {
   if (sscanf( argv[k], "%d", &socnum ) != 1)
    {
     printf("Argument '%s' is not integer socket number.\n", argv[k] );
     exit(1);
    }
   k++;
  }

 socrec = Setup_Client_Socket( "", socnum );
 if (socrec == 0)
  {
   printf("Error establishing socket. Client application exiting.\n");
   exit(1);
  }

 printf("Client sending socket data.\n");
 for (j=0; j < 100; j++)
  {
   sprintf(line,"%d	%g\n", j, RAND() );
   Send_Socket( socrec, line );		num++;
  }

 printf(" Client closing socket %d (sent %d-lines).\n", socnum, num );
 Close_Socket( socrec );

 return 0;
}
