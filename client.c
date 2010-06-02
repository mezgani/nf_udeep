#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct rcnphdr{
   unsigned short int version;
   unsigned short int port;
   unsigned short int id;
   char mode[16];
   char comm[16];
   char data[64]; 
};


int main(int argc, char**argv)
{
   int sockfd,n;
   struct rcnphdr packet;
   struct sockaddr_in servaddr;
   char s[102];

   bzero(&packet,sizeof(packet));

   packet.version = 1;
   packet.port    = 88;
   packet.id      = 2922;

   strncpy(packet.mode, "COMMAND", 7);
   strncpy(packet.comm, "ADD", 3);
   strncpy(packet.data, "HTTP",4);

   if (argc != 2)
   {
      printf("usage:  %s  <IP address>\n", argv[0]);
      exit(1);
   }

   sockfd=socket(AF_INET,SOCK_DGRAM,0);

   bzero(&servaddr,sizeof(servaddr));
   servaddr.sin_family = AF_INET;
   servaddr.sin_addr.s_addr=inet_addr(argv[1]);
   servaddr.sin_port=htons(8888);

   sendto(sockfd, &packet, sizeof(packet),0,
             (struct sockaddr *)&servaddr,sizeof(servaddr));
   close(sockfd);
}
