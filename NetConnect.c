#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#define NETLINK_LISTEN_PROTOCOL 31
#define FILE_TAG "-f"
#define MAX_NETCONNECT_INPUT 1024
#define MAX_ARCH_MESSAGE_LEN 4096
#define BYTES_READ "bytes_read.txt"

#define MAX_PAYLOAD 1024 /* maximum payload size*/

struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

void cpy_from_file(FILE * file, char * buffer, int max_size);

void main(int argc, char * argv[])
{
    /* this program is command line tool to help us communicate with the kernel 
     * it needs the following arguments to run: 1. filename_to_save_to, 2. message string
       or istead of "message string" have a -f tag, and then filename for input  */
    char * file_name;
    char message[MAX_NETCONNECT_INPUT];
    char * input_file_name;
    FILE * input_file;
    FILE * file;
    FILE * bytes;
    char payload[MAX_PAYLOAD];
    int payload_number = 0;
    int i;
    unsigned long recieved = 0;
    memset(message, 0, MAX_NETCONNECT_INPUT);
    if (argc != 3 && argc != 4) //thired argument is the programs name
    {
        //printf("Wrong parameters supplied. [LEAVING]\n");
        return;
    }
    if (argc == 3)
    {
        //use regular input 
        file_name = argv[1];
        strncpy(message, argv[2], MAX_NETCONNECT_INPUT);
    }
    else if(argc == 4)
    {
        //check if -f tag given
        if (!strcmp(argv[2], FILE_TAG))
        {
            input_file_name = argv[3];
            input_file = fopen(input_file_name, "rt");
            if (!input_file)
            {
                printf("WHAT");
            }
            printf("GOT HERE\n");
            cpy_from_file(input_file, message, MAX_NETCONNECT_INPUT);
            fclose(input_file);

        }
    }
    else {printf ("WRONG PARAMETERS SUPPLIED [LEAVING]\n"); return;}
    file_name = argv[1];

    if (!strstr(file_name,".txt"))
    {
        printf("BAD parameters, file_name needs to be supplied with .txt ending.\n");
        return;
    }

    file = fopen(file_name,"a+");

    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_LISTEN_PROTOCOL);
    if (sock_fd < 0)
        return;

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); /* self pid */

    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; /* For Linux Kernel */
    dest_addr.nl_groups = 0; /* unicast */

    /* message header */
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    strcpy(NLMSG_DATA(nlh), message);

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    printf("Letting kernel know our PID\n");
    sendmsg(sock_fd, &msg, 0);
    printf("Waiting for report from kernel\n");

    //delay to avoid rereading buffer

    recvmsg(sock_fd, &msg, 0);

    if (!strcmp(NLMSG_DATA(nlh),message))
    {
        //delay -> and read again ignoring first
        recvmsg(sock_fd, &msg,0);
        printf("Buffer reread, avoiding crash...\n" );
    }

         //check if empty
    if (strcmp(NLMSG_DATA(nlh),"EMPTY") == 0)
    {
        printf("No data to be read... [LEAVING]\n");
        return;
    }



    payload_number = atoi(NLMSG_DATA(nlh)) / MAX_PAYLOAD;
    if (atoi(NLMSG_DATA(nlh)) % MAX_PAYLOAD != 0)
    {
        payload_number++;
    }

    save_read_bytes(bytes, NLMSG_DATA(nlh));

    printf("Exepecting [%d] bytes in [%d] payloads\n", atoi(NLMSG_DATA(nlh)),payload_number);
    memset(payload, 0, MAX_PAYLOAD);
    memset(NLMSG_DATA(nlh), 0, MAX_PAYLOAD);

    for (i=0; i<payload_number; i++)
    {
        recvmsg(sock_fd, &msg, 0);
        strncpy(payload,NLMSG_DATA(nlh), MAX_PAYLOAD);
        recieved += strlen(payload);
        printf("Recieved [%d] bytes of total [%lu]\n",(int)strlen(payload), recieved);
        fprintf(file,"%s\n",payload);
        memset(NLMSG_DATA(nlh), 0, MAX_PAYLOAD);
        memset(payload, 0, MAX_PAYLOAD);
    }

    printf("OKAY [LEAVING]\n");
    fclose(file);
    close(sock_fd);

}


/* takes open file, and buffer, copies contents of file to buffer */
void cpy_from_file(FILE * file, char * buffer, int max_size)
{

    char temp;
    int counter = 0;
    for (temp = fgetc(file); temp!=EOF && temp!=NULL; temp = fgetc(file))
    {
        counter++;
        if (counter > max_size)
        {
            return;
        }
        else{
            strncat(buffer, &temp, 1);
        }
    }
    return;

}


void save_read_bytes(FILE * file, char * bytes)
{
    file = fopen(BYTES_READ, "w");
    fprintf(file, "%s",bytes );
    fclose(file);
    return;
}
