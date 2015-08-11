#define LINUX
#define MODULE
#define __KERNEL__


//read size from code segment
#define MAX_READ 4196
#define MAX_PATTERN_LEN 1024
#define MAX_COMMAND_LEN 2048
#define COMMAND_SEPARATOR 0x2a
#define PATTERN_SEPARATOR 0x23
#define SIZE_SEPARATOR 0x03

#define SET_WRITE write_cr0( read_cr0() & (~0x10000))
#define SET_READ write_cr0 (read_cr0() | 0x10000)

//netlink defines
#define MSG_BUFFER 8192
#define NETLINK_IO_SIZE 1024
#define STACKED_REPORT_LIMIT 100
#define REPORT_MAX_LEN 1024
#define NETLINK_LISTEN_PROTOCOL 31

//Netlink protocol
#define PULL_REQUEST "PULL"
#define ORDER_MESSAGE "SIZE:"

//Arch to Client comms 
#define UPDATE_RULESET "RULE:"
#define RULESET_MAX_SIZE 2048

#include <linux/kernel.h>
//#include <linux/stdlib.h> needed for atoi :(
#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/time.h>
#include <linux/delay.h> // loops_per_jiffy



unsigned long ** find_sys_call_table(void);
unsigned long ** syscall_table; 

/* CHAR PROCESSING */
char* strstr(const char *str, const char *target);
char * findchr(char * string, char val, int n);
char inArray(char * array, char c);
char * get_string(char * from, char * end);

//write calls 
asmlinkage int  (*original_write) (unsigned int , const char __user * , size_t ); //original pointer of sys_write will be held here
asmlinkage int hooked_write(unsigned int fd, const char __user * buf, size_t count); //this is the hooked write
int hook_write(void);
int unhook_write(void);


//open calls
asmlinkage int (*original_open) (const char * , int , int );
asmlinkage int hooked_open(const char * file, int flags, int mode);
void hook_open(void);
void unhook_open(void);

//sys_execve calls
asmlinkage int (*original_execve) (const char *, char * const, char * const);
asmlinkage int hooked_execve(const char * addr, char * const argv[], char * const envp[]);
void hook_execve(void);
void unhook_execve(void);

//netlink functionallity
int create_netlink(void);
void transfer_reports(void);
void recv_msg(struct sk_buff * msg);
int send_msg(char * payload);
long * check_netguard_header(char * message);
unsigned int get_netguard_header_length(char * message, char * data_start);
char * get_data_from_message(char * message);
void parse_message(char * message);
void relase_input(void);
struct sock * netlink = NULL;
int clientPID = 0;
char nlmessage[NETLINK_IO_SIZE];

/* MESSAGE HANDLING */
char * is_updateruleset(char * message);
int is_pull(char * message);


int first_flag = 0;

//extra-size linked list handling
struct report_node{
	char report[REPORT_MAX_LEN];
	struct string_node * next_report;
};
char sreports[STACKED_REPORT_LIMIT][REPORT_MAX_LEN];
char * readble_report = NULL;
int reports_added_to_stack = 0;
char * ruleset = NULL;
char ruleset_buffer[RULESET_MAX_SIZE];
void add_to_stack(char * report);
void clear_reports(void);
void clear_history(void);
unsigned long long get_stacked_len(void);
struct report_node * first_report = NULL;
struct report_node * last_report = NULL;
void add_to_surplus(char * report); //report is sized at REPORT_MAX_LEN
char * hread_report(void); //frees report from list afterwards
char * sread_report(void); //reads report from the stack
char * get_report(void); //gets report, first tries from stack, else tries from heap
void add_to_surplus_size(int report_size);
void sub_from_surplus_size(int report_size); //updates surplus size (the size of the text itself)
unsigned long long surplus_size = 0;
int place_report(char * buffer, char * report);
char leftovers[REPORT_MAX_LEN];
char failed_payload[NETLINK_IO_SIZE]; //if failed to send over netlink
char * arch_command = NULL;
unsigned int arch_sizer = 0;
long arch_command_length = 0;
//char msg_record[MSG_BUFFER];

//NetGuard functionality
void issue_opened_file_report(char * addr, char * rule, int pid);
void issue_pre_communicative_report(char * addr, int pid);
char * get_time_stamp(void);
void check_pattern(char * fs_addr, char * rules);
char * get_pattern(char * string, char separator);
#define TIME_STAMP_SIZE 20

int client_found = 0;


int start(void)
{
	int i;
	syscall_table = find_sys_call_table(); //save syscall table address
    hook_write();
    hook_open();
    hook_execve();
    clear_history();
    //open netlink
    if (create_netlink())
    {
    	printk("OK!\n");
    }

	return 0; //0 == good, //-1 == fuckup
}


void finish(void)
{
	unhook_write();
	unhook_open();
	unhook_execve();
	netlink_kernel_release(netlink);
    printk("NetGuard Removed\n");

}

//we gonna find the sys call table by looping addresses 
unsigned long **find_sys_call_table() {

    unsigned long ptr;
    unsigned long *p;

    for (ptr = (unsigned long)sys_close; ptr < (unsigned long)&loops_per_jiffy; ptr += sizeof(void *))
    {   
        //looping from sys_close syscall to loops_per_jiffy addresses     
        p = (unsigned long *)ptr;
        if (p[__NR_close] == (unsigned long)sys_close) 
        {
            return (unsigned long **)p;
        }

    }
    return NULL;
}

/* WRITE SYS CALL HOOKING */
int hook_write(void)
{	
	SET_WRITE;
	original_write = (void *)syscall_table[__NR_write];
	syscall_table[__NR_write] = hooked_write;
	SET_READ;
	return 0;
}

int unhook_write(void)
{
	SET_WRITE;
	syscall_table[__NR_write] = original_write;
	SET_READ;
	return 0;
}

asmlinkage int hooked_write(unsigned int fd, const char __user * buf, size_t count) //this is the hooked write
{
	return (*original_write)(fd,buf,count);

}


/* OPEN SYSCALL HOOKING */
void hook_open(void)
{
	SET_WRITE;
	original_open =(void *) syscall_table[__NR_open];
	syscall_table[__NR_open] = hooked_open;
	SET_READ;
	return;
}

void unhook_open(void)
{
	SET_WRITE;
	syscall_table[__NR_open] = original_open;
	SET_READ;
	return;
}

asmlinkage int hooked_open(const char * file, int flags, int mode)
{
	check_pattern(file, ruleset);
	return (*original_open)(file,flags,mode);
}


void hook_execve(void)
{
	SET_WRITE;
	original_execve = (void *) syscall_table[__NR_execve];
	syscall_table[__NR_execve] = hooked_execve;
	SET_READ;
	return; 
}

void unhook_execve(void)
{
	SET_WRITE;
	syscall_table[__NR_execve] = original_execve;
	SET_READ;
	return;
}


asmlinkage int hooked_execve(const char * addr, char * const argv[], char * const envp[])
{
	/* check if files run are suspicious */ 
	return (*original_execve)(addr, argv, envp);
}



/* CHAR PROCESSISNG */ 
char* strstr(const char *str, const char *target)
{
	/* @leetcode.com */
	
  if (!*target) return str;
  char *p1 = (char*)str, *p2 = (char*)target;
  char *p1Adv = (char*)str;
  while (*++p2)
    p1Adv++;
  while (*p1Adv) {
    char *p1Begin = p1;
    p2 = (char*)target;
    while (*p1 && *p2 && *p1 == *p2) {
      p1++;
      p2++;
    }
    if (!*p2)
      return p1Begin;
    p1 = p1Begin + 1;
    p1Adv++;
  }
  return NULL;
}

char * findchr(char * string, char val, int n)
{
	int i;
	int len;

	len = strlen(string);

	for (i=0; i<n && i<len; i++)
	{
		if (string[i] == val)
		{
			return &string[i];
		}
	}
	return NULL;
}


/* Used to see if char is in array
   Uses strlen */
char inArray(char * array, char c)
{
	int len,i;
	len = strlen(array);

	for (i=0; i<len; i++)
	{
		if (array[i] == c)
		{
			return 1;
		}
	}
	return 0;
}


/* This function returns pointer to a buffer containing a string that ends either with a given parameters or is null turminated
   Uses strlen & strcat DECAPITATED */ 
char * get_string(char * from, char * end)
{
	int len,i;
	char buffer[MAX_PATTERN_LEN + 1];
	len = strlen(from);
	memset(buffer, 0, MAX_PATTERN_LEN);

	for (i=0; i<len; i++)
	{
		if (!inArray(end, from[i]))
		{
			//add to buffer
			strncat(buffer, &from[i],1);
		}
		else 
		{
			//end
			return buffer;
		}
	}
	return NULL;
}

/* This function gets a pointer to a pointer to start of new rule, and returns a buffer with it 
    returns NULL if no more rules */ 
char * get_pattern(char * string, char separator)
{
	int len, i;
	char buffer[MAX_PATTERN_LEN + 1];
	memset(buffer, 0, MAX_PATTERN_LEN + 1);
	len = strlen(string); //check rule 
	//return NULL;
	if (len > 1)
	{
		for (i=0; i<len && i<=MAX_PATTERN_LEN; i++)
		{
			//printk(" WOW %c !!!\n",*(*current_rule + i ));
			if (string[i] == separator)
			{
				//update pointer
				return buffer;
			}
			else
			{
				//copy character
				strncat(buffer,&string[i], 1);
			}
		}
	}
	return NULL;
}
/* END CHAR PROCESSING */ 


/* NETLINK FUNCTIONALITY */
int create_netlink(void)
{
	/* creates netlink socket using global sock struct */

	struct netlink_kernel_cfg cfg = {
		.groups = 1,
		.input = recv_msg,
	};

	netlink = netlink_kernel_create(&init_net, NETLINK_LISTEN_PROTOCOL, &cfg);
	
	if (!netlink)
	{
		return 1;
	}
	else
	{
		return 0;
	}

}

void  recv_msg(struct sk_buff * msg)
{
	/* our architecture does not require kernel module to recieve data
	 * But we need to know the PID of our process, we will use recv_msg to get it 
	 * New stuff: every msg has a header "<total_transmission_length><message_sequence_number><total_messages_num><DATA>"
	 * if PULL message is recieved no buffer is allocated and the report are transfered*/
	 char msg_buf[NETLINK_IO_SIZE];
	 char * msg_data;
	 unsigned int transmission_size; 
	 struct nlmsghdr * net_header;
	 long * netguard_header;
	 int i;
	 long trans_len, msg_num, seq_size;
	 net_header = (struct nlmsghdr *)msg->data;
	 memset(msg_buf, 0, NETLINK_IO_SIZE);
	 clientPID = net_header->nlmsg_pid;

	 strncpy(msg_buf,(char *) NLMSG_DATA(net_header), strlen( NLMSG_DATA(net_header)));
	 printk("recv_msg called with: [%s]\n",msg_buf);
	 //check the header
	 netguard_header = check_netguard_header(msg_buf);
	 trans_len = netguard_header[0];
	 msg_num = netguard_header[1];
	 seq_size = netguard_header[2];
	 if (netguard_header == NULL)
	 {
	 	printk("COMONN\n");
	 	return; //bad header
	 }
	 //allocate buffer at the size of <total_transmission_length> aka netguard_header[0] if none existent already
	 //printk("the numbers: [%lo], 1: [%lo], 2: [%lo] \n",netguard_header[0], netguard_header[1], netguard_header[2]);
	 if (!arch_command)
	 {
	 	arch_command = (char *) kmalloc (trans_len + 1, GFP_KERNEL); //for null terminator
	 	//memset(arch_command, 0, trans_len + 1);
	 	arch_command_length = netguard_header[0];

	 	//clean arch_Command
	 	for (i=0; i<=trans_len; i++)
	 	{
	 		arch_command[i] = 0;
	 	}
	 }
	 msg_data = get_data_from_message(msg_buf);
	 if ((strlen(msg_data) + arch_sizer) > arch_command_length)
	 {
	 	//bad message - leave arch commnad as is, but don't copy the message
	 	return;
	 }else
	 {
	 	strncat(arch_command, msg_data, strlen(msg_data));
	 	arch_sizer += strlen(msg_data);
	 }
	 //check if this was last message
	 //printk("netguard_header1 [%lo] and netguard_header2 [%lo]\n", msg_num, seq_size);
	 if (msg_num == seq_size)
	 {

	 	//last message
	 	//parse
	 	parse_message(arch_command);

	 }
	 return;
}
 
/* checks if header is correct, returns pointer header seprated to long array */
long * check_netguard_header(char * message)
{
	//header is three numbers, 6 byte each in decimal base with zero filling
	char string_numbers[3][7];
	int i;
	long header_numbers[3];
	char * last_ptr = message;
	int kstrtol_res = 0;
	//printk("the message [%s]\n",message);
	for (i=0; i<3; i++)
	{
		memset(string_numbers[i], 0 ,7);
	}
	for (i=0;i<3;i++)
	{
		strncpy(string_numbers[i],last_ptr, 6);
		last_ptr += 6;
	
	}
	
	for (i=0;i<3;i++)
	{
		kstrtol_res = kstrtol(string_numbers[i], 10, &header_numbers[i]);
		if (kstrtol_res != 0)
		{
			printk("bad kstrtol to: [%s]\n", string_numbers[i]);
			return NULL;
		}
	}
	return header_numbers;
	/*

	//find the three number and check that they strtol properly
	for (i=0; i<3; i++)
	{
		if (i==0)
		{
			//take first number
			last_number_found = &message[0];
		}
		else
		{
			last_number_found = strstr(last_number_found,0x20);
			last_number_found++; //point to new number
		}
		kstrtol_res = strict_strtol(last_number_found, 10, &header_numbers[i]);
		printk("last number found [%s]\n", last_number_found);
		if (kstrtol_res != 0)
		{
			printk("kstrtol is not 0: [%d]\n", kstrtol_res);
			return NULL; //BAD HEADER
		}
	}
	return header_numbers;*/
}

unsigned int get_netguard_header_length(char * message, char * data_start)
{
	unsigned int i;
	char * ptr;
	ptr = message;
	for (i=0; ptr != data_start; ptr++, i++);
	return i;

}
char * get_data_from_message(char * message)
{
	//find fist three spaces
	return &message[18];
}

void parse_message(char * message)
{
	char * rule_holder = NULL;
	if (is_pull(message))
	{
		relase_input();
		transfer_reports();
	}
	rule_holder = is_updateruleset(message);
 	if (rule_holder)
 	{
 		strncpy(ruleset_buffer, &rule_holder[5], RULESET_MAX_SIZE);
 		ruleset = ruleset_buffer;
 		relase_input();
 	}
}

void relase_input(void)
{
	kfree(arch_command);
 	arch_command = NULL;
 	arch_sizer = 0;
 	arch_command_length = 0;
}

int send_msg(char * payload)
{
	/* sends all nlmessage buffer, and surplus if there is any
	 * first payload contains the number of bytes expected
	 * second message and on, contain the actual payload
	 * returns 2 if the message sent was the size header */
	struct nlmsghdr * net_header;
	struct sk_buff * msg_out; 
	int sent_flag;
	memset(nlmessage, 0, NETLINK_IO_SIZE);
	
	
	strncpy(nlmessage, payload, NETLINK_IO_SIZE);

	msg_out = nlmsg_new(NETLINK_IO_SIZE, 0);
	nlmessage[NETLINK_IO_SIZE-1] = "\0";
	if (first_flag == 2 || first_flag == 3 || first_flag == 4)
	{
		printk("BAJESUS: [%d] payload len [%d]\n", strlen(nlmessage), strlen(payload));
		//first_flag += 1;
	}
	first_flag += 1;

	if (!msg_out)
	{
		printk("COULDN'T ALLOCATE NEW HEADER! \n");
		return 0;
	}

	net_header = nlmsg_put(msg_out, 0, 0, NLMSG_DONE, NETLINK_IO_SIZE, 0);
	NETLINK_CB(msg_out).dst_group = 0;
	strncpy(nlmsg_data(net_header), nlmessage, NETLINK_IO_SIZE);
	printk("sending to [%d] clientPID\n", clientPID);
	sent_flag = nlmsg_unicast(netlink, msg_out, clientPID);

	if (sent_flag == 11 || sent_flag == -11)
	{
		//deadlock, retry
		printk("Deadlock... stop transmition\n");
		return -11;
	}
	//empty buf after sending
	memset(nlmessage, 0, NETLINK_IO_SIZE);
	return sent_flag;
}
/* NETLINK END */


/* REPORT HANDLING */

void transfer_reports(void)
{
	/* this function uses send_msg to transfer all the data stored */
	int chunk_num=0, i;
	char * report, payload[NETLINK_IO_SIZE];
	memset(leftovers,0, REPORT_MAX_LEN);
	if (reports_added_to_stack == 0)
	{
		//send_msg(payload);
		return;
	}
	if (strlen(failed_payload) > 0)
	{
		chunk_num++;
	}
	chunk_num = (get_stacked_len()+ surplus_size) / NETLINK_IO_SIZE;
	if ((get_stacked_len() + surplus_size) % NETLINK_IO_SIZE != 0)
	{
		chunk_num++;
	}
	//send size
	sprintf(payload,"%lu",get_stacked_len()+surplus_size+strlen(failed_payload));
	send_msg(payload);
	printk("sent [%d] size\n", get_stacked_len()+surplus_size);
	memset(payload,0, NETLINK_IO_SIZE);

	if (strlen(failed_payload) > 0)
	{
		if (send_msg(failed_payload) == -11)
		{
			//failed again
			//leave report in failed section, abort
			return;
		}
		else
		{
			//reset failed report
			memset(failed_payload,0,NETLINK_IO_SIZE);
		}
	}
	//fill chunks and send
	for (i=0; i<chunk_num; i++)
	{
		while ((report = get_report()) != NULL)
		{
			//printk("FINISHED groups etting report: [%s]\n",report);
			if (place_report(payload, report))
			{
				if (send_msg(payload) == -11) //deadlock error
				{
					//stop transmition, save payload in failed
					strncpy(failed_payload, payload, NETLINK_IO_SIZE);
					return;
				}
				memset(payload, 0, NETLINK_IO_SIZE);
				continue;
			}
		}
		//finished all reports, but chunk is not completly full
		//printk("FINISHED FILLING PAYLOAD: [%s]\n",payload);
		if (strlen(payload) != 0)
		{
			if (send_msg(payload) == -11) //deadlock error
			{
				//stop transmition, save payload in failed
				strncpy(failed_payload, payload, NETLINK_IO_SIZE);
				return;
			}
		}
	}
	clear_history();
}

void issue_opened_file_report(char * addr, char * rule, int pid)
{
	//sofa rocks. kernel sucks.
	char buf[REPORT_MAX_LEN];
	char time_stamp[TIME_STAMP_SIZE];
	strncpy(time_stamp, get_time_stamp(), TIME_STAMP_SIZE);
	memset(buf, 0, REPORT_MAX_LEN);
	printk("RULE: [%s]\n",rule);
	sprintf(buf, "Yopel,FILE,%s,%s,%d,%s\n",rule, addr, pid, time_stamp);
	if (reports_added_to_stack == STACKED_REPORT_LIMIT)
	{
		add_to_surplus(buf);
		return;
	}
	add_to_stack(buf);
}

void issue_pre_communicative_report(char * addr, int pid)
{
	char buf[REPORT_MAX_LEN];
	char time_stamp[TIME_STAMP_SIZE];
	strncpy(time_stamp, get_time_stamp(), TIME_STAMP_SIZE);
	memset(buf, 0, REPORT_MAX_LEN);
	sprintf(buf, "PRERULE,FILE,%s,%d\n",addr, pid);
	if (reports_added_to_stack == STACKED_REPORT_LIMIT)
	{
		add_to_surplus(buf);
		return;
	}
	add_to_stack(buf);
}


void add_to_stack(char * report)
{
	/* adds report to stack, SHOULD ONLY BE CALLED IF SREPORTS ISN'T FULL! */
	if (readble_report == NULL)
	{
		//set first sreport to point to new report
		readble_report = sreports[0];
		strncpy(readble_report,report,REPORT_MAX_LEN);
		//printk("ADDED FIRST REPORT [%s]\n",readble_report);
		reports_added_to_stack++;
		return;
	}
	readble_report = sreports[reports_added_to_stack]; //point to new string
	strncpy(readble_report, report, REPORT_MAX_LEN);
	reports_added_to_stack++;
	//printk("ADDED LAST REPORT [%s]\n",readble_report);
}

//linked list report surplus handling 
void add_to_surplus(char * report)
{
	/* adds a report to the list */
	struct report_node * new;

	if (first_report == NULL)
	{
		new = (struct report_node *) kmalloc(sizeof(struct report_node), GFP_KERNEL);
		//copy data
		memset(new->report, 0, REPORT_MAX_LEN);
		strncpy(new->report,report,REPORT_MAX_LEN);
		add_to_surplus_size(strlen(report));
		new->next_report = NULL;
		first_report = new;
		last_report = new;
		return; 
	}
	else 
	{
		new = (struct report_node *) kmalloc(sizeof(struct report_node), GFP_KERNEL);
		//copy data
		memset(new->report, 0, REPORT_MAX_LEN);
		strncpy(new->report,report,REPORT_MAX_LEN);
		add_to_surplus_size(strlen(report));
		new->next_report = NULL;
		last_report->next_report = new;
		last_report = new; 
		return;
	}
}
char * hread_report(void)
{	
	/* returns pointer to a static buffer containing the report 
	 * reads from the begining, setting the next as the first and freeing the previous
	 * returns one report every time */

	char report_buffer[REPORT_MAX_LEN];
	struct report_node * temp_ptr; 
	if (first_report == NULL)
	{
		return NULL;
	} 
	else
	{
		memset(report_buffer, 0, REPORT_MAX_LEN);
		strncpy(report_buffer, first_report->report, REPORT_MAX_LEN);
		sub_from_surplus_size(strlen(report_buffer));
		if (last_report == first_report)
		{
			kfree(first_report);
			last_report = NULL;
			first_report = NULL;
			return report_buffer;
		}
		else
		{
			temp_ptr = first_report;
			first_report = temp_ptr->next_report;
			kfree(temp_ptr);
			return report_buffer;
		}
	}
	return NULL;
} 

char * sread_report(void)
{
	/* reads from sreports and clears array
	 * first_sreport points to first readble string
	 * last_sreport points to the last one */ 
	char * NULLRET = NULL;
	char report[REPORT_MAX_LEN];
	int holder;
	memset(report,0,REPORT_MAX_LEN);
	if (readble_report == NULL)
	{
		//no reports
		return NULLRET;
	}
	else if (readble_report == sreports[0])
	{
		//last report
		strncpy(report, readble_report, REPORT_MAX_LEN);
		memset(readble_report, 0, REPORT_MAX_LEN);
		readble_report = NULL;
		reports_added_to_stack--;
		return report;
	} 
	else
	{
		strncpy(report,readble_report,REPORT_MAX_LEN);
		memset(readble_report, 0, REPORT_MAX_LEN);
		readble_report = sreports[reports_added_to_stack - 2]; //decrement readble_report
		reports_added_to_stack--;
		return report;
	}
	

}

char * get_report(void)
{
	/* this function returns a pointer to a buffer containing a report
	 * uses both stack and heap data structures, returns NULL if no report was found */ 
	char * report;

	if ((report = sread_report()) != NULL)
	{
		return report;
	}
	else if ((report = hread_report()) != NULL)
	{
		return report;
	} else {
		return NULL;
	}
}

void add_to_surplus_size(int report_size)
{
	surplus_size += report_size;
}
void sub_from_surplus_size(int report_size)
{
	surplus_size -= report_size;
}

int place_report(char * buffer, char * report)
{
	/* handles chunk splitting 
	 * returns 1 when chunk is full */
	int bytes_left;
	if (strlen(leftovers))
	{
		//assume new chunk on account of leftovers
		strcpy(buffer,leftovers);
		memset(leftovers, 0, REPORT_MAX_LEN);
	}

	bytes_left = NETLINK_IO_SIZE - strlen(buffer);

	if (bytes_left >= strlen(report))
	{
		//copy whole report into buffer
		strncat(buffer,report,REPORT_MAX_LEN);
		if (strlen(buffer) == NETLINK_IO_SIZE)
		{
			return 1;
		}
		else {
			//printk("GOT HERE! len: [%d]\n",strlen(buffer));
			return 0;
		}
	}
	else if (bytes_left > 0)
	{
		strncat(buffer, report, bytes_left);
		//copy rest to leftovers
		strncpy(leftovers, &report[bytes_left], REPORT_MAX_LEN);
		return 1;

	}
}

unsigned long long get_stacked_len()
{
	unsigned long long ret = 0;
	int i;
	for (i=0;i<reports_added_to_stack; i++)
	{
		ret += strlen(sreports[i]);

	}
	//printk("ret: [%d]\n",ret);
	return ret;
}


void clear_reports(void)
{
	int i;
	for (i=0; i<STACKED_REPORT_LIMIT; i++)
	{
		memset(sreports[i],0,REPORT_MAX_LEN);
	}
}

void clear_history(void)
{
	memset(nlmessage,0,NETLINK_IO_SIZE);
	memset(failed_payload,0, NETLINK_IO_SIZE);
	readble_report = NULL;
	clear_reports();
	reports_added_to_stack = 0;
	first_report = 0;
	last_report = 0;
	clientPID =0;
	client_found =0;
	surplus_size =0;
}

/* REPORT HANDLING END */

/* MISC */
char * get_time_stamp(void)
{	
	/* returns pointer to static buffer containing time stamp
	 * format: dd/mm/yyyy HH:MM:SS */
	char time_stamp[TIME_STAMP_SIZE];
	memset(time_stamp, 0, TIME_STAMP_SIZE);
	struct tm time; 
	struct timeval tv;
	unsigned long offset;
	do_gettimeofday(&tv);
	offset = (tv.tv_sec - (sys_tz.tz_minuteswest * 60));
	time_to_tm(tv.tv_sec, offset, &time);
	sprintf(time_stamp,"%02d/%02d/%04d %02d:%02d:%02d",time.tm_mday + 4, time.tm_mon, time.tm_year + 1855, time.tm_hour + 9, time.tm_min, time.tm_sec);
	return time_stamp;

}
/* MISC END */

/* MESSAGE HANDLING */

/* this function returns pointer to start of command if the string contains an order to update rule set 
 * It should recieve */
char *  is_updateruleset(char * message)
{
	char * ptr = NULL;
	char buffer[MAX_COMMAND_LEN];
	char separator = COMMAND_SEPARATOR;
	memset(buffer, 0, MAX_COMMAND_LEN);
	//printk("GOT TO FUNCTION\n");
	ptr = strstr(message, UPDATE_RULESET);
	if (ptr)
	{
		//printk("Succes [%s] \n",get_string(ptr, &separator));
		strncpy(buffer, ptr, MAX_COMMAND_LEN ); //every transmission has one command
		return buffer;
	}
	//printk("Not found\n!");
	return NULL;
}

int is_pull(char * message)
{
	if (strlen(message) == 4 && !strcmp(message, PULL_REQUEST))
	{
		return 1;
	}
	else
	{
		return 0;
	}
}
/* MESSAGE HANDLING */ 


/* PATTERN PARSING */
/* this function checks incoming open request for all paterns
 * if it recieves null pointer (ruleset) it loggs with a special tag */ 
void check_pattern(char * fs_addr, char * rules)
{

	char * found;
	char found_buffer[MAX_PATTERN_LEN];
	int cur_start = 0;
	char separator = PATTERN_SEPARATOR;
	//set current rule to start
	memset(found_buffer,0,MAX_PATTERN_LEN);
	if (rules == NULL)
	{
		issue_pre_communicative_report(fs_addr, current->pid); //no rules defined yet
		return;
	}


	for (found = get_pattern(&rules[cur_start], separator); found!=NULL; found = get_pattern(&rules[cur_start], separator))
	{
		cur_start += strlen(found) + 1;
		if (strstr(fs_addr, found))
		{
			strncpy(found_buffer, found, MAX_PATTERN_LEN);
			issue_opened_file_report(fs_addr, found_buffer, current->pid);
			memset(found_buffer, 0, MAX_PATTERN_LEN);
		}
	}

}



/* MODULE SETTINGS */
module_init(start);
module_exit(finish);

MODULE_LICENSE("GPL");
/* MODULE SETTINGS END */
