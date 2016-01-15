/*******************************************************************************
*
* Copyright (c) 2016 by Patrick Kutch
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
******************************************************************************/

// starting point from: http://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/

#include<stdio.h>           //For standard things
#include<unistd.h>
#include<stdlib.h>          //malloc
#include<string.h>          //memset
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <argp.h>
#include <stdbool.h>
#include <pthread.h>
#include <inttypes.h>
#include <pcap/pcap.h>
#include <sys/queue.h>

struct packetNode // linked list for holding packets read from PCAP file
{
    unsigned char *data;
    unsigned int length;
    struct packetNode *pNext;
};

struct threadArgs  // goodies for the worker threads
{
    const struct packetNode *pList;
    int packetCount;
    bool SendOutput; 
    int outSock;
};
// function declarations
void ProcessPacket(unsigned char *, int);
void PrintData(unsigned char *, int);
int BindToInterface(char *);
int Process_DevToDev(int, int);
void Process_PcapFileToDev_PreProcessed(const char *fName, int outSock);
void InsertData(unsigned char **pBuffer,  int data_size, const unsigned char *newData,  int new_data_size,  int location, int *newLength);
bool IsVLANTagged(const unsigned char *buffer, int data_size);
bool IsServiceTagged(const unsigned char *buffer, int data_size);
void ManipulatePacket(unsigned char **pBuffer, int data_size, int *new_size);
void InitializeArguments();
bool AlterMAC_Address(unsigned char *pBuffer, int data_size);
bool CheckArguments();
void CreateTag(int EtherType, int Priority, int ID, unsigned char *tagBuffer);
int ReadPCPFile(const char *fName);
struct packetNode * ReadPCAP_Packets(const char *fName);
char* PrintDataToBuffer(unsigned char *data, int Size);
void * BlastPCAPPackets(void *args);
void IncrementRcvCount();
void IncrementSndCount();
unsigned long getRcvCount();
unsigned long getSndCount();

int sock_input,sock_output;
pthread_mutex_t rcvCounterLock;
pthread_mutex_t sndCounterLock;
unsigned long rcvCounter;
unsigned long sndCounter;


// Information for command line goodis
const char *argp_program_version = "V0.1.0c";
const char *argp_program_bug_address = "<http://github.com/PatrickKutch/VNF_Tool>";
static char doc[] = "VNF Tool";
static char args_doc[] = "[FILENAME]...";
static struct argp_option options[] = {
    { "input", 'i', "INPUT File | Device", 0, "PCAP file to read input from or input device" },
    { "number", 'n', "", 0, "number of packets to read from PCAP file, default is all" },
    { "repeat", 'r', "", 0, "number loops to send the packets in the PCAP file" },
    { "output", 'o', "OUTPUT Device", 0, "Outut device." },
    { "ethertype", 'e', "", 0, "EtherType/TPID (HEX)", 1 },
    { "tag", 't', "TAG", 0, "Tag ID (base 10)", 1 },
    { "raw", 'w', "RAW L2 Insert", 0, "Insert Raw L2 data after SRC/Dest MAC (aabbccddeeff)." },
    { "priority", 'p', "TAG", 0, "Priority Tag (1-7 | 'random').", 1 },
    { "source", 's', "SOURCE MAC", 0, "Change Source MAC address (aa:bb:cc:dd:ee:ff)." },
    { "dest", 'd', "DEST MAC", 0, "Change Dest MAC address (aa:bb:cc:dd:ee:ff)." },
    { "gap", 'g', "", 0, "Sleep time between packets when reading from PCAP file in uSeconds, default is 0." },
    { "threadcount",'c',"THREAD COUNT", 0, "Number of simultaneous threads to run." },
    { "verbose", 'v', "", 0, "verbose level 0 - 3." },
    { 0 }
};

// stuct to hold command line arguments
struct arguments
{
    enum
    {PCAP_INPUT_MODE, DEVICE_INPUT_MODE } input_mode;
    enum
    {CONSUME_MODE, DEVICE_OUTPUT_MODE } output_mode;
    enum
    {NONE_MODE, S_TAG_SPECIFIED_PRIORITY_MODE, S_TAG_RANDOM_PRIORITY_MODE, CUSTOM_TAG_MODE } S_Tag_mode;

    char *input;
    char *output;
    char *rawData;
    int Tag;
    int EtherType;
    int Priority;
    bool RandomPriority;
    bool Valid, Checked;
    bool ManipulateData;
    char *srcMac;
    char *dstMac;
    int  rawLength;
    int  RepeatCount;
    int  MaxCount;
    int  sleepTime;
    int  VerboseLevel;
    int  ThreadCount;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = state->input;
    

    switch (key)
    {
    case 'i':
        arguments->input = arg;
        if (access(arg, F_OK) != -1) // is a file?
        {
            arguments->input_mode = PCAP_INPUT_MODE;  // yes
        }
        else
        {
            arguments->input_mode = DEVICE_INPUT_MODE;  // no, is another eth device
        }

        break;

    case 'o':
        arguments->output = arg;
        arguments->output_mode = DEVICE_OUTPUT_MODE;
        break;

    case 't': // Todo - make it so we can handle multiple tags
        arguments->Tag =  (int)strtol(arg, (char **)NULL, 10);
        if (arguments->Tag < 0 || arguments->Tag > 4095)
        {
            printf("Invalid Tag specified: %s\n", arg);
            arguments->Valid = false;
        }
        break;

    case 'r':
        arguments->RepeatCount =  (int)strtol(arg, (char **)NULL, 10);
        if (arguments->RepeatCount <= 0)
        {
            printf("Invalid Repeat Count specified: %s\n", arg);
            arguments->Valid = false;
        }
        break;

    case 'c':
        arguments->ThreadCount =  (int)strtol(arg, (char **)NULL, 10);
        if (arguments->ThreadCount <= 0)
        {
            printf("Invalid Thread Count specified: %s\n", arg);
            arguments->Valid = false;
        }
        break;
    case 'g':
        arguments->sleepTime =  (int)strtol(arg, (char **)NULL, 10);
        if (arguments->sleepTime < 0)
        {
            printf("Invalid sleep time (gap) specified: %s\n", arg);
            arguments->Valid = false;
        }
        break;

    case 'v':
        arguments->VerboseLevel =  (int)strtol(arg, (char **)NULL, 10);
        if (arguments->VerboseLevel <= 0 | arguments->VerboseLevel > 3)
        {
            printf("Invalid verbose level specified: %s\n", arg);
            arguments->Valid = false;
        }
        break;

    case 'n':
        arguments->MaxCount =  (int)strtol(arg, (char **)NULL, 10);
        if (arguments->MaxCount <= 0)
        {
            printf("Invalid number of packets specified: %s\n", arg);
            arguments->Valid = false;
        }
        break;

    case 'e':
        if (0 == sscanf(arg, "%X",  &arguments->EtherType))
        {
            printf("Invalid EtherType/TPID specified: %s\n", arg);
            arguments->Valid = false;
        }
        break;

    case 'w':
        arguments->rawData = arg;
        
    break;

    case 's':
        if (strlen(arg) != 17)
        {
            printf("Invalid Source MAC Address  specified: %s\n", arg);
            arguments->Valid = false;
        }
        else
        {
            arguments->srcMac = arg;
        }
        break;

    case 'd':
        if (strlen(arg) != 17)
        {
            printf("Invalid Destinatation MAC Address  specified: %s\n", arg);
            arguments->Valid = false;
        }
        else
        {
            arguments->dstMac = arg;
        }
        break;

    case 'p':

        if (0 == strncmp(arg, "random", 6))
        {
            arguments->RandomPriority = true;
            srand(time(NULL));  // set random seed, so not always the same
        }
        else
        {
            arguments->Priority = (int)strtol(arg, (char **)NULL, 10);
            if (arguments->Priority < 0 || arguments->Priority > 7)
            {
                printf("Invalid Priority specified: %s\n", arg);
                arguments->Valid = false;
            }
        }
        break;

    case ARGP_KEY_ARG:
        return 0;

    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };
struct arguments arguments;

int main(int argc, char *argv[])
{
    int retVal = 1;

    InitializeArguments();
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    CheckArguments();

    if (arguments.Valid)
    {
        //Create a raw socket that shall sniff
        if (arguments.input_mode == DEVICE_OUTPUT_MODE)
        {
            sock_input = BindToInterface(arguments.input);
            if (sock_input < 0)
            {
                printf("Socket Error\n");
                return 1;
            }
        }

        if (NULL != arguments.output)
        {
            sock_output = BindToInterface(arguments.output);
            if (sock_output < 0)
            {
                printf("Socket Error\n");
                return 1;
            }
        }
        else
        {
            sock_output = 0;
        }
        if (arguments.input_mode == DEVICE_INPUT_MODE)
        {
            retVal = Process_DevToDev(sock_input, sock_output);
        }
        else
        {
            Process_PcapFileToDev_PreProcessed(arguments.input, sock_output);
        }
    }
    return (int)getRcvCount();
}

/*
    Reads data from one device and if specified, manipulates and blasts out
    to another device
*/
int Process_DevToDev(int inpSock, int outSock)
{
    unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
    int data_size;
    int packet_num = 1;
    int new_size;
    struct sockaddr_ll saddr = {0};
    socklen_t saddr_size = sizeof(saddr);
    int loopCountMax = arguments.RepeatCount;
    int loopCount;

    if (loopCountMax < 1)
    {
        loopCountMax = 1;
    }
    else
    {
        printf("Repeating each received packet %d times\n", arguments.RepeatCount);
    }

    while (1)
    {
        //data_size = read(inpSock, buffer, 65536);
        data_size = recvfrom(inpSock,buffer,65536,0,(struct sockaddr*)&saddr, &saddr_size );
        
        if (data_size < 0)
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        if (saddr.sll_pkttype == PACKET_OUTGOING ) // Reading from Raw socket will also read what was just written, resulting in endless loop :-)
        {
            continue;
        }
        IncrementRcvCount();
        
        if (arguments.VerboseLevel > 1)
        {
            printf("\nIncoming[%d]\n", packet_num);
            PrintData(buffer, data_size);
        }
        else if (arguments.VerboseLevel == 1)
        {
            printf("Packets Processed: %d      \r", packet_num);
            fflush(stdout); // otherwise might not print
        }
        if (outSock != 0)
        {
            loopCount = 0;
            while (loopCount < loopCountMax)
            {
                ManipulatePacket(&buffer, data_size, &data_size);
                write(outSock, buffer, data_size);
                if (arguments.VerboseLevel > 1)
                {
                    if (loopCountMax == 1)
                    {
                        printf("\nOutgoing[%d]\n", packet_num); 
                    }
                    else
                    {
                        printf("\nOutgoing[%d: Repeat#:%d]\n", packet_num,loopCount+1); 
                    }
                    PrintData(buffer, data_size);
                }
                loopCount++;
                IncrementSndCount();
            }
        }
        packet_num++;
    }
    close(inpSock);
    printf("Finished"); // not sure why I do this, never reaches here :-)

}

/*
    Reads packets from PCAP file, then spawns threads (potentially) to manipulate and blast
    those packets out
*/
void Process_PcapFileToDev_PreProcessed(const char *fName, int outSock)
{
    int packetCount = 0;
    int processed_Count = 0;
    int loopCount = 0;
    char repeatString[200];
    int processedThisLoopCount = 0;
    unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
    packetCount = ReadPCPFile(fName);
    pthread_t th[arguments.ThreadCount];
    if (packetCount == 0)
    {
        return;
    }
    if (arguments.RepeatCount > 0)
    {
        sprintf(repeatString, ", repeating %d times", arguments.RepeatCount);
    }
    else
    {
        sprintf(repeatString, "");
    }

    if (arguments.MaxCount <= 0)
    {
        printf("Processing %d packet from PCAP file%s. Using %d threads/sessions.\n", packetCount, repeatString,arguments.ThreadCount);
    }
    else
    {
        printf("Processing %d packet from PCAP file that contains %d packets%s\n", arguments.MaxCount, packetCount, repeatString);
    }

    unsigned int pkt_counter = 0;   // packet counter
    unsigned long byte_counter = 0; //total bytes seen in entire trace

    int loopCountMax = arguments.RepeatCount;
    
    if (loopCountMax < 1)
    {
        loopCountMax = 1;
    }

    struct packetNode *pList,*pCurrent;

    pList = ReadPCAP_Packets(fName);

    for (loopCount = 1; loopCount < arguments.ThreadCount; loopCount++)
    {
        pthread_create(&th[loopCount-1],NULL,BlastPCAPPackets,&(struct threadArgs){pList, packetCount, false, outSock});
    }
    
    BlastPCAPPackets(&(struct threadArgs){pList, packetCount, true, outSock});
}

/*
    Blasts packet to the wire from a already loaded PCAP file
*/
void * BlastPCAPPackets(void *pArgs)
{
    const struct threadArgs *args;
    const struct packetNode *pList;
    int packetCount; 
    bool SendOutput; 
    int outSock;
    int loopCount = 0;
    char repeatString[200];
    int processedThisLoopCount = 0;
    unsigned char *buffer;
    int newLength;

    args = (const struct threadArgs*)pArgs;
    pList = args->pList;
    packetCount = args->packetCount;
    SendOutput = args->SendOutput;
    outSock = args->outSock;

    int loopCountMax = arguments.RepeatCount;

    if (loopCountMax < 1)
    {
        loopCountMax = 1;
    }

    const struct packetNode *pCurrent;
    buffer = NULL;
   
    while (loopCount < loopCountMax)
    {
        pCurrent = pList;
        processedThisLoopCount = 0;

        while (pCurrent != NULL) // go throught the linked list and do the deed!
        {
            IncrementSndCount();
            if (buffer != NULL)
            {
                free(buffer);
            }
            buffer = (unsigned char *)malloc(pCurrent->length); //Its Big!
            memcpy(buffer, pCurrent->data, pCurrent->length); // copy into temp buffer for manipulation, probably quite slow

            if (arguments.VerboseLevel > 1 && SendOutput)
            {
                printf("\nFrom PCAP File[%u]\n", getSndCount());
                PrintData(buffer, pCurrent->length);
            }

            if (arguments.VerboseLevel > 1  && SendOutput)
            {
                printf("\nOutgoing[%u]\n", getSndCount());
            }
            else if (arguments.VerboseLevel == 1  && SendOutput)
            {
                printf("Packets Processed: %u      \r", getSndCount());
            }
            ManipulatePacket(&buffer, pCurrent->length, &newLength);
            if (arguments.VerboseLevel > 1  && SendOutput)
            {
                PrintData(buffer, newLength);
            }
            write(outSock, buffer, newLength); 
            if (arguments.MaxCount > 0)
            {
                if (++processedThisLoopCount >= arguments.MaxCount)
                {
                    break;
                }
            }
            usleep(arguments.sleepTime); // may want a rest in between
            pCurrent = pCurrent->pNext;
        }
        loopCount++;

    }
    if (arguments.VerboseLevel == 1  && SendOutput)
    {
        printf("\n");
    }
    
    return NULL;


}

/* 
    go do any required twiddling of data 
*/ 
void ManipulatePacket(unsigned char **pBuffer, int data_size, int *new_size)
{
    unsigned char tBuffer[100];
    int Priority;
    *new_size = data_size;
    if (arguments.ManipulateData)
    {
        if (arguments.srcMac != NULL || arguments.dstMac != NULL)
        {
            AlterMAC_Address(*pBuffer,  data_size);
        }
        if (arguments.EtherType > 0 && arguments.Tag > 0)
        {
            if (arguments.RandomPriority)
            {
                Priority = rand() & 0x007;
            }
            else
            {
                Priority = arguments.Priority; // if static priority, could create the tag once and store for more efficiency
            }
            CreateTag(arguments.EtherType, Priority, arguments.Tag, tBuffer);
            InsertData(pBuffer, data_size, tBuffer,  4,  12, &data_size);
            if (arguments.VerboseLevel > 2)
            {
                printf("Inserting Tag: EtherType[%X] Tag[%d] Priority[%d]\n", arguments.EtherType, arguments.Tag, Priority);
            }
            *new_size = data_size;
        }
        else if (arguments.EtherType != -1) // Ethertype specified, but no Tag, so insert new type
        {
            printf("TODO: Insert new EthType here\n");
        }
        if (arguments.rawData != NULL)
        {
            InsertData(pBuffer,data_size,arguments.rawData,arguments.rawLength,12,&data_size);
            *new_size = data_size;
        }
    }
}



void PrintData(unsigned char *data, int Size)
{
    char *dBuff = PrintDataToBuffer(data, Size);

    printf("%s", dBuff);
    free(dBuff);
}

/*
    Helper routine to blast data to a buffer. Returned buffer needs to be freed
*/
char* PrintDataToBuffer(unsigned char *data, int Size)
{
    FILE *stream;
    size_t streamSize;
    int i,j;

    char *streamBuf;

    stream = open_memstream(&streamBuf, &streamSize);
    for (i = 0; i < Size; i++)
    {
        if (i != 0 && i % 16 == 0)   //if one line of hex printing is complete...
        {
            fprintf(stream, "         ");
            for (j = i - 16; j < i; j++)
            {
                if (data[j] >= 32 && data[j] <= 128)
                    fprintf(stream, "%c", (unsigned char)data[j]); //if its a number or alphabet

                else
                    fprintf(stream, "."); //otherwise print a dot
            }
            fprintf(stream, "\n");
        }

        if (i % 16 == 0)
            fprintf(stream, "   ");

        fprintf(stream, " %02X", (unsigned int)data[i]);

        if (i == Size - 1)  //print the last spaces
        {
            for (j = 0; j < 15 - i % 16; j++) fprintf(stream, "   "); //extra spaces

            fprintf(stream, "         ");

            for (j = i - i % 16; j <= i; j++)
            {
                if (data[j] >= 32 && data[j] <= 128)
                    fprintf(stream, "%c", (unsigned char)data[j]);
                else
                    fprintf(stream, ".");
            }
            fprintf(stream, "\n");
        }
    }

    fflush(stream);

    fclose(stream);
    streamBuf[streamSize] = 0;
    return streamBuf;
}

/*
    Helper routine to setup raw socket for an interface
*/
int BindToInterface(char *device)
{
    //partly nabbed from  http://yusufonlinux.blogspot.com/2010/11/data-link-access-and-zero-copy.html
    int raw;
    struct sockaddr_ll sll;
    struct ifreq ifr;
    struct packet_mreq      mr;

    raw = socket(PF_PACKET, SOCK_RAW, ETH_P_ALL);  // create the socket
    if (raw < 0)
    {
        printf("Socket Error\n");
        return -1;
    }

    bzero(&sll, sizeof(sll));
    bzero(&ifr, sizeof(ifr));

    memset(&mr, 0, sizeof(mr));
    strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
    //copy device name to ifr
    if ((ioctl(raw, SIOCGIFINDEX, &ifr)) == -1)
    {
        perror("Unable to find interface index");
        printf("-->%s\n", device);
        exit(-1);
    }
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    mr.mr_ifindex = ifr.ifr_ifindex;
    mr.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(raw, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)))
    {
        perror("SetSockOpt: ");
        exit(-1);
    }

    if ((bind(raw, (struct sockaddr *)&sll, sizeof(sll))) == -1)  // bind it to the device
    {
        perror("bind: ");
        exit(-1);
    }
    return raw;
}

/*
    Inserts some data into an existing buffer, at a specific location, returning new size
*/
void InsertData(unsigned char **pBuffer,  int data_size, const unsigned char *newData,  int new_data_size,  int location, int *newLength)
{
    unsigned char *newBuffer = (unsigned char *)malloc(650000);
    unsigned char *buffer = *pBuffer;   
    unsigned char *ptrBuf = newBuffer;

    // TODO: someday I should validate the new buffer and the existing buffer :-)

    memcpy(ptrBuf, buffer, location); // copy up to the insert location
    ptrBuf += location; // move pointer
    memcpy(ptrBuf, newData, new_data_size);
    ptrBuf += new_data_size;
    memcpy(ptrBuf, buffer + location, data_size - location); // copy the rest of the data in orig buffer
    *newLength = data_size + new_data_size;
    *pBuffer = newBuffer;
    free(buffer); // free the original memory
}

/*
    Inserts new SRC and/or DEST MAC address, based upon the command line params
*/
bool AlterMAC_Address(unsigned char *pBuffer, int data_size)
{
    if (data_size < 20) // just in case you get a funky buffer
    {
        return false;
    }
    if (arguments.dstMac != NULL)
    {
        memcpy(pBuffer, arguments.dstMac, 6);
        if (arguments.VerboseLevel > 2)
        {
            printf("Modifying Destination MAC\n", arguments.dstMac);
        }
    }
    if (arguments.srcMac != NULL)
    {
        memcpy(pBuffer + 6, arguments.srcMac, 6);
        if (arguments.VerboseLevel > 2)
        {
            printf("Modifying Source MAC\n", arguments.srcMac);
        }
    }
}

/*
    Initialize the arguments structure.
*/
void InitializeArguments()
{
    arguments.input = NULL;

    arguments.input_mode = PCAP_INPUT_MODE;
    arguments.output = NULL;
    arguments.output_mode = CONSUME_MODE;
    arguments.Valid = true;
    arguments.Checked = false;
    arguments.ManipulateData = false;
    arguments.Tag = -1;
    arguments.EtherType = -1;
    arguments.Priority = 0;
    arguments.RandomPriority = false;

    arguments.srcMac = NULL;
    arguments.dstMac = NULL;
    arguments.RepeatCount = 0;
    arguments.MaxCount = -1;
    arguments.VerboseLevel = 0;
    arguments.sleepTime = 0; // really fast!
    arguments.ThreadCount = 1;
    arguments.rawData = NULL;
}

/*
    validate command line args and setup arguments structure
*/
bool CheckArguments()
{
    char printBuffer[1000];
    if (!arguments.Valid)
    {
        return false;
    }
    printf("%s ", doc);
    printf("%s ", argp_program_version);
    printf("%s\n", argp_program_bug_address);

    if (NULL == arguments.input)
    {
        printf("No Input specified\n");
        arguments.Valid = false;
        return false;
    }
    else if (arguments.VerboseLevel > 0)
    {
        printf("Getting input from %s and ", arguments.input);
        if (NULL != arguments.output)
        {
            printf("sending to %s.\n", arguments.output);
        }
        else
        {
            printf("consuming.\n");
        }
    }
    if (arguments.srcMac != NULL) 
    {
        if (arguments.VerboseLevel > 0)
        {
            printf("Changing Source MAC address to: %s\n", arguments.srcMac);
        }
        arguments.ManipulateData = true;

        char *mac = (char *)malloc(6);
        sscanf(arguments.srcMac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
        arguments.srcMac = mac;
    }
    if (arguments.dstMac != NULL)
    {
        if (arguments.VerboseLevel > 0)
        {
            printf("Changing Desination MAC address to: %s\n", arguments.dstMac);
        }
        arguments.ManipulateData = true;

        char *mac = (char *)malloc(6);
        sscanf(arguments.dstMac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
        arguments.dstMac = mac;
    }

    if (arguments.Tag > 0 || true == arguments.RandomPriority)
    {
        if (arguments.EtherType == -1)
        {
            printf("Tag specified, but no EtherType\n");
            arguments.Valid = false;
            return false;
        }
        if (arguments.Priority != 0 && !arguments.RandomPriority) 
        {
            if (arguments.Tag == 0)
            {
                printf("Priority specified, but no Tag.\n");
                arguments.Valid = false;
                return false;
            }
            if (arguments.Tag > 4095)
            {
                printf("Invalid Tag specified.\n");
                arguments.Valid = false;
                return false;
            }
            arguments.ManipulateData = true;
        }
    }
    if (arguments.EtherType >= 0)
    {
        arguments.ManipulateData = true;
        if (arguments.Tag == 0)
        {
            printf("EtherType for Tag specified, but no Tag.\n");
            arguments.Valid = false;
            return false;
        }
        if (arguments.EtherType > 0xFFFF)
        {
            printf("Invalid EtherType/TPID specified.\n");
            arguments.Valid = false;
            return false;
        }
        if (arguments.VerboseLevel > 0)
        {
            if (true == arguments.RandomPriority)
            {
                sprintf(printBuffer, "random");
            }
            else
            {
                sprintf(printBuffer, "%d", arguments.Priority);
            }
            printf("Inserting Tag: EtherType[0x%X] Priority[%s] Tag[%d]\n", arguments.EtherType, printBuffer, arguments.Tag);
        }
    }
    if (arguments.MaxCount > -1)
    {
        if (arguments.input_mode == DEVICE_INPUT_MODE)
        {
            printf("Number of packets specified, but input is from device - ignoring.\n");
        }
    }
    if (arguments.rawData != NULL)
    {
        if (strlen(arguments.rawData) % 2 ==1)
        {
            printf("Raw L2 input data is invalid, must be even number of bytes\n");
            arguments.Valid = false;
            return false;
        }
       printf("Inserting raw L2 Data: [%s]\n",arguments.rawData);
       arguments.ManipulateData = true; 
       int size = strlen(arguments.rawData)/2;
       arguments.rawLength = size;
       char *l2Data = (char *)malloc(size + 1); 
       char data[3];
       int iLoop;
       
       // I'm sure there is a better way to do this       
       for (iLoop =0; iLoop < size;iLoop++)
       {
           strncpy(data,arguments.rawData+iLoop*2,2);
           sscanf(data,"%x", &l2Data[iLoop]);
       }

       l2Data[size+1] = 0;

       arguments.rawData = l2Data;

    }
    if (arguments.ThreadCount < 1) 
    {
    }
    arguments.Checked = true; 
}

void CreateTag(int EtherType, int Priority, int ID, unsigned char *tagBuffer)
{
    memset(tagBuffer, 0xFF, 8); // zero it out, is only 4 bytes
    uint32_t tdata = EtherType << 16 | Priority << 13 |   ID;

    tdata = htonl(tdata);

    memcpy(tagBuffer, &tdata, 4);
}

int ReadPCPFile(const char *fName)
{
    // reference: https://code.google.com/p/pcapsctpspliter/issues/detail?id=6
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE]; //not sure what to do with this, oh well
    unsigned int pkt_counter = 0;   // packet counter
    unsigned long byte_counter = 0; //total bytes seen in entire trace

    //temporary packet buffers
    struct pcap_pkthdr header; // The header that pcap gives us
    const u_char *packet; // The actual packet

    handle = pcap_open_offline(fName, errbuf);   //call pcap library function

    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open pcap file %s: %s\n", fName, errbuf);
        return 0;
    }
    // find out how many packets there are!
    while (packet = pcap_next(handle, &header))
    {
        pkt_counter++;
    }
    pcap_close(handle);

    return pkt_counter;
}

struct packetNode * ReadPCAP_Packets(const char *fName)
{
    pcap_t *handle;
    struct packetNode *pNode;
    struct packetNode *pList = NULL;
    struct packetNode *pCurrent = NULL;
    char errbuf[PCAP_ERRBUF_SIZE]; //not sure what to do with this, oh well
    struct pcap_pkthdr header; // The header that pcap gives us
    const u_char *packet; 
    
    handle = pcap_open_offline(fName, errbuf);   //call pcap library function
    
    while (packet = pcap_next(handle, &header))
    {
        pNode = (struct packetNode *)malloc(sizeof(struct packetNode));
        pNode->length = header.len;
        pNode->data = (unsigned char *)malloc(header.len);
        memcpy(pNode->data, packet, header.len);
        pNode->pNext = NULL;
        if (pList == NULL)
        {
            pList = pNode;
            pCurrent = pNode;
        }
        else
        {
            pCurrent->pNext = pNode;
            pCurrent = pNode;
        }
    }
    pcap_close(handle);
    return pList;
}
void IncrementRcvCount()
{
    pthread_mutex_lock(&rcvCounterLock);
        rcvCounter++;
    pthread_mutex_unlock(&rcvCounterLock);
}
void IncrementSndCount()
{
    pthread_mutex_lock(&sndCounterLock);
        sndCounter++;
    pthread_mutex_unlock(&sndCounterLock);
}

unsigned long getRcvCount()
{
    unsigned long retVal = 0;
    pthread_mutex_lock(&rcvCounterLock);
        retVal = rcvCounter;
    pthread_mutex_unlock(&rcvCounterLock);

    return retVal;
}

unsigned long getSndCount()
{
    unsigned long retVal = 0;
    pthread_mutex_lock(&sndCounterLock);
        retVal = sndCounter;
    pthread_mutex_unlock(&sndCounterLock);

    return retVal;
}

