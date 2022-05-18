#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#define MAX 505

typedef struct Pcap
{
    unsigned int timesec;
    unsigned int timeusec;
    unsigned int capLength;
    unsigned int length;
} Pcap;

typedef struct PcapTime
{
    struct tm *cTime;
    unsigned int timeusec;
} Ptime;

typedef struct Mac
{
    unsigned char destMac[6];
    unsigned char sourceMac[6];
    unsigned char type[2];
}Mac;

typedef struct IpV6Header
{
    unsigned char version; 
    unsigned char trafficClass; 
    unsigned int flowLabel; 
    unsigned short int payloadLength;
    unsigned char nextHeader; 
    unsigned char hopLimit; 
    unsigned char sourceAddr[16]; 
    unsigned char destAddr[16]; 
}Ipv6;


typedef struct TcpHeader{
    unsigned short sourcePort;
    unsigned short destPort;
    unsigned int seqNumber;
    unsigned int ackNumber;
    unsigned char hLen;
    unsigned char reserved;
    unsigned char urg;
    unsigned char ack;
    unsigned char psh;
    unsigned char rst;
    unsigned char syn;
    unsigned char fin;
    unsigned short windowSize;
    unsigned short checkSum;
    unsigned short urgentPointer;
    unsigned int payLoadSize;
    unsigned char optionLength;
    unsigned char option[45];
}Tcp;


typedef struct UdpHeader{
    unsigned short sourcePort;
    unsigned short destPort;
    unsigned short totalLength;
    unsigned short checkSum;
    unsigned int payLoadSize;
}Udp;

bool fileRead = true;
bool ipV6 = false;
char* optionArr[50] = {};
int readCount = 0, maxTcpSize =0, maxUdpSize=0, optionCnt=0;
void pcapParsing(FILE *file);
Ptime timeConvert(unsigned int timesec, unsigned int timeusec);
Mac secondLayer(char *buffer);
Ipv6 analyzeV6(char *buffer);
Tcp analyzeTcp(char *buffer, int lastIndex);
Udp analyzeUdp(char *buffer, int lastIndex);
unsigned char convertEndian(char data);
void applicationType(unsigned short sourcePort, unsigned destPort, char type);
Pcap pHeader[MAX];
int main(int argc, char *argv[])
{
    char* fname = argv[1];
    FILE *file = fopen(fname, "rb");
    if (file == NULL)
    {
        printf("couldn't read the file\n");
        fileRead = false;
    }
    if (fileRead) pcapParsing(file);
    fclose(file);
    return 0;
}

void pcapParsing(FILE *file)
{
    char fileInfo[24] = {0,};
    fread(&fileInfo, 24, 1, file);
    Pcap *ph = pHeader;
    Ptime time;
    Mac macData;
    Ipv6 ip;
    Tcp tcpData;
    Udp udpData;
    char macBuffer[20] = {0,};
    char buffer[700000] = {0,};
    char tcpBuffer[70000]= {0,};
    while (feof(file) == 0){
        if (fread(ph, 16, 1, file) != 1 || readCount++ > MAX) break;
        time = timeConvert(ph->timesec, ph->timeusec);
        printf("================================================\n");
        printf("packet Num : %d\n", readCount);
        printf("#1. localtime : %d:%d:%d.%d\n", time.cTime->tm_hour, time.cTime->tm_min, time.cTime->tm_sec, time.timeusec);
        printf("#2. caputer-length : %d , acutal-length : %d\n", ph->capLength, ph->length);
        fread(macBuffer, 1, 14, file);
        macData = secondLayer(macBuffer);
        ipV6 = macData.type[0] == 0x86 ? true : false;
        fread(buffer, 1, ph->capLength - 14, file);
        if (ipV6)
        {   
            ip = analyzeV6(buffer);
            printf("#3. source ip address : ");
            for (int i = 0; i < 16; i++)
            {
                printf("%x", ip.sourceAddr[i]);
                if(i<15) printf(":");
            }
            printf("\ndest ip address : ");
            for (int i = 0; i < 16; i++)
            {
                printf("%x", ip.destAddr[i]);
                if(i<15) printf(":");
            }
            printf("\n#4.traffic class : %d , flow label : 0x%x\n", ip.trafficClass, ip.flowLabel);
            printf("#5.payloadLength :%d\n", ip.payloadLength);
            if (ip.nextHeader == 6) {
                tcpData=analyzeTcp(buffer, ph->capLength - 14);
                if(maxTcpSize<tcpData.payLoadSize) maxTcpSize=tcpData.payLoadSize;
                printf("#6.source port : %d, dest port : %d\n", tcpData.sourcePort,tcpData.destPort);
                printf("#7.starting sequence number : %u, ending sequence number : %u\n", tcpData.seqNumber, tcpData.seqNumber+tcpData.payLoadSize);
                printf("#8.acknowledgement number : %u\n", tcpData.ackNumber);
                printf("#9.tcp payload size : %d\n", tcpData.payLoadSize);
                printf("#10.window Size :%d\n", tcpData.windowSize);
                printf("#11.TCP segment Type S:%d, F:%d, R:%d, P:%d, A:%d, U:%d\n", tcpData.syn, tcpData.fin, tcpData.rst, tcpData.psh, tcpData.ack, tcpData.urg);
                if(tcpData.optionLength==0){
                  printf("#12.TCP Options : No Options\n");      
                }else{
                    printf("#12.TCP Options bytes : ");
                    for(int i=0; i<tcpData.optionLength; i++){
                        if(tcpData.option[i]<10) printf("0%x", tcpData.option[i]);
                        else printf("%x", tcpData.option[i]);
                    }
                    printf(", TCP Options List : ");
                    for(int i =0; i<optionCnt;i++){
                        printf("%s ", optionArr[i]);
                        optionArr[i]="";
                        if(i<optionCnt-1) {
                            printf(", ");
                            continue;
                        }
                        optionCnt=0;
                        printf("\n");
                    }
                }
                printf("#13.Greatest payload size in TCP : %d , UDP : %d\n", maxTcpSize, maxUdpSize);
                applicationType(tcpData.sourcePort, tcpData.destPort, 't');
            }
            else if (ip.nextHeader == 17) {
                udpData=analyzeUdp(buffer, ph->capLength - 14);
                if(maxUdpSize<udpData.payLoadSize) maxUdpSize=udpData.payLoadSize;
                printf("#6.source port : %d, dest port : %d\n", udpData.sourcePort, udpData.destPort);
                printf("#7.udp paylaod size : %d\n", udpData.payLoadSize);
                printf("#8.Greatest payload size in TCP : %d , UDP : %d\n", maxTcpSize, maxUdpSize);
                applicationType(udpData.sourcePort, udpData.destPort, 'u');
            }
            else printf("Not Support protocol\n");
        }else{
            printf("this packet is ipV4\n");
        }
        ph++;
    }
}

Ptime timeConvert(unsigned int timesec, unsigned int timeusec)
{
    Ptime temp;
    time_t t = timesec;
    temp.timeusec = timeusec;
    temp.cTime = localtime(&t);
    return temp;
}

Mac secondLayer(char *buffer)
{
    Mac *temp = (Mac *)buffer;
    return *temp;
}

Ipv6 analyzeV6(char *buffer)
{
    Ipv6 temp;
    temp.version = buffer[0] >> 4;
    temp.trafficClass=buffer[0]<<4 | buffer[1]>>4;
    temp.flowLabel=(buffer[1]<<4)>>4;
    temp.flowLabel<<=16;
    temp.flowLabel|=buffer[2]<<8;
    temp.flowLabel|=buffer[3];
    temp.payloadLength=buffer[4]<<8 | buffer[5];
    temp.nextHeader = buffer[6];
    temp.hopLimit = buffer[7];
    for (int i = 0; i < 16; i++)
    {
        temp.sourceAddr[i]=buffer[8+i];
    }
    for (int i = 0; i < 16; i++)
    {
        temp.destAddr[i]=buffer[24+i];
    }
    return temp;
}


Tcp analyzeTcp(char *buffer, int lastIndex){
    unsigned char tcpBuffer[100]={0,};
    for(int i=40;i<60;i++){
        tcpBuffer[i-40]=buffer[i];
    }
    Tcp temp;
    temp.sourcePort=(tcpBuffer[0]<<8);
    temp.sourcePort|=tcpBuffer[1];
    temp.destPort=(tcpBuffer[2])<<8;
    temp.destPort|=tcpBuffer[3];
    temp.seqNumber=(tcpBuffer[4])<<24;
    temp.seqNumber|=(tcpBuffer[5])<<16;
    temp.seqNumber|=(tcpBuffer[6])<<8;
    temp.seqNumber|=tcpBuffer[7];
    temp.ackNumber=(tcpBuffer[8])<<24;
    temp.ackNumber|=(tcpBuffer[9])<<16;
    temp.ackNumber|=(tcpBuffer[10])<<8;
    temp.ackNumber|=tcpBuffer[11];
    temp.hLen=tcpBuffer[12]>>4;
    temp.reserved=(tcpBuffer[12]<<4);
    temp.reserved|=(tcpBuffer[13]>>6);
    unsigned char bitCheck = tcpBuffer[13]<<2;
    bitCheck>>=2;
    temp.urg=(bitCheck&32)>>5;
    temp.ack=(bitCheck&16)>>4;
    temp.psh=(bitCheck&8)>>3;
    temp.rst=(bitCheck&4)>>2;
    temp.syn=(bitCheck&2)>>1;
    temp.fin=bitCheck&1;
    temp.windowSize=(tcpBuffer[14]<<8);
    temp.windowSize|=tcpBuffer[15];
    temp.checkSum=(tcpBuffer[16]<<8);
    temp.checkSum|=tcpBuffer[17];
    temp.urgentPointer=(tcpBuffer[18]<<8);
    temp.urgentPointer|=tcpBuffer[19];
    unsigned char length = (temp.hLen<<2);
    unsigned char optionLength = length-20;
    temp.optionLength = length-20;
    for(int i=0; i<optionLength;i++){
        temp.option[i]=buffer[60+i];
    }
    temp.payLoadSize=lastIndex - (optionLength+60);
    int idx =0;
    int next= 0;
    while(idx <optionLength){
        int now = temp.option[idx];
        switch (now)
        {
        case 0 :
            idx+=2;
            optionArr[optionCnt++]="End of Option List (EOL)";
            break;
        case 1 :
            idx++;
            optionArr[optionCnt++]="No-Operation";
            break;
        case 2 :
            idx+=4;
            optionArr[optionCnt++]="Maximum segment size";
            break;
        case 3 :
            idx+=3;
            optionArr[optionCnt++]="Window scale";
            break;
        case 4 :
            idx+=2;
            optionArr[optionCnt++]="SACK permitted";
            break;
        case 5:
            next= temp.option[idx+1];
            idx+=next;
            optionArr[optionCnt++]="SACK";
            break;
        case 8:
            idx+=10;
            optionArr[optionCnt++]="Timestamps";
            break;
        case 28 :
            idx+=4;
            optionArr[optionCnt++]="user time out";
            break;
        default:
            idx++;
            break;
        }
    }
    return temp;
}

Udp analyzeUdp(char *buffer, int lastIndex){
    unsigned char udpBuffer[100]= {0,};
    for(int i=40; i<48;i++){
        udpBuffer[i-40]=buffer[i];
    }
    Udp temp;
    temp.sourcePort=(udpBuffer[0])<<8;
    temp.sourcePort|=udpBuffer[1];
    temp.destPort=(udpBuffer[2])<<8;
    temp.destPort|=udpBuffer[3];
    temp.totalLength=(udpBuffer[4])<<8;
    temp.totalLength|=udpBuffer[5];
    temp.checkSum=(udpBuffer[6])<<8;
    temp.checkSum|=udpBuffer[7];
    temp.payLoadSize = lastIndex-48;
    return temp;
}

unsigned char convertEndian(char data)
{
    return (data << 4) | (data >> 4);
}

void applicationType(unsigned short sourcePort, unsigned destPort, char type){
    int ports[22]={7,20,21,22,23,25,53,67,68,69,80,110,111,123,143,179,194,220,389,443,587};
    for(int i=0; i<22;i++){
        if(sourcePort == ports[i] || destPort == ports[i]){
            if(type =='t') printf("#14.Application Type : ");
            else printf("#9.Application Type : ");
            switch (ports[i])
            {
            case 7:
                printf("ECHO\n");
                break;
            case 20:
                printf("FTP\n");
                break;
            case 21:
                printf("FTP\n");
                break;
            case 22:
                printf("SSH\n");
                break;
            case 23:
                printf("Telnet\n");
                break;
            case 25:
                printf("SMTP\n");
                break;
            case 53:
                printf("DNS\n");
                break;
            case 67:
                printf("DHCP\n");
                break;
            case 68:
                printf("DHCP\n");
                break;
            case 69:
                printf("TFTP\n");
                break;
            case 80:
                printf("HTTP\n");
                break;
            case 110:
                printf("POP3\n");
                break;
            case 111:
                printf("RPC\n");
                break;
            case 123:
                printf("NNTP\n");
                break;
            case 143:
                printf("IMAP4\n");
                break;
            case 179:
                printf("BGP\n");
                break;
            case 194:
                printf("IRC\n");
                break;
            case 220:
                printf("IAMP3\n");
                break;
            case 389:
                printf("LDAP\n");
                break;      
            case 443:
                printf("HTTPS\n");
                break; 
            case 587:
                printf("SMTP\n");
                break;         
            default:
                break;
            }
            break;
        }
    }
}