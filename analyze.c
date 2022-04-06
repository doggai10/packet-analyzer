#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#define MAX 505

typedef struct pcap
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
} Mac;

typedef struct IpHeader
{
    unsigned char version;
    unsigned char length;
    unsigned char typeOfService;
    unsigned short totalLen;
    unsigned short identification;
    unsigned char flag;
    unsigned char flagX;
    unsigned char flagD;
    unsigned char flagM;
    unsigned short fragmentOffset;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned char sourceAddr[4];
    unsigned char destAddr[4];
} Ip;

int readCount = 0;
unsigned short ipV4 = 0x0800;
bool fileRead = true;
bool ipv4 = false;
void pcapParsing(FILE *file);
Ptime timeConvert(unsigned int timesec, unsigned int timeusec);
Mac secondLayer(char *buffer);
Ip thirdLayer(char *buffer);
unsigned short convertEndian(unsigned short data);
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
    Mac data;
    Ip ip;
    char macBuffer[20] = {0,};
    char buffer[700000] = {0,};
    while (feof(file) == 0)
    {
        if (fread(ph, 16, 1, file) != 1 || readCount++ > MAX) break;
        time = timeConvert(ph->timesec, ph->timeusec);
        printf("================================================\n");
        printf("packet Num : %d\n", readCount);
        printf("#1. localtime : %d:%d:%d.%d\n", time.cTime->tm_hour, time.cTime->tm_min, time.cTime->tm_sec, time.timeusec);
        printf("#2. caputer-length : %d , acutal-length : %d\n", ph->capLength, ph->length);
        fread(macBuffer, 1, 14, file);
        data = secondLayer(macBuffer);
        printf("#3. source mac : ");
        for (int i = 0; i < 6; i++)
        {
            printf("%x", data.sourceMac[i]);
            i < 5 ? printf(":") : printf("\n");
        }
        printf("#4. dest mac : ");
        for (int i = 0; i < 6; i++)
        {
            printf("%x", data.destMac[i]);
            i < 5 ? printf(":") : printf("\n");
        }
        ipv4 = data.type[0] == 8 ? true : false;
        fread(buffer, 1, ph->capLength - 14, file);
        ip = thirdLayer(buffer);
        if (ipv4)
        {
            printf("#5. source ip address : ");
            for (int i = 0; i < 4; i++)
            {
                printf("%d", ip.sourceAddr[i]);
                i < 3 ? printf(".") : printf("\n");
            }
            printf("#6. dest ip address : ");
            for (int i = 0; i < 4; i++)
            {
                printf("%d", ip.destAddr[i]);
                i < 3 ? printf(".") : printf("\n");
            }
            printf("#5. protocol : ");
            if (ip.protocol == 1) printf("ICMP\n");
            else if (ip.protocol == 6)printf("TCP\n");
            else if (ip.protocol == 17) printf("UDP\n");
            else printf("Not Support protocol\n");
            printf("#6. identification : %d\n", ip.identification);
            printf("#7. flags : 0x%d%d%d, ", ip.flagX, ip.flagD, ip.flagM);
            if (ip.flagD == 1) printf("DF \n");
            else if (ip.flagM == 1) printf("MF \n");
            else printf("\n");
            printf("#8. TTL : %d\n", ip.ttl);
            printf("#9. Type of service : 0x%02x\n", ip.typeOfService);
        }else{
            printf("this packet is ipV6\n");
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

Ip thirdLayer(char *buffer)
{
    Ip temp;
    temp.version = buffer[0] >> 4;
    temp.length = (buffer[0] ^ (temp.version << 4));
    temp.typeOfService = buffer[1];
    unsigned short lenLeft = buffer[2] << 8;
    unsigned short lenRight = buffer[3] << 8;
    temp.totalLen = lenLeft | (lenRight >> 8);
    unsigned short left = (buffer[4] << 8);
    unsigned short right = (buffer[5] << 8);
    temp.identification = (convertEndian(left) << 8) + convertEndian(right);
    unsigned char flag = buffer[6] >> 5;
    temp.flag = flag;
    unsigned short offsetLeft = buffer[6] << 8;
    unsigned short offsetRight = buffer[7] << 8;
    unsigned short offset = offsetLeft | (offsetRight >> 8);
    temp.fragmentOffset = offset << 3;
    temp.flagD = (flag & 2) >> 1;
    temp.flagM = flag & 1;
    temp.ttl = buffer[8];
    temp.protocol = buffer[9];
    unsigned short checkLeft = (buffer[10] << 8);
    unsigned short checkRight = (buffer[11] << 8);
    temp.check = checkLeft | (checkRight >> 8);
    for (int i = 0; i < 4; i++)
    {
        unsigned short org = buffer[12 + i] << 8;
        temp.sourceAddr[i] = convertEndian(org);
    }
    for (int i = 0; i < 4; i++)
    {
        unsigned short org = buffer[16 + i] << 8;
        temp.destAddr[i] = convertEndian(org);
    }
    return temp;
}

unsigned short convertEndian(unsigned short data)
{
    return (data << 8) | (data >> 8);
}