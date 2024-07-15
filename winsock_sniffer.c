#include <stdio.h>
#include <locale.h>
#include "winsock2.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
//пользовательские порты вибирать от 1024 до 42151 или 42152+
//need admin permision during launch
#pragma comment(lib,"ws2_32.lib") //Winsock

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1) ////чтоб не включать mstcpip.h

void StartSniffing (SOCKET Sock); 

void ProcessPacket (char* , int); //Определение способа обработки
void PrintIpHeader (char*);
void PrintHttpPacket (char* , int);
void PrintUdpPacket (char* , int);
void PrintTcpPacket (char* , int);
void ConvertToHex (char* , unsigned int);
void PrintData (char* , int);

typedef struct ip_hdr
{ //Битовые поля
	unsigned char ip_header_len:4; 
	unsigned char ip_version :4; // 4 бита IPv4
	unsigned char ip_tos; 
	unsigned short ip_total_length; 
	unsigned short ip_id; 

	unsigned char ip_frag_offset :5;
	
	//Flags M D O
	unsigned char ip_more_fragment :1;
	unsigned char ip_dont_fragment :1;
	unsigned char ip_reserved_zero :1;

	unsigned char ip_frag_offset1;    //5 + 8 = 13

	unsigned char ip_ttl;
	unsigned char ip_protocol; //(TCP,UDP, ...)
	unsigned short ip_checksum; 
	unsigned int ip_srcaddr; 
	unsigned int ip_destaddr; 
} IPV4_HDR;

typedef struct udp_hdr
{
	unsigned short source_port; //№
	unsigned short dest_port; //№
	unsigned short udp_length; //Длина пакета
	unsigned short udp_checksum;
} UDP_HDR;

typedef struct tcp_header
{
	unsigned short source_port;  
	unsigned short dest_port; 
	unsigned int sequence; // Порядковый номер передаваемого сегмента - 32 бита
	unsigned int acknowledge; // Порядковый номер подтверждаемого сегмента - 32 

	unsigned char ns :1; //Nonce Sum флаг. Добавлен в RFC 3540.
	unsigned char reserved_part1:6; //Зарезервировано
	unsigned char data_offset:4; //Метка, откуда начинаются данные
	//Флаги
	unsigned char fin :1; //Finish Flag
	unsigned char syn :1; //Synchronise 
	unsigned char rst :1; //Reset 
	unsigned char psh :1; //Push 
	unsigned char ack :1; //Acknowledgement 
	unsigned char urg :1; //Urgent 

	unsigned char ecn :1; //ECN-Echo 
	unsigned char cwr :1; //Congestion Window Reduced 


	unsigned short window; 
	unsigned short checksum; 
	unsigned short urgent_pointer; 
} TCP_HDR;

typedef struct http_request 
{
	char* request_line;
	unsigned char* host;
	unsigned char* accept;
	unsigned char* acc_encod;
	unsigned char* acc_lang;
	unsigned int keep_alive;
} HTTP_REQ;

FILE *logfile;
int tcp=0, udp=0, http=0, others=0, total=0, i, j;
struct sockaddr_in source,dest;
char hex[2];


IPV4_HDR *iphdr;
TCP_HDR *tcpheader;
UDP_HDR *udpheader;
HTTP_REQ *httpheader;

int main()
{
	setlocale(LC_ALL, "Rus");
	SOCKET sniffer;
	struct in_addr addr;
	int in;

	char hostname[100];
	struct hostent *local;
	

	logfile=fopen("log.txt","w");
	if(logfile == NULL)
		printf("Лог-файл почему-то не создался :(");

	printf("\nИнициализация Winsock...");
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2,2), &wsa) != 0)
	{
		printf("WSAStartup() не взлетел\n");
		return 1;
	}
	printf("Winsock Инициализирован");

	printf("\nСоздание RAW-сокета...");
	sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (sniffer == INVALID_SOCKET)
	{
		printf("Не получилось\n");
		return 1;
	}
	printf("RAW-сокет есть!");

	//Получаем имя хоста локального
	if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR)
	{
		printf("Error : %d",WSAGetLastError());
		return 1;
	}
	printf("\nИмя Хоста: %s \n",hostname);

	//Доступные на локальном хосте IP-адреса
	local = gethostbyname(hostname);
	printf("\nДоступные интерфейсы в инет: \n");
	if (local == NULL)
	{
		printf("Error : %d.\n",WSAGetLastError());
		return 1;
	}

	for (i = 0; local->h_addr_list[i] != 0; ++i)
	{
		memcpy(&addr, local->h_addr_list[i], sizeof(struct in_addr));
		printf("№ Интерфейса: %d Адрес: %s\n",i,inet_ntoa(addr));
	}

	printf("Введите номер интерфейса, который хотелось бы прослушать: ");
	scanf("%d", &in);

	memset(&dest, 0, sizeof(dest));
	memcpy(&dest.sin_addr.s_addr, local->h_addr_list[in], sizeof(dest.sin_addr.s_addr));
	dest.sin_family = AF_INET;
	dest.sin_port = 0;

	printf("\nПривязка сокета к лок. системе и порту 0 ...");
	if (bind(sniffer,(struct sockaddr *)&dest,sizeof(dest)) == SOCKET_ERROR)
	{
		printf("bind(%s) failed.\n", inet_ntoa(addr));
		return 1;
	}
	printf("Привязан\n");

	j=1;
	printf("\nУстановка параметров сокета на прослушку...");
	if (WSAIoctl(sniffer, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD) &in , 0 , 0) == SOCKET_ERROR)
	{
		printf("WSAIoctl() не взлетел. Внимание программа должна быть запущена от имени администратора\n");
		return 1;
	}
	printf("Есть.\n");

	printf("\nНачало прослушки. Остановится на 500 пакетах\n");
	printf("Статистика захвата пакетов...\n");
	StartSniffing(sniffer); 

	closesocket(sniffer);
	WSACleanup();
	fclose(logfile);
	return 0;
}

void StartSniffing(SOCKET sniffer)
{
	char *Buffer = (char *)malloc(65536); 
	int mangobyte;

	if (Buffer == NULL)
	{
		printf("malloc() failed.\n");
		return;
	}

	do
	{
		mangobyte = recvfrom(sniffer, Buffer, 65536, 0, 0, 0); 

		if(mangobyte > 0)
			{ProcessPacket(Buffer, mangobyte);}
		else
			printf( "recvfrom() failed.\n");
	}
	while (mangobyte > 0 && total < 500);

	free(Buffer);
}

void ProcessPacket(char* Buffer, int Size)
{
	iphdr = (IPV4_HDR *)Buffer;
	unsigned short iphdrlen;
	++total;

	switch (iphdr->ip_protocol) //Проверка протоколов и вывод пакетов...
	{
		case 6: //TCP Протокол(выводит только те, у которых порт назначения 80)
			++tcp; 
			
			iphdrlen = iphdr->ip_header_len * 4;
			tcpheader = (TCP_HDR*)(Buffer + iphdrlen);
			if ((ntohs(tcpheader->dest_port)) == 80)
			{
				++http;
				PrintTcpPacket(Buffer, Size);
				PrintHttpPacket(Buffer, Size);
			}
			break;

		case 17: //UDP
			++udp;
			PrintUdpPacket(Buffer, Size);
			break;

		default: //Др-е протоколы, типа ARP итд.
			++others;
			break;
	}
	printf("TCP : %d UDP : %d HTTP %d: Иные : %d Всего : %d\r",tcp,udp,http,others,total);
}

void PrintIpHeader (char* Buffer)
{
	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len*4; //from 4 bits to 16 = ushort
	//IHL —(Internet Header Length) длина заголовка IP - пакета в 32 - битных словах
	//Именно это поле указывает на начало блока данных в пакете
	//Минимальное корректное значение для этого поля равно 5.
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iphdr->ip_srcaddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;

	fprintf(logfile,"\n");
	fprintf(logfile,"IP Header\n");
	fprintf(logfile," |-IP Version : %d\n",(unsigned int)iphdr->ip_version);
	fprintf(logfile," |-IP Header Length : %d DWORDS or %d Bytes\n",(unsigned int)iphdr->ip_header_len,((unsigned int)(iphdr->ip_header_len))*4);
	fprintf(logfile," |-Type Of Service : %d\n",(unsigned int)iphdr->ip_tos);
	fprintf(logfile," |-IP Total Length : %d Bytes(Size of Packet)\n",ntohs(iphdr->ip_total_length));
	fprintf(logfile," |-Identification : %d\n",ntohs(iphdr->ip_id));
	fprintf(logfile," |-Reserved ZERO Field : %d\n",(unsigned int)iphdr->ip_reserved_zero);
	fprintf(logfile," |-Dont Fragment Field : %d\n",(unsigned int)iphdr->ip_dont_fragment);
	fprintf(logfile," |-More Fragment Field : %d\n",(unsigned int)iphdr->ip_more_fragment);
	fprintf(logfile," |-TTL : %d\n",(unsigned int)iphdr->ip_ttl);
	fprintf(logfile," |-Protocol : %d\n",(unsigned int)iphdr->ip_protocol);
	fprintf(logfile," |-Checksum : %d\n",ntohs(iphdr->ip_checksum));
	fprintf(logfile," |-Source IP : %s\n",inet_ntoa(source.sin_addr));
	fprintf(logfile," |-Destination IP : %s\n",inet_ntoa(dest.sin_addr));
}

void PrintTcpPacket(char* Buffer, int Size)
{
	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len*4;

	tcpheader=(TCP_HDR*)(Buffer+iphdrlen);

	fprintf(logfile,"\n\n***********************TCP Packet*************************\n");

	PrintIpHeader(Buffer);

	fprintf(logfile,"\n");
	fprintf(logfile,"TCP Header\n");
	fprintf(logfile," |-Source Port : %u\n",ntohs(tcpheader->source_port));
	fprintf(logfile," |-Destination Port : %u\n",ntohs(tcpheader->dest_port));
	fprintf(logfile," |-Sequence Number : %u\n",ntohl(tcpheader->sequence));
	fprintf(logfile," |-Acknowledge Number : %u\n",ntohl(tcpheader->acknowledge));
	fprintf(logfile," |-Header Length : %d DWORDS or %d BYTES\n"
	,(unsigned int)tcpheader->data_offset,(unsigned int)tcpheader->data_offset*4);
	fprintf(logfile," |-CWR Flag : %d\n",(unsigned int)tcpheader->cwr);
	fprintf(logfile," |-ECN Flag : %d\n",(unsigned int)tcpheader->ecn);
	fprintf(logfile," |-Urgent Flag : %d\n",(unsigned int)tcpheader->urg);
	fprintf(logfile," |-Acknowledgement Flag : %d\n",(unsigned int)tcpheader->ack);
	fprintf(logfile," |-Push Flag : %d\n",(unsigned int)tcpheader->psh);
	fprintf(logfile," |-Reset Flag : %d\n",(unsigned int)tcpheader->rst);
	fprintf(logfile," |-Synchronise Flag : %d\n",(unsigned int)tcpheader->syn);
	fprintf(logfile," |-Finish Flag : %d\n",(unsigned int)tcpheader->fin);
	fprintf(logfile," |-Window : %d\n",ntohs(tcpheader->window));
	fprintf(logfile," |-Checksum : %d\n",ntohs(tcpheader->checksum));
	fprintf(logfile," |-Urgent Pointer : %d\n",tcpheader->urgent_pointer);
	fprintf(logfile,"\n");
	fprintf(logfile," DATA Dump ");
	fprintf(logfile,"\n");

	fprintf(logfile,"IP Header\n");
	PrintData(Buffer,iphdrlen);

	fprintf(logfile,"TCP Header\n");
	PrintData(Buffer+iphdrlen,tcpheader->data_offset*4);

	fprintf(logfile,"Data Payload\n");
	PrintData(Buffer+iphdrlen+tcpheader->data_offset*4
	,(Size-tcpheader->data_offset*4-iphdr->ip_header_len*4));

	fprintf(logfile,"\n###########################################################");
}

void PrintUdpPacket(char *Buffer,int Size)
{
	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len*4;

	udpheader = (UDP_HDR *)(Buffer + iphdrlen);

	fprintf(logfile,"\n\n***********************UDP Packet*************************\n");

	PrintIpHeader(Buffer);

	fprintf(logfile,"\nUDP Header\n");
	fprintf(logfile," |-Source Port : %d\n",ntohs(udpheader->source_port));
	fprintf(logfile," |-Destination Port : %d\n",ntohs(udpheader->dest_port));
	fprintf(logfile," |-UDP Length : %d\n",ntohs(udpheader->udp_length));
	fprintf(logfile," |-UDP Checksum : %d\n",ntohs(udpheader->udp_checksum));

	fprintf(logfile,"\n");
	fprintf(logfile,"IP Header\n");

	PrintData(Buffer,iphdrlen);

	fprintf(logfile,"UDP Header\n");

	PrintData(Buffer+iphdrlen,sizeof(UDP_HDR));

	fprintf(logfile,"Data Payload\n");

	PrintData(Buffer+iphdrlen+sizeof(UDP_HDR) ,(Size - sizeof(UDP_HDR) - iphdr->ip_header_len*4));

	fprintf(logfile,"\n###########################################################");
}

void PrintHttpPacket(char* Buffer, int Size)
{
	unsigned short iphdrlen, tcphdrlen;

	iphdr = (IPV4_HDR *)Buffer; 
	iphdrlen = iphdr->ip_header_len*4; 
	tcpheader = (TCP_HDR*)(Buffer + iphdrlen);
	tcphdrlen = tcpheader->data_offset*4;
	httpheader = (HTTP_REQ*)(Buffer + iphdrlen + tcphdrlen); //(tcpheader + tcphdrlen);//
	//(unsigned int)tcpheader->data_offset*4
	size_t rl_size = 1500; //1.5 kb
	httpheader->request_line = (unsigned char*)malloc(rl_size);
	//memset(httpheader->request_line, Buffer + iphdrlen + tcphdrlen, rl_size);
	memcpy(httpheader->request_line, Buffer + iphdrlen + tcphdrlen, rl_size);
	/*httpheader->host = ;
	httpheader->accept = ;
	httpheader->acc_encod = ;
	httpheader->acc_lang =

	if (httpheader->request_line == NULL || httpheader->host == NULL || httpheader->accept == NULL
		|| httpheader->acc_encod == NULL || httpheader->acc_lang == NULL)
	{
		printf("malloc() http failed.\n");
		return;
	} */

	fprintf(logfile,"\n\n***********************HTTP Packet*************************\n");
	//PrintIpHeader(Buffer);
	fprintf(logfile, "\n Http Request ");
	fprintf(logfile,"\n |-Request line : ");
	//-----------------
	for (int i = 0; i < 110; i++)
		fprintf(logfile, "%c", (char*)(httpheader->request_line[i]));
	//fprintf(logfile," |-Accept : %s\n", (unsigned char*)(httpheader->accept));
	//fprintf(logfile," |-Accept-Encoding : %s\n", (unsigned char*)(httpheader->acc_encod));
	//fprintf(logfile," |-Accept-Language : %s\n", (unsigned char*)(httpheader->acc_lang));
	//fprintf(logfile," |-Keep Alive : %d\n", ntohs(httpheader->keep_alive));
	fprintf(logfile,"\n");

	fprintf(logfile,"IP Header\n");
	PrintData(Buffer,iphdrlen);

	fprintf(logfile, "HTTP Full Header\n");
	PrintData(Buffer + iphdrlen + tcpheader->data_offset * 4, rl_size);

	fprintf(logfile,"\n###########################################################");
	free(httpheader->request_line);
}

/*
	Данные выводятся 16ричными байтами
*/
void PrintData (char* data , int Size)
{
	char a, line[17], c;
	int j;

	for(i = 0; i < Size; i++)
	{
		c = data[i];

		//Выводит 16ричное значение для каждого символа с отсупом. Очень важно чтобы символ был беззнаковым
		fprintf(logfile," %.2x", (unsigned char) c);

		//В строку данных добавлят символ
		a = ( c >=32 && c <=128) ? (unsigned char) c : '.';
		line[i%16] = a;

		if( (i!=0 && (i+1)%16==0) || i == Size - 1)
		{
			line[i%16 + 1] = '\0';

			fprintf(logfile ,"          ");

			for( j = strlen(line) ; j < 16; j++)
			{
				fprintf(logfile , "   ");
			}
			fprintf(logfile , "%s \n" , line);
		}
	}

	fprintf(logfile , "\n");
}