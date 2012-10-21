/* Purpose: TCP support for SMB
 *
 * Written by Terrance Hutchinson
 * Copyright 2012, Terrance Hutchinson, Hellfire Storage
 *
 */

#ifndef _SMB_TCP_
#define _SMB_TCP_

#include <iostream>
#include <string>
#include <unistd.h>
#include <sys/socket.h>

class SMB_TCP
{
public:
    SMB_TCP();
    ~SMB_TCP();
    SMB_TCP(SMB_TCP& OtherCopy);
    char ip_address[3];
    int port;
    char mac_address[3];
    
private:
    bool isIPv4;
    bool isIPv6;
    bool is_network_up(int port);



}SMB_TCP, PSMB_TCP;