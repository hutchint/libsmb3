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

/* Purpose: Base class that manages some of the TCP networking
 *  Can be inherited or derived from
 *
 */
class SMB_TCP
{
public:
    SMB_TCP();
    ~SMB_TCP();
    SMB_TCP(SMB_TCP& OtherCopy);
    char ip_address[3];
    int port;
    char mac_address[3];
    char protocol;
    char type; // Will be set to SOCK_STREAM in constructor
    
    // Methods
    int connect(char *ip, int port, char type, char protocol);
    int disconnect(char *ip, int port, char type, char protocol);
    int listen();
    int send();
    int recv(int socket, void *r_buf, size_t length, int flags,
             struct *sockaddr *restrict address, socklen_t *restrict address_len));
    int 
    
    
private:
    bool isIPv4;
    bool isIPv6;
    bool is_network_up(int port);
    


};