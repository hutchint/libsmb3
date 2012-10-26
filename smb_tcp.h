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
#include <sys/types.h>
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
    sockaddr *address;
    int socket(int domain, int sock_type, int protocol);
    char mac_address[3];
    char protocol;
    char type; // Will be set to SOCK_STREAM in constructor
    
    // Methods
    int connect(int socket, const struct sockaddr *address, socklen_t addr_len);
    int close(
    int listen(int socket, int backlog);
    int send(int socket, const void *buffer, size_t length, int flags);
    int recieve(int socket, void *buffer, size_t length, int flags);
    
    
private:
    bool isIPv4;
    bool isIPv6;
    bool is_network_up(int port);
    


};