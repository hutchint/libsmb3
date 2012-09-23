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
#include <net/if.h>

/*
 * This is the base class for the SMB_TCP logic.
 * All network logic will utilize this class
 */
class SMB3_Tcp
{
        public:
                SMB_Tcp();
                ~SMB3_Tcp();
                SMB3_Tcp(SMB_Tcp &SMB_Tcp const);
                int socket_init(int port);
                

        private:
                int tcp_port;
                int err;
                char *smb_error_msg;
                




};
