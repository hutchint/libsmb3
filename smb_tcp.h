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

#ifdef __cpluplus
extern "C" {
#endif


// Socket init information
typedef struct smb_sock_init {

