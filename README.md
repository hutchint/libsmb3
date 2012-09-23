libsmb3
=======

SMB3 library for creating SMB3 clients or servers

License: LGPLv3 Copyright 2012, Terrance Hutchinson terrance.hutchinson@hellfirestorage.com

This library implements the SMB3.0 Specification from Microsoft. This new version will be shipping with Windows 8 and Windows Server 2012 sometime in October 2012. The reason for creating this library is to provide a library for other developers to use in order to create their own client or server. My purpose is to use it with uCIFSplus which is a lightweight Server Message block server.

The library will be written in C++ without using the STL or other libraries. It will take advantage of the basic C++ concepts but not much else. The aim is for this to be as cross-platform as possible. The code will be written to be microprocessor architecture independent. That being said, I only have access to 4 types of processors to test on so I will not be able to verify functionality on other processor types at this time.

Supported Compiler: Clang 3.1 Supported OS: BSD, Unix (Mac OS X/Solaris), GNU/Linux Tested Architectures: ARMv7, x86, amd64, SPARC
