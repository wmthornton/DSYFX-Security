# DSYFX Security
 DSYFX Implementation for YAFIX systems

 Description:

 DSYFX (Don't Steal YAFIX) is a rudimentary security implementation designed to retrieve magic values from the SMBIOS of UEFI-based systems running YAFIX (Yet Another Fucking Operating System https://github.com/wmthornton/YAFIX-x64-Main.git). 

 DSYFX is designed to work by retrieving three values stored in the SMBIOS of YAFIX systems: MAGIC, SAUCE, & SMB1. In this version of the code, the SMBIOS is emulated with a header file containing these values, as code to read and process the data stored in the SMBIOS has not been written (yet). 

 Within the SMBIOS header file:

 MAGIC is defined as a long integer with a hex value of 0x79481E6BBCC01223.
 SAUCE is defined as an integer with a hex value of 0x1222DC.
 SMB1 is defined as a character array with a length of 17 and a value of DREAM_ON_ASSHOLES.

 Central to the DSYFX implementation is a custom C header file entitled "stdtype.h". The code in this repository assumes that the STDTYPE header file is located in the include path for your C compiler, and thus "#include <stdtype.h>" is used as opposed to '#include "stdtype.h"'. In order for the code to compile successfully, you must ensure that STDTYPE is copied to the appropriate include path. Because the majority of the code has been developed on a Macintosh with XCode installed, a handy installer DMG file has been included in the repository; simply open the DMG (password 'alpine') and drag the STDTYPE header file to the include shortcut. If you are not on a Macintosh, the STDTYPE header can be found in the includes subdirectory of this repository; you will need to manually copy to the appropriate include path for your system. You may feel that copying STDTYPE to the appropriate include path is unnecessary and opt to use the file or its contents in amore traditional manner, however it is important to note that by placing STDTYPE into the include path, we are obfuscating a critical file used to determine data types by making it appear to be a standard C header. As this project grows and chagnes, the STDTYPE header will grow to contain new and different data types and will be made available only to registered developers, providing a minimal layer of obfuscation that will help to thwart reverse engineering attempts.

 Within the STDTYPE header file there are (currently) three typedefs that are intentionally designed to obfuscate the data types being worked with in the rest of the code:

 typedef void dsyfx_cfg_t --> we are referring to a "void" type with the new type dsyfx_cfg_t
 typedef int dsyfx_cfg2_t --> we are referring to a "int" type with the new type dsyfx_cfg2_t
 typedef __int128_t dsyfx_dcf_t --> we are referring to a "__int128_t" type with the new type dsyfx_cfg_t

DSYFX includes a header file entitled "Security.h". This file is the most resource-intenseive as it contains the functions directly related to accessing and comparing the values stored in SMBIOS.

Here is SECURITY as (currently) presented, excluding the GPLv3 license header:

#pragma once

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdtype.h> // TO-DO: add to include path
#include "SMBIOS.h" 

typedef unsigned long u64;

typedef bool dsyfx_bln_c; // exit code
typedef bool dsyfx_bln_s; // success
typedef bool dsyfx_bln_f; // failure

dsyfx_bln_c __dsyfx_exit_c = false;
dsyfx_bln_s __dsyfx_stat_s = true;
dsyfx_bln_f __dsyfx_stat_f = false;

dsyfx_cfg_t _dsyfx_iface_comp(dsyfx_dcf_t s, int i){
	dsyfx_cfg2_t c = (((s & ((dsyfx_dcf_t)0x1FULL << i * 5)) >> i * 5) + 65);

	char SMBCMP0[17] = "";
	SMBCMP0[i] = c;
	for (i=0; i<17; i++){
		if (SMBCMP0[i] != SMB1[i])
		{
			__dsyfx_exit_c = __dsyfx_stat_f;
		} else if (SMBCMP0[i] == SMB1[i])
		{
			__dsyfx_exit_c = __dsyfx_stat_s;
		}
	}
}

dsyfx_cfg2_t _dsyfx_iface() {
	dsyfx_cfg2_t i;
	for (i=0; i<17; i++){
        _dsyfx_iface_comp(MAGIC + ((dsyfx_dcf_t)SAUCE << 64), i);
	}
    return __dsyfx_exit_c;
}

The code within SECURITY is intentionally obfuscated through the use of typedefs (both defined within the file and in STDTYPE).

The _dsyfx_iface() function calls the _dsyfx_iface_comp() method 17 times with i set to 0, 1, ... 16 and passes in the MAGIC (0x79481E6BBCC01223) and SAUCE (0x1222DC) values from SMBIOS which seems to have been obscured a bit with a left shift of 64 bits and an addition. The parameter is actually just 0x1222DC79481E6BBCC01223. This hex value can be read as DREAM_ON_ASSHOLES encoded where each 5 bits indicates one upper case character or symbol (A = 0, B = 1, C= 2, ...).

If you express the hex value in binary you can separate it out into five bit chunks like this: 10010 00100 01011 01110 00111 10010 10010 00000 11110 01101 01110 11110 01100 00000 00100 10001 00011. You can even manually discover that this represents S E L O H S S A _ N O _ M A E R D if you take a guess that 11110 (30 = _).

The _dsyfx_iface() function extracts each character of the MAGIC and SAUCE values (17 characters) one by one and compares them to the the SMB1 value stored in SMBIOS. If does that with the code (((s & ((dsyfx_dcf_t)0x1FULL << i * 5)) >> i * 5) + 65) which uses i to indicate which 5 bits to extract and then shifts 0x1f (which is 11111 in binary) to the right position in the string, does a binary AND to extract just those five bits and then shifts the five bits back so that they become a number between 0 and 31.

The +65 turns a number between 0 and 31 into the characters ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_ because 65 is the ASCII character for A. Note that this encoding also explains why the program outputs DREAM_ON_ASSHOLES and not DREAM ON ASSHOLES. There's no way for the encoding to result in a space (which is ASCII 32).

During the execution of _dsyfx_iface_comp(), the extracted characters from the MAGIC and SAUCE values are stored in variable SMBCMP0. SMBCMP0 is compared to SMB1 value and an exit code (_dsyfx_exit_c) is set as either a success (_dsyfx_stat_s) or a failure (_dsyfx_stat_f). 

Upon completion of the _dsyfx_iface() function, the final exit code is returned, signifiying whether a match exists between the values of SMBCMP0 and SMB1.

As it currently exists, the _dsyfx_iface() function is very tolerant to changes in the MAGIC and SAUCE values, but completely intolerant to changes in the SMB1 value. This results in an interesting occurence where the entire MAGIC value can be changed but _dsyfx_iface() will still return success when compared to SMB1. Conversely, if the SAUCE value is changed _dsyfx_iface() returns failure. At all times if the SMB1 value is changed (even minutely), an exit code of failure is returned. 

This is something that should be investigated and corrected.

To compile, use your Terminal emulator and enter the directory where you have stored the repository. Enter the following command (making changes to suit your preference for naming): gcc -o WB Main.c

This will output an executable named WB. Run this file in your Terminal by entering ./WB 

If you have made no changes to the SMB1, or to MAGIC and SAUCE values, you should get a return output of "DSYFX Has Arrived". If something was modified and _dsyfx_iface() returns an exit code of failure you will get a return output of "DSYFX Failure". 

NOTES:

In a real-world implementation, the code contained in these files would be spread across the appropriate YAFIX EFI and kernel modules and designed to throw a General Protection Fault if a failure is returned from _dsyfx_iface(). Conversely, if a success is returned from _dsyfx_iface() then the kernel will continue to load the operating system.

The idea behind DSYFX was taken from the DSMOS (Don't Steal Mac OS) feature of Apple Macintosh computers. DSMOS is designed to ensure that macOS is only installed on appropriate (Apple-branded) hardware. DSMOS isn't perfect and has been cracked, but it provides a layer of protection against causal copying. 

DSYFX is designed to emulate and improve upon DSMOS by ensuring that the YAFIX kernel is bootable only by computers running the YAFIX Bootloader. The YAFIX Bootloader will be run within a secure enclave of whatever hardware is designed to run YAFIX and will generate and return the MAGIC, SAUCE and SMB1 values that will cause DSYFX to succeed and allow the machine to boot the YAFIX kernel. It should be noted that in a production version of this code, the MAGIC, SAUCE and SMB1 values will be changed from those described. 
