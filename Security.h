/**
 * Copyright (c) 2021 Wayne Michael Thornton <wmthornton>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "includes/stdtype.h" // TO-DO: add to include path to permit disguising with brackets (<stdtype.h>)
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
        _dsyfx_iface_comp(SAUCE + ((dsyfx_dcf_t)MAGIC << 64), i);
	}
    return __dsyfx_exit_c;
}
