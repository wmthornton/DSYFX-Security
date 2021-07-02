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

#include "Security.h"

int main() {
	_dsyfx_iface();

	if (__dsyfx_exit_c == __dsyfx_stat_s){
		printf("DSYFX Has Arrived!\n");
	} else if (__dsyfx_exit_c == __dsyfx_stat_f){
		printf("DSYFX Failure!\n");
	}
}