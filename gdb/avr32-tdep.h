/* Common target dependent code for GDB on AVR32 systems.
   Copyright 2004-2006 Atmel Corporation.

   Written by Haavard Skinnemoen, Atmel Norway, <hskinnemoen@atmel.com>

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#ifndef AVR32_TDEP_H
#define AVR32_TDEP_H

struct regset;

struct gdbarch_tdep
{
  const unsigned char *avr32_breakpoint;	/* Breakpoint instruction pattern */
  int avr32_breakpoint_size;	/* And its size */

  struct regset *gregset;
  int *gregset_reg_offset;
  int gregset_num_regs;
  size_t sizeof_gregset;
};

#endif /* AVR32_TDEP_H */
