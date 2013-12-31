/* GNU/Linux on AVR32 target support.
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

#include "defs.h"
#include "target.h"
#include "solib-svr4.h"
#include "osabi.h"

#include "avr32-tdep.h"

/* Fetch, and possibly build, an appropriate link_map_offsets
   structure for AVR32 linux targets using the struct offsets defined
   in <link.h>.  Note, however, that link.h is not actually referred
   to in this file.  Instead, the relevant structs offsets were
   obtained from examining link.h.  (We can't refer to link.h from
   this file because the host system won't necessarily have it, or if
   it does, the structs which it defines will refer to the host
   system, not the target).

   The following information is derived from uClibc's link.h  */

static struct link_map_offsets *
avr32_linux_fetch_link_map_offsets (void)
{
  static struct link_map_offsets lmo;
  static struct link_map_offsets *lmp = NULL;

  if (lmp == NULL)
    {
      lmp = &lmo;

      /* Size of struct r_debug */
      lmo.r_version_offset = 0;
      lmo.r_version_size = 4;
      lmo.r_map_offset = 4;

      lmo.link_map_size = 20;
      lmo.l_addr_offset = 0;
      lmo.l_name_offset = 4;
      lmo.l_ld_offset = 8;
      lmo.l_next_offset = 12;
      lmo.l_prev_offset = 16;
    }

  return lmp;
}

/* This corresponds with the layout of struct pt_regs from <asm/ptrace.h> */
static int avr32_linux_gregset_reg_offset[] =
  {
    16 * 4,		/*  r0 */
    15 * 4,		/*  r1 */
    14 * 4,		/*  r2 */
    13 * 4,		/*  r3 */
    12 * 4,		/*  r4 */
    11 * 4,		/*  r5 */
    10 * 4,		/*  r6 */
    9 * 4,		/*  r7 */
    8 * 4,		/*  r8 */
    7 * 4,		/*  r9 */
    6 * 4,		/* r10 */
    5 * 4,		/* r11 */
    4 * 4,		/* r12 */
    3 * 4,		/*  sp */
    2 * 4,		/*  lr */
    1 * 4,		/*  pc */
    /* sr at offset 0 */
    /* orig_r12 at offset 17 * 4 */
  };

static void
avr32_linux_init_abi(struct gdbarch_info info,
		     struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep(gdbarch);

  tdep->gregset_reg_offset = avr32_linux_gregset_reg_offset;
  tdep->gregset_num_regs = ARRAY_SIZE(avr32_linux_gregset_reg_offset);
  tdep->sizeof_gregset = 18 * 4;

  set_solib_svr4_fetch_link_map_offsets
    (gdbarch, avr32_linux_fetch_link_map_offsets);
}

void
_initialize_avr32_linux_tdep(void)
{
  gdbarch_register_osabi(bfd_arch_avr32, 0, GDB_OSABI_LINUX,
			 avr32_linux_init_abi);
}
