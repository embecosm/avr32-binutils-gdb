/* GNU/Linux/AVR32 specific low level interface, for the remote server for GDB.
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

#include "server.h"
#include "linux-low.h"

#define avr32_num_regs 16

static int avr32_regmap[] = {
  64, 60, 56, 52, 48, 44, 40, 36,
  32, 28, 24, 20, 16, 12, 8, 4,
};

static int avr32_cannot_store_register(int regno)
{
  return regno >= avr32_num_regs;
}

static int avr32_cannot_fetch_register(int regno)
{
  return regno > avr32_num_regs;
}

#ifdef HAVE_LINUX_REGSETS
#include <sys/procfs.h>
#include <sys/ptrace.h>

static void
avr32_fill_gregset(void *buf)
{
  int i;

  for (i = 0; i < avr32_num_regs; i++)
    collect_register(i, ((char *)buf) + avr32_regmap[i]);
}

static void
avr32_store_gregset(const void *buf)
{
  int i;

  for (i = 0; i < avr32_num_regs; i++)
    supply_register(i, ((char *)buf) + avr32_regmap[i]);
}

struct regset_info target_regsets[] = {
  { PTRACE_GETREGS, PTRACE_SETREGS, sizeof(elf_gregset_t),
    GENERAL_REGS,
    avr32_fill_gregset, avr32_store_gregset },
  { 0, 0, -1, -1, NULL, NULL }
};

#endif /* HAVE_LINUX_REGSETS */

static CORE_ADDR
avr32_get_pc(void)
{
  unsigned long pc;
  collect_register_by_name("pc", &pc);
  return pc;
}

static void
avr32_set_pc(CORE_ADDR pc)
{
  unsigned long newpc = pc;
  supply_register_by_name("pc", &newpc);
}

static const unsigned short avr32_breakpoint = 0xd673;
#define avr32_breakpoint_len 2

static int
avr32_breakpoint_at(CORE_ADDR where)
{
  unsigned short insn;

  (*the_target->read_memory)(where, (char *)&insn, sizeof(insn));
  if (insn == avr32_breakpoint)
    return 1;

  return 0;
}

struct linux_target_ops the_low_target = {
  avr32_num_regs,
  avr32_regmap,
  avr32_cannot_fetch_register,
  avr32_cannot_store_register,
  avr32_get_pc,
  avr32_set_pc,
  (const char *)&avr32_breakpoint,
  avr32_breakpoint_len,
  NULL,
  0,
  avr32_breakpoint_at,
};
