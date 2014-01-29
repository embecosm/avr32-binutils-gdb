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

#include "defs.h"
#include "frame.h"
#include "frame-base.h"
#include "frame-unwind.h"
#include "dwarf2-frame.h"
#include "inferior.h"
#include "gdbcmd.h"
#include "gdbcore.h"
#include "dis-asm.h"
#include "osabi.h"
#include "regcache.h"
#include "regset.h"
#include "arch-utils.h"

#include "avr32-tdep.h"
#include "elf-bfd.h"
#include "elf/avr32.h"

#include "gdb_assert.h"

/* 0xd673 is the BREAKPOINT instruction */
static unsigned char avr32_default_breakpoint[] = { 0xd6, 0x73 };

/* Use the same register numbering as GCC */
enum {
  AVR32_REG_R0 = 0,
  AVR32_REG_R1,
  AVR32_REG_R2,
  AVR32_REG_R3,
  AVR32_REG_R4,
  AVR32_REG_R5,
  AVR32_REG_R6,
  AVR32_REG_R7,
  AVR32_REG_R8,
  AVR32_REG_R9,
  AVR32_REG_R10,
  AVR32_REG_R11,
  AVR32_REG_R12,
  AVR32_REG_SP,
  AVR32_REG_LR,
  AVR32_REG_PC,
  AVR32_NUM_REGS
};

#define AVR32_REG_FP AVR32_REG_R7

struct avr32_frame_cache
{
  CORE_ADDR base;
  LONGEST sp_offset;
  CORE_ADDR pc;

  int uses_fp;

  CORE_ADDR saved_regs[AVR32_NUM_REGS];
  CORE_ADDR saved_sp;
};


static struct type *
avr32_register_type(struct gdbarch *gdbarch, int reg_nr)
{
  switch (reg_nr)
    {
    case AVR32_REG_SP:
      /* A pointer to data */
      return builtin_type (gdbarch)->builtin_data_ptr;

    case AVR32_REG_LR:
    case AVR32_REG_PC:
      /* A pointer to code */
      return builtin_type (gdbarch)->builtin_func_ptr;

    default:
      /* All orther regs are unsigned ints */
      return builtin_type (gdbarch)->builtin_uint32;
    }	  
}	/* avr32_register_type () */

static const char *
avr32_register_name(struct gdbarch *gdbarch, int reg_nr)
{
  static const char *register_names[] =
    {
      "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
      "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"
    };

  if (reg_nr < 0)
    return NULL;
  if (reg_nr >= sizeof(register_names) / sizeof(*register_names))
    return NULL;
  return register_names[reg_nr];
}

static void
avr32_show_regs_command (char *argv, int from_tty)
{
    struct frame_info *frame;
    frame = get_current_frame();/* need current scope */
    
  printf_filtered ("pc: %08lx  lr: %08lx  sp: %08lx  r12: %08lx\n",
		   (unsigned long)get_frame_register_unsigned (frame, AVR32_REG_PC),
		   (unsigned long)get_frame_register_unsigned (frame, AVR32_REG_LR),
		   (unsigned long)get_frame_register_unsigned (frame, AVR32_REG_SP),
		   (unsigned long)get_frame_register_unsigned (frame, AVR32_REG_R12));
  printf_filtered ("r11: %08lx  r10: %08lx   r9: %08lx   r8: %08lx\n",
		   (unsigned long)get_frame_register_unsigned (frame, AVR32_REG_R11),
		   (unsigned long)get_frame_register_unsigned (frame, AVR32_REG_R10),
		   (unsigned long)get_frame_register_unsigned (frame, AVR32_REG_R9),
		   (unsigned long)get_frame_register_unsigned (frame, AVR32_REG_R8));
  printf_filtered (" r7: %08lx   r6: %08lx   r5: %08lx   r4: %08lx\n",
		   (unsigned long)get_frame_register_unsigned (frame, AVR32_REG_R7),
		   (unsigned long)get_frame_register_unsigned (frame, AVR32_REG_R6),
		   (unsigned long)get_frame_register_unsigned (frame, AVR32_REG_R5),
		   (unsigned long)get_frame_register_unsigned (frame, AVR32_REG_R4));
  printf_filtered (" r3: %08lx   r2: %08lx   r1: %08lx   r0: %08lx\n",
		   (unsigned long)get_frame_register_unsigned (frame, AVR32_REG_R3),
		   (unsigned long)get_frame_register_unsigned (frame, AVR32_REG_R2),
		   (unsigned long)get_frame_register_unsigned (frame, AVR32_REG_R1),
		   (unsigned long)get_frame_register_unsigned (frame, AVR32_REG_R0));
}

static void
avr32_set_sysreg_command(char *args, int from_tty)
{
  struct gdbarch *gdbarch = target_gdbarch ();
  LONGEST ret;
  CORE_ADDR addr, value;
  char *eq, *value_s, *endptr;
  gdb_byte buffer[4];

  if (!args)
    goto show_usage;

  eq = strchr(args, '=');
  if (!eq)
    goto show_usage;

  value_s = eq + 1;
  *eq = 0;

  addr = strtoul(args, &endptr, 0);
  if (*args == '\0' || *endptr != '\0')
    goto show_usage;

  value = strtoul(value_s, &endptr, 0);
  if (*value_s == '\0' || *endptr != '\0')
    goto show_usage;

  store_unsigned_integer(buffer, 4, gdbarch_byte_order (gdbarch), value);

  ret = target_write(&current_target, TARGET_OBJECT_SYSREG, "",
		     buffer, addr, 4);
  if (ret != 4)
    printf_unfiltered("Failed to write system register %lu.\n", addr);

  return;

show_usage:
  printf_unfiltered("\"set sysreg\" must be followed by SYSREG=VALUE.\n");
}

static void
avr32_show_sysreg_command(char *args, int from_tty)
{
  struct gdbarch *gdbarch = target_gdbarch ();
  LONGEST ret;
  CORE_ADDR addr, value;
  char *endptr;
  gdb_byte value_raw[4];

  if (!args)
    goto show_usage;

  addr = strtoul(args, &endptr, 0);
  if (*args == '\0' || *endptr != '\0')
    goto show_usage;

  ret = target_read (&current_target, TARGET_OBJECT_SYSREG, "",
		     value_raw, addr, 4);
  if (ret != 4)
    printf_unfiltered("Failed to read system register %lu.\n", addr);
  else
    {
      value = extract_unsigned_integer(value_raw, 4, gdbarch_byte_order (gdbarch));
      printf_unfiltered("SYSREG[%lu] = 0x%lx\n", addr, value);
    }

  return;

show_usage:
  printf_unfiltered("\"show sysreg\" must be followed by a system register.\n");
}

static const unsigned char *
avr32_breakpoint_from_pc(struct gdbarch *gdbarch, CORE_ADDR *pcptr, int *lenptr)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep(gdbarch);

  *lenptr = tdep->avr32_breakpoint_size;
  return tdep->avr32_breakpoint;
}

static int
gdb_print_insn_avr32 (bfd_vma memaddr,
		      disassemble_info *info)
{
  info->endian = gdbarch_byte_order(target_gdbarch ());
  return print_insn_avr32(memaddr, info);
}

static void
avr32_write_pc(struct regcache *regcache, CORE_ADDR pc)
{
  regcache_cooked_write_unsigned (regcache, AVR32_REG_PC,
                  (pc & 0xffffffff));

}

/* Determine, for architecture GDBARCH, how a return value of TYPE
   should be returned.  If it is supposed to be returned in registers,
   and READBUF is non-zero, read the appropriate value from REGCACHE,
   and copy it into READBUF.  If WRITEBUF is non-zero, write the value
   from WRITEBUF into REGCACHE.  */

static enum return_value_convention
avr32_return_value(struct gdbarch *gdbarch,
		   struct value *function,
		   struct type *type,
		   struct regcache *regcache,
		   gdb_byte *readbuf,
		   const gdb_byte *writebuf)
{
  enum type_code code = TYPE_CODE(type);
  int len = TYPE_LENGTH(type);

  if (code == TYPE_CODE_STRUCT || code == TYPE_CODE_UNION)
    {
      /* The IAR Compiler Reference says that:

      "If a structure is returned, the caller passes a pointer to a
      location where the called function should write the result. The
      pointer is passed in register R12. The called function must
      return the same pointer in register R12."

      Assuming GCC provides the same guarantee, this should go into
      the Linux/AVR32 ABI document. */

      if (readbuf)
	{
	  ULONGEST addr;

	  regcache_raw_read_unsigned(regcache, AVR32_REG_R12, &addr);
	  read_memory(addr, readbuf, TYPE_LENGTH(type));
	}

      return RETURN_VALUE_ABI_RETURNS_ADDRESS;
    }

  if (readbuf)
    {
      if (len <= 4)
	regcache_raw_read(regcache, AVR32_REG_R12, readbuf);
      else if (len <= 8)
	{
	  regcache_raw_read(regcache, AVR32_REG_R10, readbuf);
	  regcache_raw_read(regcache, AVR32_REG_R11, &(readbuf[4]));
	}
      else
	internal_error(__FILE__, __LINE__,
		       "Cannot extract return value of %d bytes long.", len);
    }
  if (writebuf)
    {
      if (len <= 4)
	regcache_raw_write_part(regcache, AVR32_REG_R12, 0, len, writebuf);
      else if (len <= 8)
	{
	  regcache_raw_write(regcache, AVR32_REG_R10, writebuf);
	  regcache_raw_write_part(regcache, AVR32_REG_R11, 0,
				  len - 4, &(writebuf[4]));
	}
      else
	internal_error(__FILE__, __LINE__,
		       "Cannot store return value of %d bytes long.", len);
    }

  return RETURN_VALUE_REGISTER_CONVENTION;
}

static int
sign_extend (int value, int bits)
{
  value = value & ((1 << bits) - 1);
  return (value & (1 << (bits - 1))
          ? value | (~((1 << bits) - 1))
          : value);
}

#define IS_EXTENDED(x)		(((x) & 0xe0000000) == 0xe0000000)
/* pushm {reglist} */
#define IS_PUSHM(x)		(((x) & 0xf00f0000) == 0xd0010000)
/* stm --sp, {reglist} */
#define IS_STM_MMSP(x)		(((x) & 0xffff0000) == 0xebcd0000)
/* st.w --sp, {reg} */
#define IS_PUSH(x)		(((x) & 0xfff00000) == 0x1aa00000)
/* mov fp, sp */
#define IS_MOV_FP_SP(x)		(((x) & 0xffff0000) == 0x1a970000)
/* sub sp, {imm} */
#define IS_SUB_SP_IMM_C(x)	(((x) & 0xf00f0000) == 0x200d0000)
#define IS_SUB_SP_IMM_E(x)	(((x) & 0xe1ef0000) == 0xe02d0000)

#define GET_PUSH_SRCREG(x)	(((x) >> 16) & 0xf)
#define GET_SUB_IMM_C(x)	sign_extend(((x) >> 20) & 0xff, 8)
#define GET_SUB_IMM_E(x)	sign_extend(((x) & 0xffff)		\
					    | (((x) >> 4) & 0x10000)	\
					    | (((x) >> 8) & 0x1e0000),	\
					    21)

/* Analyze the prologue of the function starting at pc. The function
   will not be analyzed further than current_pc, which indicates how
   much of the function has actually been executed.  */
static CORE_ADDR
avr32_analyze_prologue (struct gdbarch *gdbarch, CORE_ADDR pc, CORE_ADDR current_pc,
			struct avr32_frame_cache *cache)
{
  ULONGEST insn;
  CORE_ADDR opc;

  if (pc >= current_pc)
    return current_pc;

  cache->uses_fp = 0;
  while (pc < current_pc)
    {
      insn = read_memory_unsigned_integer(pc, 2, gdbarch_byte_order (gdbarch))
	<< 16;
      if (IS_EXTENDED(insn))
	  insn = read_memory_unsigned_integer(pc, 4, gdbarch_byte_order (gdbarch));

      if (IS_PUSHM(insn))
	{
	  if (insn & 0x00100000)
	    {
	      cache->saved_regs[0] = cache->sp_offset;
	      cache->saved_regs[1] = cache->sp_offset + 4;
	      cache->saved_regs[2] = cache->sp_offset + 8;
	      cache->saved_regs[3] = cache->sp_offset + 12;
	      cache->sp_offset += 16;
	    }
	  if (insn & 0x00200000)
	    {
	      cache->saved_regs[4] = cache->sp_offset;
	      cache->saved_regs[5] = cache->sp_offset + 4;
	      cache->saved_regs[6] = cache->sp_offset + 8;
	      cache->saved_regs[7] = cache->sp_offset + 12;
	      cache->sp_offset += 16;
	    }
	  if (insn & 0x00400000)
	    {
	      cache->saved_regs[8] = cache->sp_offset;
	      cache->saved_regs[9] = cache->sp_offset + 4;
	      cache->sp_offset += 8;
	    }
	  if (insn & 0x00800000)
	    {
	      cache->saved_regs[10] = cache->sp_offset;
	      cache->sp_offset += 4;
	    }
	  if (insn & 0x01000000)
	    {
	      cache->saved_regs[11] = cache->sp_offset;
	      cache->sp_offset += 4;
	    }
	  if (insn & 0x02000000)
	    {
	      cache->saved_regs[12] = cache->sp_offset;
	      cache->sp_offset += 4;
	    }
	  if (insn & 0x04000000)
	    {
	      cache->saved_regs[14] = cache->sp_offset;
	      cache->sp_offset += 4;
	    }
	  if (insn & 0x08000000)
	    {
	      cache->saved_regs[15] = cache->sp_offset;
	      cache->sp_offset += 4;
	    }
	}
      if (IS_STM_MMSP(insn))
	{
	  int i;

	  for (i = 0; i < 16; i++)
	    {
	      if (insn & (1 << i))
		{
		  cache->saved_regs[i] = cache->sp_offset;
		  cache->sp_offset += 4;
		}
	    }
	}
      else if (IS_PUSH(insn))
	{
	  cache->saved_regs[GET_PUSH_SRCREG(insn)] = cache->sp_offset;
	  cache->sp_offset += 4;
	}
      else if (IS_MOV_FP_SP(insn))
	{
	  cache->uses_fp = 1;
	  cache->base = cache->sp_offset;
	}
      else if (IS_SUB_SP_IMM_C(insn))
	{
	  cache->sp_offset -= GET_SUB_IMM_C(insn);
	}
      else if (IS_SUB_SP_IMM_E(insn))
	{
	  cache->sp_offset -= GET_SUB_IMM_E(insn);
	}
      else
	break;

      if (IS_EXTENDED(insn))
	pc += 4;
      else
	pc += 2;
    }

  return pc;
}

/* Return PC of first real instruction.

   We assume the following prologue (all steps are optional):

   A "pushm ..." or "stm --sp, ..." instruction to handle callee-saved
   registers.

   A "mov r7,sp" instruction to set up the frame pointer.

   A "sub sp, x" instruction to allocate space for local variables. */

static CORE_ADDR
avr32_skip_prologue(struct gdbarch *gdbarch, CORE_ADDR start_pc)
{
  gdb_byte insn[4];
  CORE_ADDR pc = start_pc;

  /* Check if any registers are saved. If not, we may safely(?) assume
     that the other steps aren't taken */
  read_memory(pc, insn, sizeof(insn));
  if ((insn[0] & 0xf0) == 0xd0 && (insn[1] & 0x0f) == 0x01)
    /* pushm instruction */
    pc += 2;
  else if (insn[0] == 0xeb && insn[1] == 0xcd)
    /* stm --sp instruction */
    pc += 4;
  else
    /* assuming no prologue */
    return pc;

  /* Check for frame pointer initialization */
  read_memory(pc, insn, sizeof(insn));
  if (insn[0] == 0x1a && insn[1] == 0x97)
    /* mov r7, sp */
    pc += 2;

  /* Check for stack frame allocation */
  read_memory(pc, insn, sizeof(insn));
  if ((insn[0] & 0xf0) == 0x20 && (insn[1] & 0x0f) == 0x0d)
    /* sub sp, x where -512 <= x <= 508 and x & 3 == 0 */
    pc += 2;
  else if ((insn[0] & 0xe1) == 0xe0 && (insn[1] & 0xef) == 0x2d)
    /* sub sp, x for really large (or strange) stack frames */
    pc += 4;

  return pc;
}

static CORE_ADDR
avr32_frame_align(struct gdbarch *gdbarch, CORE_ADDR sp)
{
  return sp & ~3;
}

static CORE_ADDR
avr32_unwind_sp(struct gdbarch *gdbarch, struct frame_info *next_frame)
{
  gdb_byte buf[sizeof(long)];
  frame_unwind_register(next_frame, AVR32_REG_SP, buf);
  return extract_unsigned_integer(buf, sizeof(buf), gdbarch_byte_order (gdbarch));
}

static CORE_ADDR
avr32_unwind_pc(struct gdbarch *gdbarch, struct frame_info *next_frame)
{
  gdb_byte buf[sizeof(long)];
  frame_unwind_register(next_frame, AVR32_REG_PC, buf);
  return extract_unsigned_integer(buf, sizeof(buf), gdbarch_byte_order (gdbarch));
}

static struct frame_id
avr32_dummy_id (struct gdbarch *gdbarch, struct frame_info *this_frame)
{
  return frame_id_build (get_frame_sp (this_frame), get_frame_pc (this_frame));

}	/* avr32_dummy_id () */


static struct avr32_frame_cache *
avr32_alloc_frame_cache (void)
{
  struct avr32_frame_cache *cache;
  int i;

  cache = FRAME_OBSTACK_ZALLOC (struct avr32_frame_cache);

  for (i = 0; i < AVR32_NUM_REGS; i++)
    cache->saved_regs[i] = -1;

  return cache;
}

static struct avr32_frame_cache *
avr32_frame_cache (struct frame_info *next_frame, void **this_cache)
{
  struct gdbarch *gdbarch = get_frame_arch (next_frame);
  struct avr32_frame_cache *cache;
  CORE_ADDR current_pc;
  int i;

  if (*this_cache)
    return *this_cache;

  cache = avr32_alloc_frame_cache();
  *this_cache = cache;

  /* FP is supposed to hold the frame pointer, but this is actually
     almost never the case. */
  cache->base = frame_unwind_register_unsigned (next_frame, AVR32_REG_FP);

  /* cache->pc = frame_func_unwind (next_frame,NORMAL_FRAME); TODO */
  current_pc = gdbarch_unwind_pc (gdbarch, next_frame);
  if (cache->pc != 0)
    avr32_analyze_prologue (gdbarch, cache->pc, current_pc, cache);

  if (!cache->uses_fp)
    {
      /* We have no frame pointer, which means that unwinding will be
	 a bit tricky.  Assume that no stack-arguments are passed to
	 this function.  */
      cache->base = frame_unwind_register_unsigned (next_frame, AVR32_REG_SP);
    }

  cache->saved_sp = cache->base + cache->sp_offset;

  /* Adjust all the saved registers so that they contain addresses
     instead of offsets.  */
  for (i = 0; i < AVR32_NUM_REGS; i++)
    if (cache->saved_regs[i] != -1)
      cache->saved_regs[i] = cache->saved_sp - cache->saved_regs[i] - 4;

  return cache;
}


/* TODO. Just updated the prototype */
static struct value *
avr32_frame_prev_register (struct frame_info *this_frame,
			   void **this_cache,
			   int regnum)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  struct avr32_frame_cache *info = avr32_frame_cache (this_frame, this_cache);

  gdb_assert (regnum >= 0);

  if (regnum == gdbarch_sp_regnum (gdbarch) && info->saved_sp)
    {
      /* *optimizedp = 0; */
      /* *lvalp = not_lval; */
      /* *addrp = 0; */
      /* *realnump = -1; */
      /* if (valuep) */
      /* 	{ */
      /* 	  store_unsigned_integer(valuep, 4, gdbarch_byte_order (gdbarch), */
      /* 				 info->saved_sp); */
      /* 	} */
      /* return; */
    }

  /* The PC of the previous frame is stored in LR of the current frame. */
  if (regnum == AVR32_REG_PC)
    regnum = AVR32_REG_LR;

  if (regnum < AVR32_NUM_REGS && info->saved_regs[regnum] != -1)
    {
      /* *optimizedp = 0; */
      /* *lvalp = lval_memory; */
      /* *addrp = info->saved_regs[regnum]; */
      /* *realnump = -1; */
      /* if (valuep) */
      /* 	read_memory(*addrp, valuep, register_size(gdbarch, regnum)); */
      /* return; */
    }

  /* if (valuep) */
  /*   frame_unwind_register (next_frame, (*realnump), valuep); */

  return  NULL;			/* TODO: Placeholder */

}	/* avr32_frame_prev_register () */

static void
avr32_frame_this_id (struct frame_info *next_frame, void **this_cache,
		     struct frame_id *this_id)
{
  struct avr32_frame_cache *cache = avr32_frame_cache (next_frame, this_cache);

  /* This marks the outermost frame.  */
  if (cache->base == 0)
    return;

  *this_id = frame_id_build (cache->saved_sp, cache->pc);
}

/*! Return the base address of the frame

    For AVR32, the base address is the stack pointer of the previous frame.

    @note The implementations has changed since GDB 6.8, since we are now
          provided with the address of THIS frame, rather than the NEXT frame.

    @param[in] this_frame      The current stack frame.
    @param[in] prologue_cache  Any cached prologue for THIS function.
    @return                    The frame base address */
static CORE_ADDR
avr32_frame_base_address (struct frame_info  *this_frame,
			  void              **prologue_cache) 
{
  return  (CORE_ADDR) get_frame_sp (get_prev_frame (this_frame));

}	/* avr32_frame_base_address() */


static const struct frame_unwind avr32_frame_unwind = {
  .type = NORMAL_FRAME,
  .stop_reason   = default_frame_unwind_stop_reason,
  .this_id = avr32_frame_this_id,
  .prev_register = avr32_frame_prev_register,
  .sniffer       = default_frame_sniffer,
};

/* Default unwind sniffer. This one must always return something */
static const struct frame_base *
avr32_frame_base_sniffer (struct frame_info *this_frame)
{
  static const struct frame_base fb =
    {
      .unwind      = &avr32_frame_unwind,
      .this_base   = avr32_frame_base_address,
      .this_locals = avr32_frame_base_address,
      .this_args   = avr32_frame_base_address
    };

  return &fb;
}

/* Supply register REGNUM from the buffer specified by GREGS and LEN
   in the general-purpose register set REGSET to register cache
   REGCACHE.  If REGNUM is -1, do this for all registers in REGSET.  */

static void
avr32_supply_gregset(const struct regset *regset, struct regcache *regcache,
		     int regnum, const void *gregs, size_t len)
{
  const struct gdbarch_tdep *tdep = gdbarch_tdep(regset->arch);
  const char *regs = gregs;
  int i;

  gdb_assert(len == tdep->sizeof_gregset);

  for (i = 0; i < tdep->gregset_num_regs; i++)
    {
      if ((regnum == i || regnum == -1)
	  && tdep->gregset_reg_offset[i] != -1)
	regcache_raw_supply(regcache, i, regs + tdep->gregset_reg_offset[i]);
    }
}

/* Collect register REGNUM from the register cache REGCACHE and store
   it in the buffer specified by GREGS and LEN as described by the
   general-purpose register set REGSET.  If REGNUM is -1, do this for
   all registers in REGSET.  */

static void
avr32_collect_gregset(const struct regset *regset,
		      const struct regcache *regcache,
		      int regnum, void *gregs, size_t len)
{
  const struct gdbarch_tdep *tdep = gdbarch_tdep(regset->arch);
  char *regs = gregs;
  int i;

  for (i = 0; i < tdep->gregset_num_regs; i++)
    {
      if ((regnum == i || regnum == -1)
	  && tdep->gregset_reg_offset[i] != -1)
	regcache_raw_collect(regcache, i, regs + tdep->gregset_reg_offset[i]);
    }
}

static const struct regset *
avr32_regset_from_core_section(struct gdbarch *gdbarch,
			       const char *sect_name, size_t sect_size)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep(gdbarch);

  if (strcmp(sect_name, ".reg") == 0 && sect_size == tdep->sizeof_gregset)
    {
      if (tdep->gregset == NULL)
	tdep->gregset = regset_alloc(gdbarch, avr32_supply_gregset,
				     avr32_collect_gregset);
      return tdep->gregset;
    }

  return NULL;
}

/* Initialize the current architecture based on INFO.  If possible,
   re-use an architecture from ARCHES, which is a list of
   architectures already created during this debugging session.

   Called e.g. at program startup, when reading a core file, and when
   reading a binary file.  */

static struct gdbarch *
avr32_gdbarch_init (struct gdbarch_info info, struct gdbarch_list *arches)
{
  struct gdbarch *gdbarch;
  struct gdbarch_tdep *tdep;

  /* If there is already a candidate, use it. */
  arches = gdbarch_list_lookup_by_info(arches, &info);
  if (arches != NULL)
    return arches->gdbarch;

  /* None found, create a new architecture from the information
     provided. */
  tdep = xmalloc(sizeof(struct gdbarch_tdep));
  gdbarch = gdbarch_alloc(&info, tdep);

  /* Corefile: General-purpose registers.  Real values are filled in
     by OS-specific init.  */
  tdep->gregset = NULL;
  tdep->gregset_reg_offset = NULL;
  tdep->gregset_num_regs = 0;
  tdep->sizeof_gregset = 0;

  /* Breakpoints */
  tdep->avr32_breakpoint = avr32_default_breakpoint;
  tdep->avr32_breakpoint_size = sizeof(avr32_default_breakpoint);

  set_gdbarch_short_bit(gdbarch, 16);
  set_gdbarch_int_bit(gdbarch, 32);
  set_gdbarch_long_bit(gdbarch, 32);
  set_gdbarch_long_long_bit(gdbarch, 64);
  set_gdbarch_float_bit(gdbarch, 32);
  set_gdbarch_double_bit(gdbarch, 64);
  set_gdbarch_long_double_bit(gdbarch, 64);
  set_gdbarch_ptr_bit(gdbarch, 32);

  set_gdbarch_num_regs(gdbarch, AVR32_NUM_REGS);
  set_gdbarch_sp_regnum(gdbarch, AVR32_REG_SP);
  set_gdbarch_pc_regnum(gdbarch, AVR32_REG_PC);
  /* FIXME: What exactly is fp0? */
  set_gdbarch_fp0_regnum(gdbarch, -1);
  /* XXX: Should SR be a pseudo-register? */
  set_gdbarch_ps_regnum(gdbarch, -1);
  set_gdbarch_num_pseudo_regs(gdbarch, 0);

  set_gdbarch_register_type(gdbarch, avr32_register_type);
  set_gdbarch_register_name(gdbarch, avr32_register_name);
  set_gdbarch_breakpoint_from_pc(gdbarch, avr32_breakpoint_from_pc);
  set_gdbarch_print_insn(gdbarch, gdb_print_insn_avr32);
  set_gdbarch_write_pc(gdbarch, avr32_write_pc);

  set_gdbarch_return_value(gdbarch, avr32_return_value);

  set_gdbarch_skip_prologue(gdbarch, avr32_skip_prologue);
  set_gdbarch_inner_than(gdbarch, core_addr_lessthan);

  set_gdbarch_frame_align(gdbarch, avr32_frame_align);
  set_gdbarch_unwind_sp(gdbarch, avr32_unwind_sp);
  set_gdbarch_unwind_pc(gdbarch, avr32_unwind_pc);
  set_gdbarch_dummy_id(gdbarch, avr32_dummy_id);

  gdbarch_init_osabi(info, gdbarch);

  /* If the OS ABI provided a register mapping, enable the generic
     core file support (unless it has already been enabled.)  */
  if (tdep->gregset_reg_offset
      && !gdbarch_regset_from_core_section_p(gdbarch))
    set_gdbarch_regset_from_core_section(gdbarch,
					 avr32_regset_from_core_section);

  frame_base_append_sniffer(gdbarch, dwarf2_frame_base_sniffer);
  frame_base_append_sniffer(gdbarch, avr32_frame_base_sniffer);

  return gdbarch;
}

extern initialize_file_ftype _initialize_avr32_tdep; /* -Wmissing-prototypes */

void
_initialize_avr32_tdep(void)
{
  gdbarch_register(bfd_arch_avr32, avr32_gdbarch_init, NULL);

  /* "set sysreg NAME=VALUE"/"show sysreg NAME" */
  add_cmd("sysreg", class_vars, avr32_set_sysreg_command,
	  "Write VALUE to system register NAME.", &setlist);
  add_cmd("sysreg", class_vars, avr32_show_sysreg_command,
	  "Show the value of system register NAME.", &showlist);

  add_com("regs", class_vars, avr32_show_regs_command, "Print all registers");
}
