/* AVR32-specific support for 32-bit ELF.
   Copyright 2003,2004,2005,2006,2007,2008,2009 Atmel Corporation.

   Written by Haavard Skinnemoen, Atmel Norway, <hskinnemoen@atmel.com>

   This file is part of BFD, the Binary File Descriptor library.

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
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#include "sysdep.h"
#include "bfd.h"
#include "bfdlink.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "elf/avr32.h"
#include "elf32-avr32.h"

#define xDEBUG
#define xRELAX_DEBUG

#ifdef DEBUG
# define pr_debug(fmt, args...) fprintf(stderr, fmt, ##args)
#else
# define pr_debug(fmt, args...) do { } while (0)
#endif

#ifdef RELAX_DEBUG
# define RDBG(fmt, args...) fprintf(stderr, fmt, ##args)
#else
# define RDBG(fmt, args...) do { } while (0)
#endif

/* When things go wrong, we want it to blow up, damnit! */
#undef BFD_ASSERT
#undef abort
#define BFD_ASSERT(expr)					\
  do								\
    {								\
      if (!(expr))						\
	{							\
	  bfd_assert(__FILE__, __LINE__);			\
	  abort();						\
	}							\
    }								\
  while (0)

/* The name of the dynamic interpreter. This is put in the .interp section. */
#define ELF_DYNAMIC_INTERPRETER		"/lib/ld.so.1"

#define AVR32_GOT_HEADER_SIZE		8
#define AVR32_FUNCTION_STUB_SIZE	8

#define ELF_R_INFO(x, y) ELF32_R_INFO(x, y)
#define ELF_R_TYPE(x) ELF32_R_TYPE(x)
#define ELF_R_SYM(x) ELF32_R_SYM(x)

#define NOP_OPCODE 0xd703


/* Mapping between BFD relocations and ELF relocations */

static reloc_howto_type *
bfd_elf32_bfd_reloc_type_lookup(bfd *abfd, bfd_reloc_code_real_type code);

static reloc_howto_type *
bfd_elf32_bfd_reloc_name_lookup(bfd *abfd, const char *r_name);

static void
avr32_info_to_howto (bfd *abfd, arelent *cache_ptr, Elf_Internal_Rela *dst);

/* Generic HOWTO */
#define GENH(name, align, size, bitsize, pcrel, bitpos, complain, mask)	\
  HOWTO(name, align, size, bitsize, pcrel, bitpos,			\
	complain_overflow_##complain, bfd_elf_generic_reloc, #name,	\
	FALSE, 0, mask, pcrel)

static reloc_howto_type elf_avr32_howto_table[] = {
  /*   NAME		 ALN SZ BSZ PCREL  BP COMPLAIN  MASK	    */
  GENH(R_AVR32_NONE,	  0, 0, 0,  FALSE, 0, dont,	0x00000000),

  GENH(R_AVR32_32,	  0, 2, 32, FALSE, 0, dont,	0xffffffff),
  GENH(R_AVR32_16,	  0, 1, 16, FALSE, 0, bitfield,	0x0000ffff),
  GENH(R_AVR32_8,	  0, 0,  8, FALSE, 0, bitfield,	0x000000ff),
  GENH(R_AVR32_32_PCREL,  0, 2, 32, TRUE,  0, signed,   0xffffffff),
  GENH(R_AVR32_16_PCREL,  0, 1, 16, TRUE,  0, signed,   0x0000ffff),
  GENH(R_AVR32_8_PCREL,	  0, 0,  8, TRUE,  0, signed,   0x000000ff),

  /* Difference between two symbol (sym2 - sym1).  The reloc encodes
     the value of sym1.  The field contains the difference before any
     relaxing is done.  */
  GENH(R_AVR32_DIFF32,	  0, 2, 32, FALSE, 0, dont,	0xffffffff),
  GENH(R_AVR32_DIFF16,	  0, 1, 16, FALSE, 0, signed,	0x0000ffff),
  GENH(R_AVR32_DIFF8,	  0, 0,  8, FALSE, 0, signed,	0x000000ff),

  GENH(R_AVR32_GOT32,	  0, 2, 32, FALSE, 0, signed,	0xffffffff),
  GENH(R_AVR32_GOT16,	  0, 1, 16, FALSE, 0, signed,	0x0000ffff),
  GENH(R_AVR32_GOT8,	  0, 0,  8, FALSE, 0, signed,	0x000000ff),

  GENH(R_AVR32_21S,	  0, 2, 21, FALSE, 0, signed,	0x1e10ffff),
  GENH(R_AVR32_16U,	  0, 2, 16, FALSE, 0, unsigned,	0x0000ffff),
  GENH(R_AVR32_16S,	  0, 2, 16, FALSE, 0, signed,	0x0000ffff),
  GENH(R_AVR32_8S,	  0, 1,  8, FALSE, 4, signed,	0x00000ff0),
  GENH(R_AVR32_8S_EXT,	  0, 2,  8, FALSE, 0, signed,	0x000000ff),

  GENH(R_AVR32_22H_PCREL, 1, 2, 21, TRUE,  0, signed,	0x1e10ffff),
  GENH(R_AVR32_18W_PCREL, 2, 2, 16, TRUE,  0, signed,	0x0000ffff),
  GENH(R_AVR32_16B_PCREL, 0, 2, 16, TRUE,  0, signed,	0x0000ffff),
  GENH(R_AVR32_16N_PCREL, 0, 2, 16, TRUE,  0, signed,	0x0000ffff),
  GENH(R_AVR32_14UW_PCREL, 2, 2, 12, TRUE, 0, unsigned, 0x0000f0ff),
  GENH(R_AVR32_11H_PCREL, 1, 1, 10, TRUE,  4, signed,	0x00000ff3),
  GENH(R_AVR32_10UW_PCREL, 2, 2, 8, TRUE,  0, unsigned, 0x000000ff),
  GENH(R_AVR32_9H_PCREL,  1, 1,  8, TRUE,  4, signed,	0x00000ff0),
  GENH(R_AVR32_9UW_PCREL, 2, 1,  7, TRUE,  4, unsigned,	0x000007f0),

  GENH(R_AVR32_HI16,	 16, 2, 16, FALSE, 0, dont,	0x0000ffff),
  GENH(R_AVR32_LO16,	  0, 2, 16, FALSE, 0, dont,	0x0000ffff),

  GENH(R_AVR32_GOTPC,	  0, 2, 32, FALSE, 0, dont,	0xffffffff),
  GENH(R_AVR32_GOTCALL,   2, 2, 21, FALSE, 0, signed,	0x1e10ffff),
  GENH(R_AVR32_LDA_GOT,	  2, 2, 21, FALSE, 0, signed,	0x1e10ffff),
  GENH(R_AVR32_GOT21S,	  0, 2, 21, FALSE, 0, signed,	0x1e10ffff),
  GENH(R_AVR32_GOT18SW,	  2, 2, 16, FALSE, 0, signed,	0x0000ffff),
  GENH(R_AVR32_GOT16S,	  0, 2, 16, FALSE, 0, signed,	0x0000ffff),
  GENH(R_AVR32_GOT7UW,	  2, 1,  5, FALSE, 4, unsigned, 0x000001f0),

  GENH(R_AVR32_32_CPENT,  0, 2, 32, FALSE, 0, dont,	0xffffffff),
  GENH(R_AVR32_CPCALL,	  2, 2, 16, TRUE,  0, signed,	0x0000ffff),
  GENH(R_AVR32_16_CP,	  0, 2, 16, TRUE,  0, signed,	0x0000ffff),
  GENH(R_AVR32_9W_CP,	  2, 1,  7, TRUE,  4, unsigned, 0x000007f0),

  GENH(R_AVR32_RELATIVE,  0, 2, 32, FALSE, 0, signed,	0xffffffff),
  GENH(R_AVR32_GLOB_DAT,  0, 2, 32, FALSE, 0, dont,	0xffffffff),
  GENH(R_AVR32_JMP_SLOT,  0, 2, 32, FALSE, 0, dont,	0xffffffff),

  GENH(R_AVR32_ALIGN,	  0, 1, 0,  FALSE, 0, unsigned, 0x00000000),

  GENH(R_AVR32_15S,	  2, 2, 15, FALSE, 0, signed,	0x00007fff),
};

struct elf_reloc_map
{
  bfd_reloc_code_real_type bfd_reloc_val;
  unsigned char elf_reloc_val;
};

static const struct elf_reloc_map avr32_reloc_map[] =
{
  { BFD_RELOC_NONE,			R_AVR32_NONE },

  { BFD_RELOC_32,			R_AVR32_32 },
  { BFD_RELOC_16,			R_AVR32_16 },
  { BFD_RELOC_8,			R_AVR32_8 },
  { BFD_RELOC_32_PCREL,			R_AVR32_32_PCREL },
  { BFD_RELOC_16_PCREL,			R_AVR32_16_PCREL },
  { BFD_RELOC_8_PCREL,			R_AVR32_8_PCREL },
  { BFD_RELOC_AVR32_DIFF32,		R_AVR32_DIFF32 },
  { BFD_RELOC_AVR32_DIFF16,		R_AVR32_DIFF16 },
  { BFD_RELOC_AVR32_DIFF8,		R_AVR32_DIFF8 },
  { BFD_RELOC_AVR32_GOT32,		R_AVR32_GOT32 },
  { BFD_RELOC_AVR32_GOT16,		R_AVR32_GOT16 },
  { BFD_RELOC_AVR32_GOT8,		R_AVR32_GOT8 },

  { BFD_RELOC_AVR32_21S,		R_AVR32_21S },
  { BFD_RELOC_AVR32_16U,		R_AVR32_16U },
  { BFD_RELOC_AVR32_16S,		R_AVR32_16S },
  { BFD_RELOC_AVR32_SUB5,		R_AVR32_16S },
  { BFD_RELOC_AVR32_8S_EXT,		R_AVR32_8S_EXT },
  { BFD_RELOC_AVR32_8S,			R_AVR32_8S },

  { BFD_RELOC_AVR32_22H_PCREL,		R_AVR32_22H_PCREL },
  { BFD_RELOC_AVR32_18W_PCREL,		R_AVR32_18W_PCREL },
  { BFD_RELOC_AVR32_16B_PCREL,		R_AVR32_16B_PCREL },
  { BFD_RELOC_AVR32_16N_PCREL,		R_AVR32_16N_PCREL },
  { BFD_RELOC_AVR32_11H_PCREL,		R_AVR32_11H_PCREL },
  { BFD_RELOC_AVR32_10UW_PCREL,		R_AVR32_10UW_PCREL },
  { BFD_RELOC_AVR32_9H_PCREL,		R_AVR32_9H_PCREL },
  { BFD_RELOC_AVR32_9UW_PCREL,		R_AVR32_9UW_PCREL },

  { BFD_RELOC_HI16,			R_AVR32_HI16 },
  { BFD_RELOC_LO16,			R_AVR32_LO16 },

  { BFD_RELOC_AVR32_GOTPC,		R_AVR32_GOTPC },
  { BFD_RELOC_AVR32_GOTCALL,		R_AVR32_GOTCALL },
  { BFD_RELOC_AVR32_LDA_GOT,		R_AVR32_LDA_GOT },
  { BFD_RELOC_AVR32_GOT21S,		R_AVR32_GOT21S },
  { BFD_RELOC_AVR32_GOT18SW,		R_AVR32_GOT18SW },
  { BFD_RELOC_AVR32_GOT16S,		R_AVR32_GOT16S },
  /* GOT7UW should never be generated by the assembler */

  { BFD_RELOC_AVR32_32_CPENT,		R_AVR32_32_CPENT },
  { BFD_RELOC_AVR32_CPCALL,		R_AVR32_CPCALL },
  { BFD_RELOC_AVR32_16_CP,		R_AVR32_16_CP },
  { BFD_RELOC_AVR32_9W_CP,		R_AVR32_9W_CP },

  { BFD_RELOC_AVR32_ALIGN,		R_AVR32_ALIGN },

  { BFD_RELOC_AVR32_15S,		R_AVR32_15S },
};

static reloc_howto_type *
bfd_elf32_bfd_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
				 bfd_reloc_code_real_type code)
{
  unsigned int i;

  for (i = 0; i < sizeof(avr32_reloc_map) / sizeof(struct elf_reloc_map); i++)
    {
      if (avr32_reloc_map[i].bfd_reloc_val == code)
	return &elf_avr32_howto_table[avr32_reloc_map[i].elf_reloc_val];
    }

  return NULL;
}

static reloc_howto_type *
bfd_elf32_bfd_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
                 const char *r_name)
{
  unsigned int i;

  for (i = 0;
       i < sizeof (elf_avr32_howto_table) / sizeof (elf_avr32_howto_table[0]);
       i++)
    if (elf_avr32_howto_table[i].name != NULL
    && strcasecmp (elf_avr32_howto_table[i].name, r_name) == 0)
      return &elf_avr32_howto_table[i];

  return NULL;
}

/* Set the howto pointer for an AVR32 ELF reloc.  */
static void
avr32_info_to_howto (bfd *abfd ATTRIBUTE_UNUSED,
		     arelent *cache_ptr,
		     Elf_Internal_Rela *dst)
{
  unsigned int r_type;

  r_type = ELF32_R_TYPE (dst->r_info);
  BFD_ASSERT (r_type < (unsigned int) R_AVR32_max);
  cache_ptr->howto = &elf_avr32_howto_table[r_type];
}


/* AVR32 ELF linker hash table and associated hash entries. */

static struct bfd_hash_entry *
avr32_elf_link_hash_newfunc(struct bfd_hash_entry *entry,
			    struct bfd_hash_table *table,
			    const char *string);
static void
avr32_elf_copy_indirect_symbol(struct bfd_link_info *info,
			       struct elf_link_hash_entry *dir,
			       struct elf_link_hash_entry *ind);
static struct bfd_link_hash_table *
avr32_elf_link_hash_table_create(bfd *abfd);

/*
  Try to limit memory usage to something reasonable when sorting the
  GOT.  If just a couple of entries end up getting more references
  than this, it won't affect performance at all, but if there are many
  of them, we could end up with the wrong symbols being assigned the
  first GOT entries.
*/
#define MAX_NR_GOT_HOLES	2048

/*
  AVR32 GOT entry.  We need to keep track of refcounts and offsets
  simultaneously, since we need the offsets during relaxation, and we
  also want to be able to drop GOT entries during relaxation. In
  addition to this, we want to keep the list of GOT entries sorted so
  that we can keep the most-used entries at the lowest offsets.
*/
struct got_entry
{
  struct got_entry *next;
  struct got_entry **pprev;
  int refcount;
  bfd_signed_vma offset;
};

struct elf_avr32_link_hash_entry
{
  struct elf_link_hash_entry root;

  /* Number of runtime relocations against this symbol.  */
  unsigned int possibly_dynamic_relocs;

  /* If there are anything but R_AVR32_GOT18 relocations against this
     symbol, it means that someone may be taking the address of the
     function, and we should therefore not create a stub.  */
  bfd_boolean no_fn_stub;

  /* If there is a R_AVR32_32 relocation in a read-only section
     against this symbol, we could be in trouble. If we're linking a
     shared library or this symbol is defined in one, it means we must
     emit a run-time reloc for it and that's not allowed in read-only
     sections.  */
  asection *readonly_reloc_sec;
  bfd_vma readonly_reloc_offset;

  /* Record which frag (if any) contains the symbol.  This is used
     during relaxation in order to avoid having to update all symbols
     whenever we move something.  For local symbols, this information
     is in the local_sym_frag member of struct elf_obj_tdata.  */
  struct fragment *sym_frag;
};
#define avr32_elf_hash_entry(ent) ((struct elf_avr32_link_hash_entry *)(ent))

struct elf_avr32_link_hash_table
{
  struct elf_link_hash_table root;

  /* Shortcuts to get to dynamic linker sections.  */
  asection *sgot;
  asection *srelgot;
  asection *sstub;

  /* We use a variation of Pigeonhole Sort to sort the GOT.  After the
     initial refcounts have been determined, we initialize
     nr_got_holes to the highest refcount ever seen and allocate an
     array of nr_got_holes entries for got_hole.  Each GOT entry is
     then stored in this array at the index given by its refcount.

     When a GOT entry has its refcount decremented during relaxation,
     it is moved to a lower index in the got_hole array.
   */
  struct got_entry **got_hole;
  int nr_got_holes;

  /* Dynamic relocations to local symbols.  Only used when linking a
     shared library and -Bsymbolic is not given.  */
  unsigned int local_dynamic_relocs;

  bfd_boolean relocations_analyzed;
  bfd_boolean symbols_adjusted;
  bfd_boolean repeat_pass;
  bfd_boolean direct_data_refs;
  unsigned int relax_iteration;
  unsigned int relax_pass;
};
#define avr32_elf_hash_table(p)				\
  ((struct elf_avr32_link_hash_table *)((p)->hash))

static struct bfd_hash_entry *
avr32_elf_link_hash_newfunc(struct bfd_hash_entry *entry,
			    struct bfd_hash_table *table,
			    const char *string)
{
  struct elf_avr32_link_hash_entry *ret = avr32_elf_hash_entry(entry);

  /* Allocate the structure if it hasn't already been allocated by a
     subclass */
  if (ret == NULL)
    ret = (struct elf_avr32_link_hash_entry *)
      bfd_hash_allocate(table, sizeof(struct elf_avr32_link_hash_entry));

  if (ret == NULL)
    return NULL;

  memset(ret, 0, sizeof(struct elf_avr32_link_hash_entry));

  /* Give the superclass a chance */
  ret = (struct elf_avr32_link_hash_entry *)
    _bfd_elf_link_hash_newfunc((struct bfd_hash_entry *)ret, table, string);

  return (struct bfd_hash_entry *)ret;
}

/* Copy data from an indirect symbol to its direct symbol, hiding the
   old indirect symbol.  Process additional relocation information.
   Also called for weakdefs, in which case we just let
   _bfd_elf_link_hash_copy_indirect copy the flags for us.  */

static void
avr32_elf_copy_indirect_symbol(struct bfd_link_info *info,
			       struct elf_link_hash_entry *dir,
			       struct elf_link_hash_entry *ind)
{
  struct elf_avr32_link_hash_entry *edir, *eind;

  _bfd_elf_link_hash_copy_indirect (info, dir, ind);

  if (ind->root.type != bfd_link_hash_indirect)
    return;

  edir = (struct elf_avr32_link_hash_entry *)dir;
  eind = (struct elf_avr32_link_hash_entry *)ind;

  edir->possibly_dynamic_relocs += eind->possibly_dynamic_relocs;
  edir->no_fn_stub = edir->no_fn_stub || eind->no_fn_stub;
}

static struct bfd_link_hash_table *
avr32_elf_link_hash_table_create(bfd *abfd)
{
  struct elf_avr32_link_hash_table *ret;

  ret = bfd_zmalloc(sizeof(*ret));
  if (ret == NULL)
    return NULL;

  if (! _bfd_elf_link_hash_table_init(&ret->root, abfd,
				      avr32_elf_link_hash_newfunc,
                      sizeof (struct elf_avr32_link_hash_entry),
		      AVR32_ELF_DATA))
    {
      free(ret);
      return NULL;
    }

  /* Prevent the BFD core from creating bogus got_entry pointers */
  ret->root.init_got_refcount.glist = NULL;
  ret->root.init_plt_refcount.glist = NULL;
  ret->root.init_got_offset.glist = NULL;
  ret->root.init_plt_offset.glist = NULL;

  return &ret->root.root;
}


/* Initial analysis and creation of dynamic sections and symbols */

static asection *
create_dynamic_section(bfd *dynobj, const char *name, flagword flags,
		       unsigned int align_power);
static struct elf_link_hash_entry *
create_dynamic_symbol(bfd *dynobj, struct bfd_link_info *info,
		      const char *name, asection *sec,
		      bfd_vma offset);
static bfd_boolean
avr32_elf_create_got_section (bfd *dynobj, struct bfd_link_info *info);
static bfd_boolean
avr32_elf_create_dynamic_sections (bfd *dynobj, struct bfd_link_info *info);
static bfd_boolean
avr32_check_relocs (bfd *abfd, struct bfd_link_info *info, asection *sec,
		    const Elf_Internal_Rela *relocs);
static bfd_boolean
avr32_elf_adjust_dynamic_symbol(struct bfd_link_info *info,
				struct elf_link_hash_entry *h);

static asection *
create_dynamic_section(bfd *dynobj, const char *name, flagword flags,
		       unsigned int align_power)
{
  asection *sec;

  sec = bfd_make_section(dynobj, name);
  if (!sec
      || !bfd_set_section_flags(dynobj, sec, flags)
      || !bfd_set_section_alignment(dynobj, sec, align_power))
    return NULL;

  return sec;
}

static struct elf_link_hash_entry *
create_dynamic_symbol(bfd *dynobj, struct bfd_link_info *info,
		      const char *name, asection *sec,
		      bfd_vma offset)
{
  struct bfd_link_hash_entry *bh = NULL;
  struct elf_link_hash_entry *h;
  const struct elf_backend_data *bed = get_elf_backend_data (dynobj);

  if (!(_bfd_generic_link_add_one_symbol
	(info, dynobj, name, BSF_GLOBAL, sec, offset, NULL, FALSE,
	 bed->collect, &bh)))
    return NULL;

  h = (struct elf_link_hash_entry *)bh;
  h->def_regular = 1;
  h->type = STT_OBJECT;
  h->other = STV_HIDDEN;

  return h;
}

static bfd_boolean
avr32_elf_create_got_section (bfd *dynobj, struct bfd_link_info *info)
{
  struct elf_avr32_link_hash_table *htab;
  flagword flags;
  const struct elf_backend_data *bed = get_elf_backend_data (dynobj);

  htab = avr32_elf_hash_table(info);
  flags = bed->dynamic_sec_flags;

  if (htab->sgot)
    return TRUE;

  htab->sgot = create_dynamic_section(dynobj, ".got", flags, 2);
  if (!htab->srelgot)
    htab->srelgot = create_dynamic_section(dynobj, ".rela.got",
					   flags | SEC_READONLY, 2);

  if (!htab->sgot || !htab->srelgot)
    return FALSE;

  htab->root.hgot = create_dynamic_symbol(dynobj, info, "_GLOBAL_OFFSET_TABLE_",
					  htab->sgot, 0);
  if (!htab->root.hgot)
    return FALSE;

  /* Make room for the GOT header */
  htab->sgot->size += bed->got_header_size;

  return TRUE;
}

/* (1) Create all dynamic (i.e. linker generated) sections that we may
   need during the link */

static bfd_boolean
avr32_elf_create_dynamic_sections (bfd *dynobj, struct bfd_link_info *info)
{
  struct elf_avr32_link_hash_table *htab;
  flagword flags;
  const struct elf_backend_data *bed = get_elf_backend_data (dynobj);

  pr_debug("(1) create dynamic sections\n");

  htab = avr32_elf_hash_table(info);
  flags = bed->dynamic_sec_flags;

  if (!avr32_elf_create_got_section (dynobj, info))
    return FALSE;

  if (!htab->sstub)
    htab->sstub = create_dynamic_section(dynobj, ".stub",
					 flags | SEC_READONLY | SEC_CODE, 2);

  if (!htab->sstub)
    return FALSE;

  return TRUE;
}

/* (2) Go through all the relocs and count any potential GOT- or
   PLT-references to each symbol */

static bfd_boolean
avr32_check_relocs (bfd *abfd, struct bfd_link_info *info, asection *sec,
		    const Elf_Internal_Rela *relocs)
{
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_avr32_link_hash_table *htab;
  struct elf_link_hash_entry **sym_hashes;
  const Elf_Internal_Rela *rel, *rel_end;
  struct got_entry **local_got_ents;
  struct got_entry *got;
  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
  asection *sgot;
  bfd *dynobj;

  pr_debug("(2) check relocs for %s:<%s> (size 0x%lx)\n",
	   abfd->filename, sec->name, sec->size);

  if (info->relocatable)
    return TRUE;

  dynobj = elf_hash_table(info)->dynobj;
  symtab_hdr = &elf_tdata(abfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes(abfd);
  htab = avr32_elf_hash_table(info);
  local_got_ents = elf_local_got_ents(abfd);
  sgot = htab->sgot;

  rel_end = relocs + sec->reloc_count;
  for (rel = relocs; rel < rel_end; rel++)
    {
      unsigned long r_symndx, r_type;
      struct elf_avr32_link_hash_entry *h;

      r_symndx = ELF32_R_SYM(rel->r_info);
      r_type = ELF32_R_TYPE(rel->r_info);

      /* Local symbols use local_got_ents, while others store the same
	 information in the hash entry */
      if (r_symndx < symtab_hdr->sh_info)
	{
	  pr_debug("  (2a) processing local symbol %lu\n", r_symndx);
	  h = NULL;
	}
      else
	{
	  h = (struct elf_avr32_link_hash_entry *)
	    sym_hashes[r_symndx - symtab_hdr->sh_info];
	  while (h->root.type == bfd_link_hash_indirect
		 || h->root.type == bfd_link_hash_warning)
	    h = (struct elf_avr32_link_hash_entry *)h->root.root.u.i.link;
	  pr_debug("  (2a) processing symbol %s\n", h->root.root.root.string);
	}

      /* Some relocs require special sections to be created.  */
      switch (r_type)
	{
	case R_AVR32_GOT32:
	case R_AVR32_GOT16:
	case R_AVR32_GOT8:
	case R_AVR32_GOT21S:
	case R_AVR32_GOT18SW:
	case R_AVR32_GOT16S:
	case R_AVR32_GOT7UW:
	case R_AVR32_LDA_GOT:
	case R_AVR32_GOTCALL:
	  if (rel->r_addend)
	    {
	      if (info->callbacks->reloc_dangerous
		  (info, _("Non-zero addend on GOT-relative relocation"),
		   abfd, sec, rel->r_offset) == FALSE)
		return FALSE;
	    }
	  /* fall through */
	case R_AVR32_GOTPC:
	  if (dynobj == NULL)
	    elf_hash_table(info)->dynobj = dynobj = abfd;
	  if (sgot == NULL && !avr32_elf_create_got_section(dynobj, info))
	    return FALSE;
	  break;
	case R_AVR32_32:
	  /* We may need to create .rela.dyn later on.  */
	  if (dynobj == NULL
	      && (info->shared || h != NULL)
	      && (sec->flags & SEC_ALLOC))
	    elf_hash_table(info)->dynobj = dynobj = abfd;
	  break;
	}

      if (h != NULL && r_type != R_AVR32_GOT18SW)
	h->no_fn_stub = TRUE;

      switch (r_type)
	{
	case R_AVR32_GOT32:
	case R_AVR32_GOT16:
	case R_AVR32_GOT8:
	case R_AVR32_GOT21S:
	case R_AVR32_GOT18SW:
	case R_AVR32_GOT16S:
	case R_AVR32_GOT7UW:
	case R_AVR32_LDA_GOT:
	case R_AVR32_GOTCALL:
	  if (h != NULL)
	    {
	      got = h->root.got.glist;
	      if (!got)
		{
		  got = bfd_zalloc(abfd, sizeof(struct got_entry));
		  if (!got)
		    return FALSE;
		  h->root.got.glist = got;
		}
	    }
	  else
	    {
	      if (!local_got_ents)
		{
		  bfd_size_type size;
		  bfd_size_type i;
		  struct got_entry *tmp_entry;

		  size = symtab_hdr->sh_info;
		  size *= sizeof(struct got_entry *) + sizeof(struct got_entry);
		  local_got_ents = bfd_zalloc(abfd, size);
		  if (!local_got_ents)
		    return FALSE;

		  elf_local_got_ents(abfd) = local_got_ents;

		  tmp_entry = (struct got_entry *)(local_got_ents
						   + symtab_hdr->sh_info);
		  for (i = 0; i < symtab_hdr->sh_info; i++)
		    local_got_ents[i] = &tmp_entry[i];
		}

	      got = local_got_ents[r_symndx];
	    }

	  got->refcount++;
	  if (got->refcount > htab->nr_got_holes)
	    htab->nr_got_holes = got->refcount;
	  break;

	case R_AVR32_32:
	  if ((info->shared || h != NULL)
	      && (sec->flags & SEC_ALLOC))
	    {
	      if (htab->srelgot == NULL)
		{
		  htab->srelgot = create_dynamic_section(dynobj, ".rela.got",
							 bed->dynamic_sec_flags
							 | SEC_READONLY, 2);
		  if (htab->srelgot == NULL)
		    return FALSE;
		}

	      if (sec->flags & SEC_READONLY
		  && !h->readonly_reloc_sec)
		{
		  h->readonly_reloc_sec = sec;
		  h->readonly_reloc_offset = rel->r_offset;
		}

	      if (h != NULL)
		{
		  pr_debug("Non-GOT reference to symbol %s\n",
			   h->root.root.root.string);
		  h->possibly_dynamic_relocs++;
		}
	      else
		{
		  pr_debug("Non-GOT reference to local symbol %lu\n",
			   r_symndx);
		  htab->local_dynamic_relocs++;
		}
	    }

	  break;

	  /* TODO: GNU_VTINHERIT and GNU_VTENTRY */
	}
    }

  return TRUE;
}

/* (3) Adjust a symbol defined by a dynamic object and referenced by a
   regular object.  The current definition is in some section of the
   dynamic object, but we're not including those sections.  We have to
   change the definition to something the rest of the link can
   understand.  */

static bfd_boolean
avr32_elf_adjust_dynamic_symbol(struct bfd_link_info *info,
				struct elf_link_hash_entry *h)
{
  struct elf_avr32_link_hash_table *htab;
  struct elf_avr32_link_hash_entry *havr;
  bfd *dynobj;

  pr_debug("(3) adjust dynamic symbol %s\n", h->root.root.string);

  htab = avr32_elf_hash_table(info);
  havr = (struct elf_avr32_link_hash_entry *)h;
  dynobj = elf_hash_table(info)->dynobj;

  /* Make sure we know what is going on here.  */
  BFD_ASSERT (dynobj != NULL
	      && (h->u.weakdef != NULL
		  || (h->def_dynamic
		      && h->ref_regular
		      && !h->def_regular)));

  /* We don't want dynamic relocations in read-only sections. */
  if (havr->readonly_reloc_sec)
    {
      if (info->callbacks->reloc_dangerous
	  (info, _("dynamic relocation in read-only section"),
	   havr->readonly_reloc_sec->owner, havr->readonly_reloc_sec,
	   havr->readonly_reloc_offset) == FALSE)
	return FALSE;
    }

  /* If this is a function, create a stub if possible and set the
     symbol to the stub location.  */
  if (0 && !havr->no_fn_stub)
    {
      if (!h->def_regular)
	{
	  asection *s = htab->sstub;

	  BFD_ASSERT(s != NULL);

	  h->root.u.def.section = s;
	  h->root.u.def.value = s->size;
	  h->plt.offset = s->size;
	  s->size += AVR32_FUNCTION_STUB_SIZE;

	  return TRUE;
	}
    }
  else if (h->type == STT_FUNC)
    {
      /* This will set the entry for this symbol in the GOT to 0, and
	 the dynamic linker will take care of this. */
      h->root.u.def.value = 0;
      return TRUE;
    }

  /* If this is a weak symbol, and there is a real definition, the
     processor independent code will have arranged for us to see the
     real definition first, and we can just use the same value.  */
  if (h->u.weakdef != NULL)
    {
      BFD_ASSERT(h->u.weakdef->root.type == bfd_link_hash_defined
		 || h->u.weakdef->root.type == bfd_link_hash_defweak);
      h->root.u.def.section = h->u.weakdef->root.u.def.section;
      h->root.u.def.value = h->u.weakdef->root.u.def.value;
      return TRUE;
    }

  /* This is a reference to a symbol defined by a dynamic object which
     is not a function.  */

  return TRUE;
}


/* Garbage-collection of unused sections */

static asection *
avr32_elf_gc_mark_hook(asection *sec,
		       struct bfd_link_info *info ATTRIBUTE_UNUSED,
		       Elf_Internal_Rela *rel,
		       struct elf_link_hash_entry *h,
		       Elf_Internal_Sym *sym)
{
  if (h)
    {
      switch (ELF32_R_TYPE(rel->r_info))
	{
	  /* TODO: VTINHERIT/VTENTRY */
	default:
	  switch (h->root.type)
	    {
	    case bfd_link_hash_defined:
	    case bfd_link_hash_defweak:
	      return h->root.u.def.section;

	    case bfd_link_hash_common:
	      return h->root.u.c.p->section;

	    default:
	      break;
	    }
	}
    }
  else
    return bfd_section_from_elf_index(sec->owner, sym->st_shndx);

  return NULL;
}

/* Update the GOT entry reference counts for the section being removed. */
static bfd_boolean
avr32_elf_gc_sweep_hook(bfd *abfd,
			struct bfd_link_info *info ATTRIBUTE_UNUSED,
			asection *sec,
			const Elf_Internal_Rela *relocs)
{
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_avr32_link_hash_entry **sym_hashes;
  struct got_entry **local_got_ents;
  const Elf_Internal_Rela *rel, *relend;

  if (!(sec->flags & SEC_ALLOC))
    return TRUE;

  symtab_hdr = &elf_tdata(abfd)->symtab_hdr;
  sym_hashes = (struct elf_avr32_link_hash_entry **)elf_sym_hashes(abfd);
  local_got_ents = elf_local_got_ents(abfd);

  relend = relocs + sec->reloc_count;
  for (rel = relocs; rel < relend; rel++)
    {
      unsigned long r_symndx;
      unsigned int r_type;
      struct elf_avr32_link_hash_entry *h = NULL;

      r_symndx = ELF32_R_SYM(rel->r_info);
      if (r_symndx >= symtab_hdr->sh_info)
	{
	  h = sym_hashes[r_symndx - symtab_hdr->sh_info];
	  while (h->root.root.type == bfd_link_hash_indirect
		 || h->root.root.type == bfd_link_hash_warning)
	    h = (struct elf_avr32_link_hash_entry *)h->root.root.u.i.link;
	}

      r_type = ELF32_R_TYPE(rel->r_info);

      switch (r_type)
	{
	case R_AVR32_GOT32:
	case R_AVR32_GOT16:
	case R_AVR32_GOT8:
	case R_AVR32_GOT21S:
	case R_AVR32_GOT18SW:
	case R_AVR32_GOT16S:
	case R_AVR32_GOT7UW:
	case R_AVR32_LDA_GOT:
	case R_AVR32_GOTCALL:
	  if (h)
	    h->root.got.glist->refcount--;
	  else
	    local_got_ents[r_symndx]->refcount--;
	  break;

	case R_AVR32_32:
	  if (info->shared || h)
	    {
	      if (h)
		h->possibly_dynamic_relocs--;
	      else
		avr32_elf_hash_table(info)->local_dynamic_relocs--;
	    }

	default:
	  break;
	}
    }

  return TRUE;
}

/* Sizing and refcounting of dynamic sections */

static void
insert_got_entry(struct elf_avr32_link_hash_table *htab, struct got_entry *got);
static void
unref_got_entry(struct elf_avr32_link_hash_table *htab, struct got_entry *got);
static void
ref_got_entry(struct elf_avr32_link_hash_table *htab, struct got_entry *got);
static bfd_boolean
assign_got_offsets(struct elf_avr32_link_hash_table *htab);
static bfd_boolean
allocate_dynrelocs(struct elf_link_hash_entry *h, void *_info);
static bfd_boolean
avr32_elf_size_dynamic_sections (bfd *output_bfd,
				 struct bfd_link_info *info);

static void
insert_got_entry(struct elf_avr32_link_hash_table *htab, struct got_entry *got)
{
  /* Any entries with got_refcount > htab->nr_got_holes end up in the
   * last pigeonhole without any sorting. We expect the number of such
   * entries to be small, so it is very unlikely to affect
   * performance.  */
  int entry = got->refcount;

  if (entry > htab->nr_got_holes)
    entry = htab->nr_got_holes;

  got->pprev = &htab->got_hole[entry];
  got->next = htab->got_hole[entry];

  if (got->next)
    got->next->pprev = &got->next;

  htab->got_hole[entry] = got;
}

/* Decrement the refcount of a GOT entry and update its position in
   the pigeonhole array.  */
static void
unref_got_entry(struct elf_avr32_link_hash_table *htab, struct got_entry *got)
{
  BFD_ASSERT(got->refcount > 0);

  if (got->next)
    got->next->pprev = got->pprev;

  *(got->pprev) = got->next;
  got->refcount--;
  insert_got_entry(htab, got);
}

static void
ref_got_entry(struct elf_avr32_link_hash_table *htab, struct got_entry *got)
{
  if (got->next)
    got->next->pprev = got->pprev;

  *(got->pprev) = got->next;
  got->refcount++;
  insert_got_entry(htab, got);

  BFD_ASSERT(got->refcount > 0);
}

/* Assign offsets to all GOT entries we intend to keep.  The entries
   that are referenced most often are placed at low offsets so that we
   can use compact instructions as much as possible.

   Returns TRUE if any offsets or the total size of the GOT changed.  */

static bfd_boolean
assign_got_offsets(struct elf_avr32_link_hash_table *htab)
{
  struct got_entry *got;
  bfd_size_type got_size = 0;
  bfd_boolean changed = FALSE;
  bfd_signed_vma offset;
  int i;

  /* The GOT header provides the address of the DYNAMIC segment, so
     we need that even if the GOT is otherwise empty.  */
  if (htab->root.dynamic_sections_created)
    got_size = AVR32_GOT_HEADER_SIZE;

  for (i = htab->nr_got_holes; i > 0; i--)
    {
      got = htab->got_hole[i];
      while (got)
	{
	  if (got->refcount > 0)
	    {
	      offset = got_size;
	      if (got->offset != offset)
		{
		  RDBG("GOT offset changed: %ld -> %ld\n",
		       got->offset, offset);
		  changed = TRUE;
		}
	      got->offset = offset;
	      got_size += 4;
	    }
	  got = got->next;
	}
    }

  if (htab->sgot->size != got_size)
    {
      RDBG("GOT size changed: %lu -> %lu\n", htab->sgot->size,
	   got_size);
      changed = TRUE;
    }
  htab->sgot->size = got_size;

  RDBG("assign_got_offsets: total size %lu (%s)\n",
       got_size, changed ? "changed" : "no change");

  return changed;
}

static bfd_boolean
allocate_dynrelocs(struct elf_link_hash_entry *h, void *_info)
{
  struct bfd_link_info *info = _info;
  struct elf_avr32_link_hash_table *htab;
  struct elf_avr32_link_hash_entry *havr;
  struct got_entry *got;

  pr_debug("  (4b) allocate_dynrelocs: %s\n", h->root.root.string);

  if (h->root.type == bfd_link_hash_indirect)
    return TRUE;

  if (h->root.type == bfd_link_hash_warning)
    /* When warning symbols are created, they **replace** the "real"
       entry in the hash table, thus we never get to see the real
       symbol in a hash traversal.  So look at it now.  */
    h = (struct elf_link_hash_entry *) h->root.u.i.link;

  htab = avr32_elf_hash_table(info);
  havr = (struct elf_avr32_link_hash_entry *)h;

  got = h->got.glist;

  /* If got is NULL, the symbol is never referenced through the GOT */
  if (got && got->refcount > 0)
    {
      insert_got_entry(htab, got);

      /* Shared libraries need relocs for all GOT entries unless the
	 symbol is forced local or -Bsymbolic is used.  Others need
	 relocs for everything that is not guaranteed to be defined in
	 a regular object.  */
      if ((info->shared
	   && !info->symbolic
	   && h->dynindx != -1)
	  || (htab->root.dynamic_sections_created
	      && h->def_dynamic
	      && !h->def_regular))
	htab->srelgot->size += sizeof(Elf32_External_Rela);
    }

  if (havr->possibly_dynamic_relocs
      && (info->shared
	  || (elf_hash_table(info)->dynamic_sections_created
	      && h->def_dynamic
	      && !h->def_regular)))
    {
      pr_debug("Allocating %d dynamic reloc against symbol %s...\n",
	       havr->possibly_dynamic_relocs, h->root.root.string);
      htab->srelgot->size += (havr->possibly_dynamic_relocs
			      * sizeof(Elf32_External_Rela));
    }

  return TRUE;
}

/* (4) Calculate the sizes of the linker-generated sections and
   allocate memory for them.  */

static bfd_boolean
avr32_elf_size_dynamic_sections (bfd *output_bfd,
				 struct bfd_link_info *info)
{
  struct elf_avr32_link_hash_table *htab;
  bfd *dynobj;
  asection *s;
  bfd *ibfd;
  bfd_boolean relocs;

  pr_debug("(4) size dynamic sections\n");

  htab = avr32_elf_hash_table(info);
  dynobj = htab->root.dynobj;
  BFD_ASSERT(dynobj != NULL);

  if (htab->root.dynamic_sections_created)
    {
      /* Initialize the contents of the .interp section to the name of
	 the dynamic loader */
      if (info->executable)
	{
	  s = bfd_get_section_by_name(dynobj, ".interp");
	  BFD_ASSERT(s != NULL);
	  s->size = sizeof(ELF_DYNAMIC_INTERPRETER);
	  s->contents = (unsigned char *)ELF_DYNAMIC_INTERPRETER;
	}
    }

  if (htab->nr_got_holes > 0)
    {
      /* Allocate holes for the pigeonhole sort algorithm */
      pr_debug("Highest GOT refcount: %d\n", htab->nr_got_holes);

      /* Limit the memory usage by clipping the number of pigeonholes
       * at a predefined maximum. All entries with a higher refcount
       * will end up in the last pigeonhole.  */
    if (htab->nr_got_holes >= MAX_NR_GOT_HOLES)
    {
        htab->nr_got_holes = MAX_NR_GOT_HOLES - 1;

        pr_debug("Limiting maximum number of GOT pigeonholes to %u\n",
                    htab->nr_got_holes);
    }
      htab->got_hole = bfd_zalloc(output_bfd,
				  sizeof(struct got_entry *)
				  * (htab->nr_got_holes + 1));
      if (!htab->got_hole)
	return FALSE;

      /* Set up .got offsets for local syms.  */
      for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link_next)
	{
	  struct got_entry **local_got;
	  struct got_entry **end_local_got;
	  Elf_Internal_Shdr *symtab_hdr;
	  bfd_size_type locsymcount;

	  pr_debug("  (4a) processing file %s...\n", ibfd->filename);

	  BFD_ASSERT(bfd_get_flavour(ibfd) == bfd_target_elf_flavour);

	  local_got = elf_local_got_ents(ibfd);
	  if (!local_got)
	    continue;

	  symtab_hdr = &elf_tdata(ibfd)->symtab_hdr;
	  locsymcount = symtab_hdr->sh_info;
	  end_local_got = local_got + locsymcount;

	  for (; local_got < end_local_got; ++local_got)
	    insert_got_entry(htab, *local_got);
	}
    }

  /* Allocate global sym .got entries and space for global sym
     dynamic relocs */
  elf_link_hash_traverse(&htab->root, allocate_dynrelocs, info);

  /* Now that we have sorted the GOT entries, we are ready to
     assign offsets and determine the initial size of the GOT. */
  if (htab->sgot)
    assign_got_offsets(htab);

  /* Allocate space for local sym dynamic relocs */
  BFD_ASSERT(htab->local_dynamic_relocs == 0 || info->shared);
  if (htab->local_dynamic_relocs)
    htab->srelgot->size += (htab->local_dynamic_relocs
			    * sizeof(Elf32_External_Rela));

  /* We now have determined the sizes of the various dynamic
     sections. Allocate memory for them. */
  relocs = FALSE;
  for (s = dynobj->sections; s; s = s->next)
    {
      if ((s->flags & SEC_LINKER_CREATED) == 0)
	continue;

      if (s == htab->sgot
	  || s == htab->sstub)
	{
	  /* Strip this section if we don't need it */
	}
      else if (strncmp (bfd_get_section_name(dynobj, s), ".rela", 5) == 0)
	{
	  if (s->size != 0)
	    relocs = TRUE;

	  s->reloc_count = 0;
	}
      else
	{
	  /* It's not one of our sections */
	  continue;
	}

      if (s->size == 0)
	{
	  /* Strip unneeded sections */
	  pr_debug("Stripping section %s from output...\n", s->name);
	  /* deleted function in 2.17
      _bfd_strip_section_from_output(info, s);
      */
	  continue;
	}

      s->contents = bfd_zalloc(dynobj, s->size);
      if (s->contents == NULL)
	return FALSE;
    }

  if (htab->root.dynamic_sections_created)
    {
      /* Add some entries to the .dynamic section.  We fill in the
	 values later, in sh_elf_finish_dynamic_sections, but we
	 must add the entries now so that we get the correct size for
	 the .dynamic section.  The DT_DEBUG entry is filled in by the
	 dynamic linker and used by the debugger.  */
#define add_dynamic_entry(TAG, VAL) _bfd_elf_add_dynamic_entry(info, TAG, VAL)

      if (!add_dynamic_entry(DT_PLTGOT, 0))
	return FALSE;
      if (!add_dynamic_entry(DT_AVR32_GOTSZ, 0))
	return FALSE;

      if (info->executable)
	{
	  if (!add_dynamic_entry(DT_DEBUG, 0))
	    return FALSE;
	}
      if (relocs)
	{
	  if (!add_dynamic_entry(DT_RELA, 0)
	      || !add_dynamic_entry(DT_RELASZ, 0)
	      || !add_dynamic_entry(DT_RELAENT,
				    sizeof(Elf32_External_Rela)))
	    return FALSE;
	}
    }
#undef add_dynamic_entry

  return TRUE;
}


/* Access to internal relocations, section contents and symbols.
   (stolen from the xtensa port)  */

static Elf_Internal_Rela *
retrieve_internal_relocs (bfd *abfd, asection *sec, bfd_boolean keep_memory);
static void
pin_internal_relocs (asection *sec, Elf_Internal_Rela *internal_relocs);
static void
release_internal_relocs (asection *sec, Elf_Internal_Rela *internal_relocs);
static bfd_byte *
retrieve_contents (bfd *abfd, asection *sec, bfd_boolean keep_memory);
/*
static void
pin_contents (asection *sec, bfd_byte *contents);
*/
static void
release_contents (asection *sec, bfd_byte *contents);
static Elf_Internal_Sym *
retrieve_local_syms (bfd *input_bfd, bfd_boolean keep_memory);
/*
static void
pin_local_syms (bfd *input_bfd, Elf_Internal_Sym *isymbuf);
*/
static void
release_local_syms (bfd *input_bfd, Elf_Internal_Sym *isymbuf);

/* During relaxation, we need to modify relocations, section contents,
   and symbol definitions, and we need to keep the original values from
   being reloaded from the input files, i.e., we need to "pin" the
   modified values in memory.  We also want to continue to observe the
   setting of the "keep-memory" flag.  The following functions wrap the
   standard BFD functions to take care of this for us.  */

static Elf_Internal_Rela *
retrieve_internal_relocs (bfd *abfd, asection *sec, bfd_boolean keep_memory)
{
  /* _bfd_elf_link_read_relocs knows about caching, so no need for us
     to be clever here.  */
  return _bfd_elf_link_read_relocs(abfd, sec, NULL, NULL, keep_memory);
}

static void
pin_internal_relocs (asection *sec, Elf_Internal_Rela *internal_relocs)
{
  elf_section_data (sec)->relocs = internal_relocs;
}

static void
release_internal_relocs (asection *sec, Elf_Internal_Rela *internal_relocs)
{
  if (internal_relocs
      && elf_section_data (sec)->relocs != internal_relocs)
    free (internal_relocs);
}

static bfd_byte *
retrieve_contents (bfd *abfd, asection *sec, bfd_boolean keep_memory)
{
  bfd_byte *contents;
  bfd_size_type sec_size;

  sec_size = bfd_get_section_limit (abfd, sec);
  contents = elf_section_data (sec)->this_hdr.contents;

  if (contents == NULL && sec_size != 0)
    {
      if (!bfd_malloc_and_get_section (abfd, sec, &contents))
	{
	  if (contents)
	    free (contents);
	  return NULL;
	}
      if (keep_memory)
	elf_section_data (sec)->this_hdr.contents = contents;
    }
  return contents;
}

/*
static void
pin_contents (asection *sec, bfd_byte *contents)
{
  elf_section_data (sec)->this_hdr.contents = contents;
}
*/
static void
release_contents (asection *sec, bfd_byte *contents)
{
  if (contents && elf_section_data (sec)->this_hdr.contents != contents)
    free (contents);
}

static Elf_Internal_Sym *
retrieve_local_syms (bfd *input_bfd, bfd_boolean keep_memory)
{
  Elf_Internal_Shdr *symtab_hdr;
  Elf_Internal_Sym *isymbuf;
  size_t locsymcount;

  symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
  locsymcount = symtab_hdr->sh_info;

  isymbuf = (Elf_Internal_Sym *) symtab_hdr->contents;
  if (isymbuf == NULL && locsymcount != 0)
    {
      isymbuf = bfd_elf_get_elf_syms (input_bfd, symtab_hdr, locsymcount, 0,
				      NULL, NULL, NULL);
      if (isymbuf && keep_memory)
	symtab_hdr->contents = (unsigned char *) isymbuf;
    }

  return isymbuf;
}

/*
static void
pin_local_syms (bfd *input_bfd, Elf_Internal_Sym *isymbuf)
{
  elf_tdata (input_bfd)->symtab_hdr.contents = (unsigned char *)isymbuf;
}

*/
static void
release_local_syms (bfd *input_bfd, Elf_Internal_Sym *isymbuf)
{
  if (isymbuf && (elf_tdata (input_bfd)->symtab_hdr.contents
		  != (unsigned char *)isymbuf))
    free (isymbuf);
}

/* Data structures used during relaxation. */

enum relax_state_id {
  RS_ERROR = -1,
  RS_NONE = 0,
  RS_ALIGN,
  RS_CPENT,
  RS_PIC_CALL,
  RS_PIC_MCALL,
  RS_PIC_RCALL2,
  RS_PIC_RCALL1,
  RS_PIC_LDA,
  RS_PIC_LDW4,
  RS_PIC_LDW3,
  RS_PIC_SUB5,
  RS_NOPIC_MCALL,
  RS_NOPIC_RCALL2,
  RS_NOPIC_RCALL1,
  RS_NOPIC_LDW4,
  RS_NOPIC_LDDPC,
  RS_NOPIC_SUB5,
  RS_NOPIC_MOV2,
  RS_NOPIC_MOV1,
  RS_RCALL2,
  RS_RCALL1,
  RS_BRC2,
  RS_BRC1,
  RS_BRAL,
  RS_RJMP,
  RS_MAX,
};

enum reference_type {
  REF_ABSOLUTE,
  REF_PCREL,
  REF_CPOOL,
  REF_GOT,
};

struct relax_state
{
  const char *name;
  enum relax_state_id id;
  enum relax_state_id direct;
  enum relax_state_id next;
  enum relax_state_id prev;

  enum reference_type reftype;

  unsigned int r_type;

  bfd_vma opcode;
  bfd_vma opcode_mask;

  bfd_signed_vma range_min;
  bfd_signed_vma range_max;

  bfd_size_type size;
};

/*
 * This is for relocs that
 *   a) has an addend or is of type R_AVR32_DIFF32, and
 *   b) references a different section than it's in, and
 *   c) references a section that is relaxable
 *
 * as well as relocs that references the constant pool, in which case
 * the add_frag member points to the frag containing the constant pool
 * entry.
 *
 * Such relocs must be fixed up whenever we delete any code. Sections
 * that don't have any relocs with all of the above properties don't
 * have any additional reloc data, but sections that do will have
 * additional data for all its relocs.
 */
struct avr32_reloc_data
{
  struct fragment *add_frag;
  struct fragment *sub_frag;
};

/*
 * A 'fragment' is a relaxable entity, that is, code may be added or
 * deleted at the end of a fragment. When this happens, all subsequent
 * fragments in the list will have their offsets updated.
 */
struct fragment
{
  enum relax_state_id state;
  enum relax_state_id initial_state;

  Elf_Internal_Rela *rela;
  bfd_size_type size;
  bfd_vma offset;
  int size_adjust;
  int offset_adjust;
  bfd_boolean has_grown;

  /* Only used by constant pool entries.  When this drops to zero, the
     frag is discarded (i.e. size_adjust is set to -4.)  */
  int refcount;
};

struct avr32_relax_data
{
  unsigned int frag_count;
  struct fragment *frag;
  struct avr32_reloc_data *reloc_data;

  /* TRUE if this section has one or more relaxable relocations */
  bfd_boolean is_relaxable;
  unsigned int iteration;
};

struct avr32_section_data
{
  struct bfd_elf_section_data elf;
  struct avr32_relax_data relax_data;
};

/* Relax state definitions */

#define PIC_MOV2_OPCODE		0xe0600000
#define PIC_MOV2_MASK		0xe1e00000
#define PIC_MOV2_RANGE_MIN	(-1048576 * 4)
#define PIC_MOV2_RANGE_MAX	(1048575 * 4)
#define PIC_MCALL_OPCODE	0xf0160000
#define PIC_MCALL_MASK		0xffff0000
#define PIC_MCALL_RANGE_MIN	(-131072)
#define PIC_MCALL_RANGE_MAX	(131068)
#define RCALL2_OPCODE		0xe0a00000
#define RCALL2_MASK		0xe1ef0000
#define RCALL2_RANGE_MIN	(-2097152)
#define RCALL2_RANGE_MAX	(2097150)
#define RCALL1_OPCODE		0xc00c0000
#define RCALL1_MASK		0xf00c0000
#define RCALL1_RANGE_MIN	(-1024)
#define RCALL1_RANGE_MAX	(1022)
#define PIC_LDW4_OPCODE		0xecf00000
#define PIC_LDW4_MASK		0xfff00000
#define PIC_LDW4_RANGE_MIN	(-32768)
#define PIC_LDW4_RANGE_MAX	(32767)
#define PIC_LDW3_OPCODE		0x6c000000
#define PIC_LDW3_MASK		0xfe000000
#define PIC_LDW3_RANGE_MIN	(0)
#define PIC_LDW3_RANGE_MAX	(124)
#define SUB5_PC_OPCODE		0xfec00000
#define SUB5_PC_MASK		0xfff00000
#define SUB5_PC_RANGE_MIN	(-32768)
#define SUB5_PC_RANGE_MAX	(32767)
#define NOPIC_MCALL_OPCODE	0xf01f0000
#define NOPIC_MCALL_MASK	0xffff0000
#define NOPIC_MCALL_RANGE_MIN	PIC_MCALL_RANGE_MIN
#define NOPIC_MCALL_RANGE_MAX	PIC_MCALL_RANGE_MAX
#define NOPIC_LDW4_OPCODE	0xfef00000
#define NOPIC_LDW4_MASK		0xfff00000
#define NOPIC_LDW4_RANGE_MIN	PIC_LDW4_RANGE_MIN
#define NOPIC_LDW4_RANGE_MAX	PIC_LDW4_RANGE_MAX
#define LDDPC_OPCODE		0x48000000
#define LDDPC_MASK		0xf8000000
#define LDDPC_RANGE_MIN		0
#define LDDPC_RANGE_MAX		508

#define NOPIC_MOV2_OPCODE  0xe0600000
#define NOPIC_MOV2_MASK        0xe1e00000
#define NOPIC_MOV2_RANGE_MIN   (-1048576)
#define NOPIC_MOV2_RANGE_MAX   (1048575)
#define NOPIC_MOV1_OPCODE  0x30000000
#define NOPIC_MOV1_MASK        0xf0000000
#define NOPIC_MOV1_RANGE_MIN   (-128)
#define NOPIC_MOV1_RANGE_MAX   (127)

/* Only brc2 variants with cond[3] == 0 is considered, since the
   others are not relaxable.  bral is a special case and is handled
   separately.  */
#define BRC2_OPCODE		0xe0800000
#define BRC2_MASK		0xe1e80000
#define BRC2_RANGE_MIN		(-2097152)
#define BRC2_RANGE_MAX		(2097150)
#define BRC1_OPCODE		0xc0000000
#define BRC1_MASK		0xf0080000
#define BRC1_RANGE_MIN		(-256)
#define BRC1_RANGE_MAX		(254)
#define BRAL_OPCODE		0xe08f0000
#define BRAL_MASK		0xe1ef0000
#define BRAL_RANGE_MIN		BRC2_RANGE_MIN
#define BRAL_RANGE_MAX		BRC2_RANGE_MAX
#define RJMP_OPCODE		0xc0080000
#define RJMP_MASK		0xf00c0000
#define RJMP_RANGE_MIN		(-1024)
#define RJMP_RANGE_MAX		(1022)

/* Define a relax state using the GOT  */
#define RG(id, dir, next, prev, r_type, opc, size)			\
  { "RS_"#id, RS_##id, RS_##dir, RS_##next, RS_##prev, REF_GOT,		\
      R_AVR32_##r_type,	opc##_OPCODE, opc##_MASK,			\
      opc##_RANGE_MIN, opc##_RANGE_MAX, size }
/* Define a relax state using the Constant Pool  */
#define RC(id, dir, next, prev, r_type, opc, size)			\
  { "RS_"#id, RS_##id, RS_##dir, RS_##next, RS_##prev, REF_CPOOL,	\
      R_AVR32_##r_type,	opc##_OPCODE, opc##_MASK,			\
      opc##_RANGE_MIN, opc##_RANGE_MAX, size }

/* Define a relax state using pc-relative direct reference  */
#define RP(id, dir, next, prev, r_type, opc, size)			\
  { "RS_"#id, RS_##id, RS_##dir, RS_##next, RS_##prev, REF_PCREL,	\
      R_AVR32_##r_type,	opc##_OPCODE, opc##_MASK,			\
      opc##_RANGE_MIN, opc##_RANGE_MAX, size }

/* Define a relax state using non-pc-relative direct reference */
#define RD(id, dir, next, prev, r_type, opc, size)         \
  { "RS_"#id, RS_##id, RS_##dir, RS_##next, RS_##prev, REF_ABSOLUTE,   \
      R_AVR32_##r_type,    opc##_OPCODE, opc##_MASK,           \
      opc##_RANGE_MIN, opc##_RANGE_MAX, size }

/* Define a relax state that will be handled specially  */
#define RS(id, r_type, size)						\
  { "RS_"#id, RS_##id, RS_NONE, RS_NONE, RS_NONE, REF_ABSOLUTE,		\
      R_AVR32_##r_type, 0, 0, 0, 0, size }

const struct relax_state relax_state[RS_MAX] = {
  RS(NONE, NONE, 0),
  RS(ALIGN, ALIGN, 0),
  RS(CPENT, 32_CPENT, 4),

  RG(PIC_CALL, PIC_RCALL1, PIC_MCALL, NONE, GOTCALL, PIC_MOV2, 10),
  RG(PIC_MCALL, PIC_RCALL1, NONE, PIC_CALL, GOT18SW, PIC_MCALL, 4),
  RP(PIC_RCALL2, NONE, PIC_RCALL1, PIC_MCALL, 22H_PCREL, RCALL2, 4),
  RP(PIC_RCALL1, NONE, NONE, PIC_RCALL2, 11H_PCREL, RCALL1, 2),

  RG(PIC_LDA, PIC_SUB5, PIC_LDW4, NONE, LDA_GOT, PIC_MOV2, 8),
  RG(PIC_LDW4, PIC_SUB5, PIC_LDW3, PIC_LDA, GOT16S, PIC_LDW4, 4),
  RG(PIC_LDW3, PIC_SUB5, NONE, PIC_LDW4, GOT7UW, PIC_LDW3, 2),
  RP(PIC_SUB5, NONE, NONE, PIC_LDW3, 16N_PCREL, SUB5_PC, 4),

  RC(NOPIC_MCALL, NOPIC_RCALL1, NONE, NONE, CPCALL, NOPIC_MCALL, 4),
  RP(NOPIC_RCALL2, NONE, NOPIC_RCALL1, NOPIC_MCALL, 22H_PCREL, RCALL2, 4),
  RP(NOPIC_RCALL1, NONE, NONE, NOPIC_RCALL2, 11H_PCREL, RCALL1, 2),

  RC(NOPIC_LDW4, NOPIC_MOV1, NOPIC_LDDPC, NONE, 16_CP, NOPIC_LDW4, 4),
  RC(NOPIC_LDDPC, NOPIC_MOV1, NONE, NOPIC_LDW4, 9W_CP, LDDPC, 2),
  RP(NOPIC_SUB5, NOPIC_MOV1, NONE, NOPIC_LDDPC, 16N_PCREL, SUB5_PC, 4),
  RD(NOPIC_MOV2, NONE, NOPIC_MOV1, NOPIC_SUB5, 21S, NOPIC_MOV2, 4),
  RD(NOPIC_MOV1, NONE, NONE, NOPIC_MOV2, 8S, NOPIC_MOV1, 2),

  RP(RCALL2, NONE, RCALL1, NONE, 22H_PCREL, RCALL2, 4),
  RP(RCALL1, NONE, NONE, RCALL2, 11H_PCREL, RCALL1, 2),
  RP(BRC2, NONE, BRC1, NONE, 22H_PCREL, BRC2, 4),
  RP(BRC1, NONE, NONE, BRC2, 9H_PCREL, BRC1, 2),
  RP(BRAL, NONE, RJMP, NONE, 22H_PCREL, BRAL, 4),
  RP(RJMP, NONE, NONE, BRAL, 11H_PCREL, RJMP, 2),
};

static bfd_boolean
avr32_elf_new_section_hook(bfd *abfd, asection *sec)
{
  struct avr32_section_data *sdata;

  sdata = bfd_zalloc(abfd, sizeof(struct avr32_section_data));
  if (!sdata)
    return FALSE;

  sec->used_by_bfd = sdata;
  return _bfd_elf_new_section_hook(abfd, sec);
}

static struct avr32_relax_data *
avr32_relax_data(asection *sec)
{
  struct avr32_section_data *sdata;

  BFD_ASSERT(sec->used_by_bfd);

  sdata = (struct avr32_section_data *)elf_section_data(sec);
  return &sdata->relax_data;
}

/* Link-time relaxation */

static bfd_boolean
avr32_elf_relax_section(bfd *abfd, asection *sec,
			struct bfd_link_info *info, bfd_boolean *again);

enum relax_pass_id {
  RELAX_PASS_SIZE_FRAGS,
  RELAX_PASS_MOVE_DATA,
};

/* Stolen from the xtensa port */
static int
internal_reloc_compare (const void *ap, const void *bp)
{
  const Elf_Internal_Rela *a = (const Elf_Internal_Rela *) ap;
  const Elf_Internal_Rela *b = (const Elf_Internal_Rela *) bp;

  if (a->r_offset != b->r_offset)
    return (a->r_offset - b->r_offset);

  /* We don't need to sort on these criteria for correctness,
     but enforcing a more strict ordering prevents unstable qsort
     from behaving differently with different implementations.
     Without the code below we get correct but different results
     on Solaris 2.7 and 2.8.  We would like to always produce the
     same results no matter the host.  */

  if (a->r_info != b->r_info)
    return (a->r_info - b->r_info);

  return (a->r_addend - b->r_addend);
}

static enum relax_state_id
get_pcrel22_relax_state(bfd *abfd, asection *sec, struct bfd_link_info *info,
			const Elf_Internal_Rela *rela)
{
  bfd_byte *contents;
  bfd_vma insn;
  enum relax_state_id rs = RS_NONE;

  contents = retrieve_contents(abfd, sec, info->keep_memory);
  if (!contents)
    return RS_ERROR;

  insn = bfd_get_32(abfd, contents + rela->r_offset);
  if ((insn & RCALL2_MASK) == RCALL2_OPCODE)
    rs = RS_RCALL2;
  else if ((insn & BRAL_MASK) == BRAL_OPCODE)
    /* Optimizing bral -> rjmp gets us into all kinds of
       trouble with jump tables. Better not do it.  */
    rs = RS_NONE;
  else if ((insn & BRC2_MASK) == BRC2_OPCODE)
    rs = RS_BRC2;

  release_contents(sec, contents);

  return rs;
}

static enum relax_state_id
get_initial_relax_state(bfd *abfd, asection *sec, struct bfd_link_info *info,
			const Elf_Internal_Rela *rela)
{
  switch (ELF_R_TYPE(rela->r_info))
    {
    case R_AVR32_GOTCALL:
      return RS_PIC_CALL;
    case R_AVR32_GOT18SW:
      return RS_PIC_MCALL;
    case R_AVR32_LDA_GOT:
      return RS_PIC_LDA;
    case R_AVR32_GOT16S:
      return RS_PIC_LDW4;
    case R_AVR32_CPCALL:
      return RS_NOPIC_MCALL;
    case R_AVR32_16_CP:
      return RS_NOPIC_LDW4;
    case R_AVR32_9W_CP:
      return RS_NOPIC_LDDPC;
    case R_AVR32_ALIGN:
      return RS_ALIGN;
    case R_AVR32_32_CPENT:
      return RS_CPENT;
    case R_AVR32_22H_PCREL:
      return get_pcrel22_relax_state(abfd, sec, info, rela);
    case R_AVR32_9H_PCREL:
      return RS_BRC1;
    default:
      return RS_NONE;
    }
}

static bfd_boolean
reloc_is_cpool_ref(const Elf_Internal_Rela *rela)
{
  switch (ELF_R_TYPE(rela->r_info))
    {
    case R_AVR32_CPCALL:
    case R_AVR32_16_CP:
    case R_AVR32_9W_CP:
      return TRUE;
    default:
      return FALSE;
    }
}

static struct fragment *
new_frag(bfd *abfd ATTRIBUTE_UNUSED, asection *sec,
	 struct avr32_relax_data *rd, enum relax_state_id state,
	 Elf_Internal_Rela *rela)
{
  struct fragment *frag;
  bfd_size_type r_size;
  bfd_vma r_offset;
  unsigned int i = rd->frag_count;

  BFD_ASSERT(state >= RS_NONE && state < RS_MAX);

  rd->frag_count++;
  frag = bfd_realloc(rd->frag, sizeof(struct fragment) * rd->frag_count);
  if (!frag)
    return NULL;
  rd->frag = frag;

  frag += i;
  memset(frag, 0, sizeof(struct fragment));

  if (state == RS_ALIGN)
    r_size = (((rela->r_offset + (1 << rela->r_addend) - 1)
	       & ~((1 << rela->r_addend) - 1)) - rela->r_offset);
  else
    r_size = relax_state[state].size;

  if (rela)
    r_offset = rela->r_offset;
  else
    r_offset = sec->size;

  if (i == 0)
    {
      frag->offset = 0;
      frag->size = r_offset + r_size;
    }
  else
    {
      frag->offset = rd->frag[i - 1].offset + rd->frag[i - 1].size;
      frag->size = r_offset + r_size - frag->offset;
    }

  if (state != RS_CPENT)
    /* Make sure we don't discard this frag */
    frag->refcount = 1;

  frag->initial_state = frag->state = state;
  frag->rela = rela;

  return frag;
}

static struct fragment *
find_frag(asection *sec, bfd_vma offset)
{
  struct fragment *first, *last;
  struct avr32_relax_data *rd = avr32_relax_data(sec);

  if (rd->frag_count == 0)
    return NULL;

  first = &rd->frag[0];
  last = &rd->frag[rd->frag_count - 1];

  /* This may be a reloc referencing the end of a section.  The last
     frag will never have a reloc associated with it, so its size will
     never change, thus the offset adjustment of the last frag will
     always be the same as the offset adjustment of the end of the
     section.  */
  if (offset == sec->size)
    {
      BFD_ASSERT(last->offset + last->size == sec->size);
      BFD_ASSERT(!last->rela);
      return last;
    }

  while (first <= last)
    {
      struct fragment *mid;

      mid = (last - first) / 2 + first;
      if ((mid->offset + mid->size) <= offset)
	first = mid + 1;
      else if (mid->offset > offset)
	last = mid - 1;
      else
	return mid;
    }

  return NULL;
}

/* Look through all relocs in a section and determine if any relocs
   may be affected by relaxation in other sections.  If so, allocate
   an array of additional relocation data which links the affected
   relocations to the frag(s) where the relaxation may occur.

   This function also links cpool references to cpool entries and
   increments the refcount of the latter when this happens.  */

static bfd_boolean
allocate_reloc_data(bfd *abfd, asection *sec, Elf_Internal_Rela *relocs,
		    struct bfd_link_info *info)
{
  Elf_Internal_Shdr *symtab_hdr;
  Elf_Internal_Sym *isymbuf = NULL;
  struct avr32_relax_data *rd;
  unsigned int i;
  bfd_boolean ret = FALSE;

  symtab_hdr = &elf_tdata(abfd)->symtab_hdr;
  rd = avr32_relax_data(sec);

  RDBG("%s<%s>: allocate_reloc_data\n", abfd->filename, sec->name);

  for (i = 0; i < sec->reloc_count; i++)
    {
      Elf_Internal_Rela *rel = &relocs[i];
      asection *sym_sec;
      unsigned long r_symndx;
      bfd_vma sym_value;

      if (!rel->r_addend && ELF_R_TYPE(rel->r_info) != R_AVR32_DIFF32
	  && !reloc_is_cpool_ref(rel))
	continue;

      r_symndx = ELF_R_SYM(rel->r_info);

      if (r_symndx < symtab_hdr->sh_info)
	{
	  Elf_Internal_Sym *isym;

	  if (!isymbuf)
	    isymbuf = retrieve_local_syms(abfd, info->keep_memory);
	  if (!isymbuf)
	    return FALSE;

	  isym = &isymbuf[r_symndx];
	  sym_sec = bfd_section_from_elf_index(abfd, isym->st_shndx);
	  sym_value = isym->st_value;
	}
      else
	{
	  struct elf_link_hash_entry *h;

	  h = elf_sym_hashes(abfd)[r_symndx - symtab_hdr->sh_info];

	  while (h->root.type == bfd_link_hash_indirect
		 || h->root.type == bfd_link_hash_warning)
	    h = (struct elf_link_hash_entry *)h->root.u.i.link;

	  if (h->root.type != bfd_link_hash_defined
	      && h->root.type != bfd_link_hash_defweak)
	    continue;

	  sym_sec = h->root.u.def.section;
	  sym_value = h->root.u.def.value;
	}

      if (sym_sec && avr32_relax_data(sym_sec)->is_relaxable)
	{
	  bfd_size_type size;
	  struct fragment *frag;

	  if (!rd->reloc_data)
	    {
	      size = sizeof(struct avr32_reloc_data) * sec->reloc_count;
	      rd->reloc_data = bfd_zalloc(abfd, size);
	      if (!rd->reloc_data)
		goto out;
	    }

	  RDBG("[%3d] 0x%04lx: target: 0x%lx + 0x%lx",
	       i, rel->r_offset, sym_value, rel->r_addend);

	  frag = find_frag(sym_sec, sym_value + rel->r_addend);
	  BFD_ASSERT(frag);
	  rd->reloc_data[i].add_frag = frag;

	  RDBG(" -> %s<%s>:%04lx\n", sym_sec->owner->filename, sym_sec->name,
	       frag->rela ? frag->rela->r_offset : sym_sec->size);

	  if (reloc_is_cpool_ref(rel))
	    {
	      BFD_ASSERT(ELF_R_TYPE(frag->rela->r_info) == R_AVR32_32_CPENT);
	      frag->refcount++;
	    }

	  if (ELF_R_TYPE(rel->r_info) == R_AVR32_DIFF32)
	    {
	      bfd_byte *contents;
	      bfd_signed_vma diff;

	      contents = retrieve_contents(abfd, sec, info->keep_memory);
	      if (!contents)
		goto out;

	      diff = bfd_get_signed_32(abfd, contents + rel->r_offset);
	      frag = find_frag(sym_sec, sym_value + rel->r_addend + diff);
	      BFD_ASSERT(frag);
	      rd->reloc_data[i].sub_frag = frag;

	      release_contents(sec, contents);
	    }
	}
    }

  ret = TRUE;

 out:
  release_local_syms(abfd, isymbuf);
  return ret;
}

static bfd_boolean
global_sym_set_frag(struct elf_avr32_link_hash_entry *havr,
		    struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  struct fragment *frag;
  asection *sec;

  if (havr->root.root.type != bfd_link_hash_defined
      && havr->root.root.type != bfd_link_hash_defweak)
    return TRUE;

  sec = havr->root.root.u.def.section;
  if (bfd_is_const_section(sec)
      || !avr32_relax_data(sec)->is_relaxable)
    return TRUE;

  frag = find_frag(sec, havr->root.root.u.def.value);
  if (!frag)
    {
      unsigned int i;
      struct avr32_relax_data *rd = avr32_relax_data(sec);

      RDBG("In %s: No frag for %s <%s+%lu> (limit %lu)\n",
	   sec->owner->filename, havr->root.root.root.string,
	   sec->name, havr->root.root.u.def.value, sec->size);
      for (i = 0; i < rd->frag_count; i++)
	RDBG("    %8lu - %8lu\n", rd->frag[i].offset,
	     rd->frag[i].offset + rd->frag[i].size);
    }
  BFD_ASSERT(frag);

  havr->sym_frag = frag;
  return TRUE;
}

static bfd_boolean
analyze_relocations(struct bfd_link_info *info)
{
  bfd *abfd;
  asection *sec;

  /* Divide all relaxable sections into fragments */
  for (abfd = info->input_bfds; abfd; abfd = abfd->link_next)
    {
      if (!(elf_elfheader(abfd)->e_flags & EF_AVR32_LINKRELAX))
	{
	  if (!(*info->callbacks->warning)
	      (info, _("input is not relaxable"), NULL, abfd, NULL, 0))
	    return FALSE;
	  continue;
	}

      for (sec = abfd->sections; sec; sec = sec->next)
	{
	  struct avr32_relax_data *rd;
	  struct fragment *frag;
	  Elf_Internal_Rela *relocs;
	  unsigned int i;
	  bfd_boolean ret = TRUE;

	  if (!(sec->flags & SEC_RELOC) || sec->reloc_count == 0)
	    continue;

	  rd = avr32_relax_data(sec);

	  relocs = retrieve_internal_relocs(abfd, sec, info->keep_memory);
	  if (!relocs)
	    return FALSE;

	  qsort(relocs, sec->reloc_count, sizeof(Elf_Internal_Rela),
		internal_reloc_compare);

	  for (i = 0; i < sec->reloc_count; i++)
	    {
	      enum relax_state_id state;

	      ret = FALSE;
	      state = get_initial_relax_state(abfd, sec, info, &relocs[i]);
	      if (state == RS_ERROR)
		break;

	      if (state)
		{
		  frag = new_frag(abfd, sec, rd, state, &relocs[i]);
		  if (!frag)
		    break;

		  pin_internal_relocs(sec, relocs);
		  rd->is_relaxable = TRUE;
		}

	      ret = TRUE;
	    }

	  release_internal_relocs(sec, relocs);
	  if (!ret)
	    return ret;

	  if (rd->is_relaxable)
	    {
	      frag = new_frag(abfd, sec, rd, RS_NONE, NULL);
	      if (!frag)
		return FALSE;
	    }
	}
    }

  /* Link each global symbol to the fragment where it's defined.  */
  elf_link_hash_traverse(elf_hash_table(info), global_sym_set_frag, info);

  /* Do the same for local symbols. */
  for (abfd = info->input_bfds; abfd; abfd = abfd->link_next)
    {
      Elf_Internal_Sym *isymbuf, *isym;
      struct fragment **local_sym_frag;
      unsigned int i, sym_count;

      sym_count = elf_tdata(abfd)->symtab_hdr.sh_info;
      if (sym_count == 0)
	continue;

      local_sym_frag = bfd_zalloc(abfd, sym_count * sizeof(struct fragment *));
      if (!local_sym_frag)
	return FALSE;
      elf_tdata(abfd)->local_sym_frag = local_sym_frag;

      isymbuf = retrieve_local_syms(abfd, info->keep_memory);
      if (!isymbuf)
	return FALSE;

      for (i = 0; i < sym_count; i++)
	{
	  struct avr32_relax_data *rd;
	  struct fragment *frag;
	  asection *asec;

	  isym = &isymbuf[i];

	  asec = bfd_section_from_elf_index(abfd, isym->st_shndx);
	  if (!asec)
	    continue;

	  rd = avr32_relax_data(asec);
	  if (!rd->is_relaxable)
	    continue;

	  frag = find_frag(asec, isym->st_value);
	  BFD_ASSERT(frag);

	  local_sym_frag[i] = frag;
	}

      release_local_syms(abfd, isymbuf);
    }

  /* And again for relocs with addends and constant pool references */
  for (abfd = info->input_bfds; abfd; abfd = abfd->link_next)
    for (sec = abfd->sections; sec; sec = sec->next)
      {
	Elf_Internal_Rela *relocs;
	bfd_boolean ret;

	if (!(sec->flags & SEC_RELOC) || sec->reloc_count == 0)
	  continue;

	relocs = retrieve_internal_relocs(abfd, sec, info->keep_memory);
	if (!relocs)
	  return FALSE;

	ret = allocate_reloc_data(abfd, sec, relocs, info);

	release_internal_relocs(sec, relocs);
	if (ret == FALSE)
	  return ret;
      }

  return TRUE;
}

static bfd_boolean
rs_is_good_enough(const struct relax_state *rs, struct fragment *frag,
		  bfd_vma symval, bfd_vma addr, struct got_entry *got,
		  struct avr32_reloc_data *ind_data,
		  bfd_signed_vma offset_adjust)
{
  bfd_signed_vma target = 0;

  switch (rs->reftype)
    {
    case REF_ABSOLUTE:
      target = symval;
      break;
    case REF_PCREL:
      target = symval - addr;
      break;
    case REF_CPOOL:
      /* cpool frags are always in the same section and always after
	 all frags referring to it.  So it's always correct to add in
	 offset_adjust here.  */
      target = (ind_data->add_frag->offset + ind_data->add_frag->offset_adjust
		+ offset_adjust - frag->offset - frag->offset_adjust);
      break;
    case REF_GOT:
      target = got->offset;
      break;
    default:
      abort();
    }

  if (target >= rs->range_min && target <= rs->range_max)
    return TRUE;
  else
    return FALSE;
}

static bfd_boolean
avr32_size_frags(bfd *abfd, asection *sec, struct bfd_link_info *info)
{
  struct elf_avr32_link_hash_table *htab;
  struct avr32_relax_data *rd;
  Elf_Internal_Shdr *symtab_hdr;
  Elf_Internal_Rela *relocs = NULL;
  Elf_Internal_Sym *isymbuf = NULL;
  struct got_entry **local_got_ents;
  struct fragment **local_sym_frag;
  bfd_boolean ret = FALSE;
  bfd_signed_vma delta = 0;
  unsigned int i;

  htab = avr32_elf_hash_table(info);
  rd = avr32_relax_data(sec);

  if (sec == htab->sgot)
    {
      RDBG("Relaxing GOT section (vma: 0x%lx)\n",
	   sec->output_section->vma + sec->output_offset);
      if (assign_got_offsets(htab))
	htab->repeat_pass = TRUE;
      return TRUE;
    }

  if (!rd->is_relaxable)
    return TRUE;

  if (!sec->rawsize)
    sec->rawsize = sec->size;

  symtab_hdr = &elf_tdata(abfd)->symtab_hdr;
  relocs = retrieve_internal_relocs(abfd, sec, info->keep_memory);
  if (!relocs)
    goto out;

  isymbuf = retrieve_local_syms(abfd, info->keep_memory);
  if (!isymbuf)
    goto out;

  local_got_ents = elf_local_got_ents(abfd);
  local_sym_frag = elf_tdata(abfd)->local_sym_frag;

  RDBG("size_frags: %s<%s>\n  vma: 0x%08lx, size: 0x%08lx\n",
       abfd->filename, sec->name,
       sec->output_section->vma + sec->output_offset, sec->size);

  for (i = 0; i < rd->frag_count; i++)
    {
      struct fragment *frag = &rd->frag[i];
      struct avr32_reloc_data *r_data = NULL, *ind_data = NULL;
      const struct relax_state *state, *next_state;
      struct fragment *target_frag = NULL;
      asection *sym_sec = NULL;
      Elf_Internal_Rela *rela;
      struct got_entry *got;
      bfd_vma symval, r_offset, addend, addr;
      bfd_signed_vma size_adjust = 0, distance;
      unsigned long r_symndx;
      bfd_boolean defined = TRUE, dynamic = FALSE;
      unsigned char sym_type;

      frag->offset_adjust += delta;
      state = next_state = &relax_state[frag->state];
      rela = frag->rela;

      BFD_ASSERT(state->id == frag->state);

      RDBG("  0x%04lx%c%d: %s [size %ld]", rela ? rela->r_offset : sec->rawsize,
	   (frag->offset_adjust < 0)?'-':'+',
	   abs(frag->offset_adjust), state->name, state->size);

      if (!rela)
	{
	  RDBG(": no reloc, ignoring\n");
	  continue;
	}

      BFD_ASSERT((unsigned int)(rela - relocs) < sec->reloc_count);
      BFD_ASSERT(state != RS_NONE);

      r_offset = rela->r_offset + frag->offset_adjust;
      addr = sec->output_section->vma + sec->output_offset + r_offset;

      switch (frag->state)
	{
	case RS_ALIGN:
	  size_adjust = ((addr + (1 << rela->r_addend) - 1)
			 & ~((1 << rela->r_addend) - 1));
	  size_adjust -= (sec->output_section->vma + sec->output_offset
			  + frag->offset + frag->offset_adjust
			  + frag->size + frag->size_adjust);

	  RDBG(": adjusting size %lu -> %lu\n", frag->size + frag->size_adjust,
	       frag->size + frag->size_adjust + size_adjust);
	  break;

	case RS_CPENT:
	  if (frag->refcount == 0 && frag->size_adjust == 0)
	    {
	      RDBG(": discarding frag\n");
	      size_adjust = -4;
	    }
	  else if (frag->refcount > 0 && frag->size_adjust < 0)
	    {
	      RDBG(": un-discarding frag\n");
	      size_adjust = 4;
	    }
	  break;

	default:
	  if (rd->reloc_data)
	    r_data = &rd->reloc_data[frag->rela - relocs];

	  /* If this is a cpool reference, we want the symbol that the
	     cpool entry refers to, not the symbol for the cpool entry
	     itself, as we already know what frag it's in.  */
	  if (relax_state[frag->initial_state].reftype == REF_CPOOL)
	    {
	      Elf_Internal_Rela *irela = r_data->add_frag->rela;

	      r_symndx = ELF_R_SYM(irela->r_info);
	      addend = irela->r_addend;

	      /* The constant pool must be in the same section as the
		 reloc referring to it.  */
	      BFD_ASSERT((unsigned long)(irela - relocs) < sec->reloc_count);

	      ind_data = r_data;
	      r_data = &rd->reloc_data[irela - relocs];
	    }
	  else
	    {
	      r_symndx = ELF_R_SYM(rela->r_info);
	      addend = rela->r_addend;
	    }

	  /* Get the value of the symbol referred to by the reloc.  */
	  if (r_symndx < symtab_hdr->sh_info)
	    {
	      Elf_Internal_Sym *isym;

	      isym = isymbuf + r_symndx;
	      symval = 0;

	      RDBG(" local sym %lu: ", r_symndx);

	      if (isym->st_shndx == SHN_UNDEF)
		defined = FALSE;
	      else if (isym->st_shndx == SHN_ABS)
		sym_sec = bfd_abs_section_ptr;
	      else if (isym->st_shndx == SHN_COMMON)
		sym_sec = bfd_com_section_ptr;
	      else
		sym_sec = bfd_section_from_elf_index(abfd, isym->st_shndx);

	      symval = isym->st_value;
	      sym_type = ELF_ST_TYPE(isym->st_info);
	      target_frag = local_sym_frag[r_symndx];

	      if (local_got_ents)
		got = local_got_ents[r_symndx];
	      else
		got = NULL;
	    }
	  else
	    {
	      /* Global symbol */
	      unsigned long indx;
	      struct elf_link_hash_entry *h;
	      struct elf_avr32_link_hash_entry *havr;

	      indx = r_symndx - symtab_hdr->sh_info;
	      h = elf_sym_hashes(abfd)[indx];
	      BFD_ASSERT(h != NULL);

	      while (h->root.type == bfd_link_hash_indirect
		     || h->root.type == bfd_link_hash_warning)
		h = (struct elf_link_hash_entry *)h->root.u.i.link;

	      havr = (struct elf_avr32_link_hash_entry *)h;
	      got = h->got.glist;

	      symval = 0;

	      RDBG(" %s: ", h->root.root.string);

	      if (h->root.type != bfd_link_hash_defined
		  && h->root.type != bfd_link_hash_defweak)
		{
		  RDBG("(undef)");
		  defined = FALSE;
		}
	      else if ((info->shared && !info->symbolic && h->dynindx != -1)
		       || (htab->root.dynamic_sections_created
			   && h->def_dynamic && !h->def_regular))
		{
		  RDBG("(dynamic)");
		  dynamic = TRUE;
		  sym_sec = h->root.u.def.section;
		}
	      else
		{
		  sym_sec = h->root.u.def.section;
		  symval = h->root.u.def.value;
		  target_frag = havr->sym_frag;
		}

	      sym_type = h->type;
	    }

	  /* Thanks to elf32-ppc for this one.  */
	  if (sym_sec && sym_sec->sec_info_type == SEC_INFO_TYPE_MERGE)
	    {
	      /* At this stage in linking, no SEC_MERGE symbol has been
		 adjusted, so all references to such symbols need to be
		 passed through _bfd_merged_section_offset.  (Later, in
		 relocate_section, all SEC_MERGE symbols *except* for
		 section symbols have been adjusted.)

	         SEC_MERGE sections are not relaxed by us, as they
	         shouldn't contain any code.  */

	      BFD_ASSERT(!target_frag && !(r_data && r_data->add_frag));

	      /* gas may reduce relocations against symbols in SEC_MERGE
		 sections to a relocation against the section symbol when
		 the original addend was zero.  When the reloc is against
		 a section symbol we should include the addend in the
		 offset passed to _bfd_merged_section_offset, since the
		 location of interest is the original symbol.  On the
		 other hand, an access to "sym+addend" where "sym" is not
		 a section symbol should not include the addend;  Such an
		 access is presumed to be an offset from "sym";  The
		 location of interest is just "sym".  */
	      RDBG("\n    MERGE: %s: 0x%lx+0x%lx+0x%lx -> ",
		   (sym_type == STT_SECTION)?"section":"not section",
		   sym_sec->output_section->vma + sym_sec->output_offset,
		   symval, addend);

	      if (sym_type == STT_SECTION)
		symval += addend;

	      symval = (_bfd_merged_section_offset
			(abfd, &sym_sec,
			 elf_section_data(sym_sec)->sec_info, symval));

	      if (sym_type != STT_SECTION)
		symval += addend;
	    }
	  else
	    symval += addend;

	  if (defined && !dynamic)
	    {
	      RDBG("0x%lx+0x%lx",
		   sym_sec->output_section->vma + sym_sec->output_offset,
		   symval);
	      symval += sym_sec->output_section->vma + sym_sec->output_offset;
	    }

	  if (r_data && r_data->add_frag)
	    /* If the add_frag pointer is set, it means that this reloc
	       has an addend that may be affected by relaxation.  */
	    target_frag = r_data->add_frag;

	  if (target_frag)
	    {
	      symval += target_frag->offset_adjust;

	      /* If target_frag comes after this frag in the same
		 section, we should assume that it will be moved by
		 the same amount we are.  */
	      if ((target_frag - rd->frag) < (int)rd->frag_count
		  && target_frag > frag)
		symval += delta;
	    }

	  distance = symval - addr;

	  /* First, try to make a direct reference.  If the symbol is
	     dynamic or undefined, we must take care not to change its
	     reference type, that is, we can't make it direct.

	     Also, it seems like some sections may actually be resized
	     after the relaxation code is done, so we can't really
	     trust that our "distance" is correct.  There's really no
	     easy solution to this problem, so we'll just disallow
	     direct references to SEC_DATA sections.

	     Oh, and .bss isn't actually SEC_DATA, so we disallow
	     !SEC_HAS_CONTENTS as well. */
	  if (!dynamic && defined
	      && (htab->direct_data_refs
		  || (!(sym_sec->flags & SEC_DATA)
		      && (sym_sec->flags & SEC_HAS_CONTENTS)))
	      && next_state->direct)
	    {
	      next_state = &relax_state[next_state->direct];
	      RDBG(" D-> %s", next_state->name);
	    }

	  /* Iterate backwards until we find a state that fits.  */
	  while (next_state->prev
		 && !rs_is_good_enough(next_state, frag, symval, addr,
				       got, ind_data, delta))
	    {
	      next_state = &relax_state[next_state->prev];
	      RDBG(" P-> %s", next_state->name);
	    }

	  /* Then try to find the best possible state.  */
	  while (next_state->next)
	    {
	      const struct relax_state *candidate;

	      candidate = &relax_state[next_state->next];
	      if (!rs_is_good_enough(candidate, frag, symval, addr, got,
				     ind_data, delta))
		break;

	      next_state = candidate;
	      RDBG(" N-> %s", next_state->name);
	    }

	  RDBG(" [size %ld]\n", next_state->size);

	  BFD_ASSERT(next_state->id);
	  BFD_ASSERT(!dynamic || next_state->reftype == REF_GOT);

	  size_adjust = next_state->size - state->size;

	  /* There's a theoretical possibility that shrinking one frag
	     may cause another to grow, which may cause the first one to
	     grow as well, and we're back where we started.  Avoid this
	     scenario by disallowing a frag that has grown to ever
	     shrink again.  */
	  if (state->reftype == REF_GOT && next_state->reftype != REF_GOT)
	    {
	      if (frag->has_grown)
		next_state = state;
	      else
		unref_got_entry(htab, got);
	    }
	  else if (state->reftype != REF_GOT && next_state->reftype == REF_GOT)
	    {
	      ref_got_entry(htab, got);
	      frag->has_grown = TRUE;
	    }
	  else if (state->reftype == REF_CPOOL
		   && next_state->reftype != REF_CPOOL)
	    {
	      if (frag->has_grown)
		next_state = state;
	      else
		ind_data->add_frag->refcount--;
	    }
	  else if (state->reftype != REF_CPOOL
		   && next_state->reftype == REF_CPOOL)
	    {
	      ind_data->add_frag->refcount++;
	      frag->has_grown = TRUE;
	    }
	  else
	    {
	      if (frag->has_grown && size_adjust < 0)
		next_state = state;
	      else if (size_adjust > 0)
		frag->has_grown = TRUE;
	    }

	  size_adjust = next_state->size - state->size;
	  frag->state = next_state->id;

	  break;
	}

      if (size_adjust)
	htab->repeat_pass = TRUE;

      frag->size_adjust += size_adjust;
      sec->size += size_adjust;
      delta += size_adjust;

      BFD_ASSERT((frag->offset + frag->offset_adjust
		  + frag->size + frag->size_adjust)
		 == (frag[1].offset + frag[1].offset_adjust + delta));
    }

  ret = TRUE;

 out:
  release_local_syms(abfd, isymbuf);
  release_internal_relocs(sec, relocs);
  return ret;
}

static bfd_boolean
adjust_global_symbol(struct elf_avr32_link_hash_entry *havr,
		     struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  struct elf_link_hash_entry *h = &havr->root;

  if (havr->sym_frag && (h->root.type == bfd_link_hash_defined
			 || h->root.type == bfd_link_hash_defweak))
    {
      RDBG("adjust_global_symbol: %s 0x%08lx -> 0x%08lx\n",
	   h->root.root.string, h->root.u.def.value,
	   h->root.u.def.value + havr->sym_frag->offset_adjust);
      h->root.u.def.value += havr->sym_frag->offset_adjust;
    }
  return TRUE;
}

static bfd_boolean
adjust_syms(struct bfd_link_info *info)
{
  struct elf_avr32_link_hash_table *htab;
  bfd *abfd;

  htab = avr32_elf_hash_table(info);
  elf_link_hash_traverse(&htab->root, adjust_global_symbol, info);

  for (abfd = info->input_bfds; abfd; abfd = abfd->link_next)
    {
      Elf_Internal_Sym *isymbuf;
      struct fragment **local_sym_frag, *frag;
      unsigned int i, sym_count;

      sym_count = elf_tdata(abfd)->symtab_hdr.sh_info;
      if (sym_count == 0)
	continue;

      isymbuf = retrieve_local_syms(abfd, info->keep_memory);
      if (!isymbuf)
	return FALSE;

      local_sym_frag = elf_tdata(abfd)->local_sym_frag;

      for (i = 0; i < sym_count; i++)
	{
	  frag = local_sym_frag[i];
	  if (frag)
	    {
	      RDBG("adjust_local_symbol: %s[%u] 0x%08lx -> 0x%08lx\n",
		   abfd->filename, i, isymbuf[i].st_value,
		   isymbuf[i].st_value + frag->offset_adjust);
	      isymbuf[i].st_value += frag->offset_adjust;
	    }
	}

      release_local_syms(abfd, isymbuf);
    }

  htab->symbols_adjusted = TRUE;
  return TRUE;
}

static bfd_boolean
adjust_relocs(bfd *abfd, asection *sec, struct bfd_link_info *info)
{
  struct avr32_relax_data *rd;
  Elf_Internal_Rela *relocs;
  Elf_Internal_Shdr *symtab_hdr;
  unsigned int i;
  bfd_boolean ret = FALSE;

  rd = avr32_relax_data(sec);
  if (!rd->reloc_data)
    return TRUE;

  RDBG("adjust_relocs: %s<%s> (count: %u)\n", abfd->filename, sec->name,
       sec->reloc_count);

  relocs = retrieve_internal_relocs(abfd, sec, info->keep_memory);
  if (!relocs)
    return FALSE;

  symtab_hdr = &elf_tdata(abfd)->symtab_hdr;

  for (i = 0; i < sec->reloc_count; i++)
    {
      Elf_Internal_Rela *rela = &relocs[i];
      struct avr32_reloc_data *r_data = &rd->reloc_data[i];
      struct fragment *sym_frag;
      unsigned long r_symndx;

      if (r_data->add_frag)
	{
	  r_symndx = ELF_R_SYM(rela->r_info);

	  if (r_symndx < symtab_hdr->sh_info)
	    sym_frag = elf_tdata(abfd)->local_sym_frag[r_symndx];
	  else
	    {
	      struct elf_link_hash_entry *h;

	      h = elf_sym_hashes(abfd)[r_symndx - symtab_hdr->sh_info];

	      while (h->root.type == bfd_link_hash_indirect
		     || h->root.type == bfd_link_hash_warning)
		h = (struct elf_link_hash_entry *)h->root.u.i.link;

	      BFD_ASSERT(h->root.type == bfd_link_hash_defined
			 || h->root.type == bfd_link_hash_defweak);

	      sym_frag = ((struct elf_avr32_link_hash_entry *)h)->sym_frag;
	    }

	  RDBG("    addend: 0x%08lx -> 0x%08lx\n",
	       rela->r_addend,
	       rela->r_addend + r_data->add_frag->offset_adjust
	       - (sym_frag ? sym_frag->offset_adjust : 0));

	  /* If this is against a section symbol, we won't find any
	     sym_frag, so we'll just adjust the addend.  */
	  rela->r_addend += r_data->add_frag->offset_adjust;
	  if (sym_frag)
	    rela->r_addend -= sym_frag->offset_adjust;

	  if (r_data->sub_frag)
	    {
	      bfd_byte *contents;
	      bfd_signed_vma diff;

	      contents = retrieve_contents(abfd, sec, info->keep_memory);
	      if (!contents)
		goto out;

	      /* I realize now that sub_frag is misnamed.  It's
		 actually add_frag which is subtracted in this
		 case...  */
	      diff = bfd_get_signed_32(abfd, contents + rela->r_offset);
	      diff += (r_data->sub_frag->offset_adjust
		       - r_data->add_frag->offset_adjust);
	      bfd_put_32(abfd, diff, contents + rela->r_offset);

	      RDBG("   0x%lx: DIFF32 updated: 0x%lx\n", rela->r_offset, diff);

	      release_contents(sec, contents);
	    }
	}
      else
	BFD_ASSERT(!r_data->sub_frag);
    }

  ret = TRUE;

 out:
  release_internal_relocs(sec, relocs);
  return ret;
}

static bfd_boolean
avr32_move_data(bfd *abfd, asection *sec, struct bfd_link_info *info)
{
  struct elf_avr32_link_hash_table *htab;
  struct avr32_relax_data *rd;
  struct fragment *frag, *fragend;
  Elf_Internal_Rela *relocs = NULL;
  bfd_byte *contents = NULL;
  unsigned int i;
  bfd_boolean ret = FALSE;

  htab = avr32_elf_hash_table(info);
  rd = avr32_relax_data(sec);

  if (!htab->symbols_adjusted)
    if (!adjust_syms(info))
      return FALSE;

  if (rd->is_relaxable)
    {
      /* Resize the section first, so that we can be sure that enough
	 memory is allocated in case the section has grown.  */
      if (sec->size > sec->rawsize
	  && elf_section_data(sec)->this_hdr.contents)
	{
	  /* We must not use cached data if the section has grown.  */
	  free(elf_section_data(sec)->this_hdr.contents);
	  elf_section_data(sec)->this_hdr.contents = NULL;
	}

      relocs = retrieve_internal_relocs(abfd, sec, info->keep_memory);
      if (!relocs)
	goto out;
      contents = retrieve_contents(abfd, sec, info->keep_memory);
      if (!contents)
	goto out;

      fragend = rd->frag + rd->frag_count;

      RDBG("move_data: %s<%s>: relocs=%p, contents=%p\n",
	   abfd->filename, sec->name, relocs, contents);

      /* First, move the data into place. We must take care to move
	 frags in the right order so that we don't accidentally
	 overwrite parts of the next frag.  */
      for (frag = rd->frag; frag < fragend; frag++)
	{
	  RDBG("    0x%08lx%c0x%x: size 0x%lx%c0x%x\n",
	       frag->offset, frag->offset_adjust >= 0 ? '+' : '-',
	       abs(frag->offset_adjust),
	       frag->size, frag->size_adjust >= 0 ? '+' : '-',
	       abs(frag->size_adjust));
	  if (frag->offset_adjust > 0)
	    {
	      struct fragment *prev = frag - 1;
	      struct fragment *last;

	      for (last = frag; last < fragend && last->offset_adjust > 0;
		   last++) ;

	      if (last == fragend)
		last--;

	      for (frag = last; frag != prev; frag--)
		{
		  if (frag->offset_adjust
		      && frag->size + frag->size_adjust > 0)
		    {
		      RDBG("memmove 0x%lx -> 0x%lx (size %lu)\n",
			   frag->offset, frag->offset + frag->offset_adjust,
			   frag->size + frag->size_adjust);
		      memmove(contents + frag->offset + frag->offset_adjust,
			      contents + frag->offset,
			      frag->size + frag->size_adjust);
		    }
		}
	      frag = last;
	    }
	  else if (frag->offset_adjust && frag->size + frag->size_adjust > 0)
	    {
	      RDBG("memmove 0x%lx -> 0x%lx (size %lu)\n",
		   frag->offset, frag->offset + frag->offset_adjust,
		   frag->size + frag->size_adjust);
	      memmove(contents + frag->offset + frag->offset_adjust,
		      contents + frag->offset,
		      frag->size + frag->size_adjust);
	    }
	}

      i = 0;

      for (frag = rd->frag; frag < fragend; frag++)
	{
	  const struct relax_state *state, *istate;
	  struct avr32_reloc_data *r_data = NULL;

	  istate = &relax_state[frag->initial_state];
	  state = &relax_state[frag->state];

	  if (rd->reloc_data)
	    r_data = &rd->reloc_data[frag->rela - relocs];

	  BFD_ASSERT((long)(frag->size + frag->size_adjust) >= 0);
	  BFD_ASSERT(state->reftype != REF_CPOOL
		     || r_data->add_frag->refcount > 0);

	  if (istate->reftype == REF_CPOOL && state->reftype != REF_CPOOL)
	    {
	      struct fragment *ifrag;

	      /* An indirect reference through the cpool has been
		 converted to a direct reference.  We must update the
		 reloc to point to the symbol itself instead of the
		 constant pool entry.  The reloc type will be updated
		 later.  */
	      ifrag = r_data->add_frag;
	      frag->rela->r_info = ifrag->rela->r_info;
	      frag->rela->r_addend = ifrag->rela->r_addend;

	      /* Copy the reloc data so the addend will be adjusted
		 correctly later.  */
	      *r_data = rd->reloc_data[ifrag->rela - relocs];
	    }

	  /* Move all relocs covered by this frag.  */
	  if (frag->rela)
	    BFD_ASSERT(&relocs[i] <= frag->rela);
	  else
	    BFD_ASSERT((frag + 1) == fragend && frag->state == RS_NONE);

	  if (frag == rd->frag)
	    BFD_ASSERT(i == 0);
	  else
	    BFD_ASSERT(&relocs[i] > frag[-1].rela);

	  /* If non-null, frag->rela is the last relocation in the
	     fragment.  frag->rela can only be null in the last
	     fragment, so in that case, we'll just do the rest.  */
	  for (; (i < sec->reloc_count
		  && (!frag->rela || &relocs[i] <= frag->rela)); i++)
	    {
	      RDBG("[%4u] r_offset 0x%08lx -> 0x%08lx\n", i, relocs[i].r_offset,
		   relocs[i].r_offset + frag->offset_adjust);
	      relocs[i].r_offset += frag->offset_adjust;
	    }

	  if (frag->refcount == 0)
	    {
	      /* If this frag is to be discarded, make sure we won't
		 relocate it later on.  */
	      BFD_ASSERT(frag->state == RS_CPENT);
	      frag->rela->r_info = ELF_R_INFO(ELF_R_SYM(frag->rela->r_info),
					    R_AVR32_NONE);
	    }
	  else if (frag->state == RS_ALIGN)
	    {
	      bfd_vma addr, addr_end;

	      addr = frag->rela->r_offset;
	      addr_end = (frag->offset + frag->offset_adjust
			  + frag->size + frag->size_adjust);

	      /* If the section is executable, insert NOPs.
		 Otherwise, insert zeroes.  */
	      if (sec->flags & SEC_CODE)
		{
		  if (addr & 1)
		    {
		      bfd_put_8(abfd, 0, contents + addr);
		      addr++;
		    }

		  BFD_ASSERT(!((addr_end - addr) & 1));

		  while (addr < addr_end)
		    {
		      bfd_put_16(abfd, NOP_OPCODE, contents + addr);
		      addr += 2;
		    }
		}
	      else
		memset(contents + addr, 0, addr_end - addr);
	    }
	  else if (state->opcode_mask)
	    {
	      bfd_vma insn;

	      /* Update the opcode and the relocation type unless it's a
		 "special" relax state (i.e. RS_NONE, RS_ALIGN or
		 RS_CPENT.), in which case the opcode mask is zero.  */
	      insn = bfd_get_32(abfd, contents + frag->rela->r_offset);
	      insn &= ~state->opcode_mask;
	      insn |= state->opcode;
	      RDBG("    0x%lx: inserting insn %08lx\n",
		   frag->rela->r_offset, insn);
	      bfd_put_32(abfd, insn, contents + frag->rela->r_offset);

	      frag->rela->r_info = ELF_R_INFO(ELF_R_SYM(frag->rela->r_info),
					      state->r_type);
	    }

	  if ((frag + 1) == fragend)
	    BFD_ASSERT((frag->offset + frag->size + frag->offset_adjust
			+ frag->size_adjust) == sec->size);
	  else
	    BFD_ASSERT((frag->offset + frag->size + frag->offset_adjust
			+ frag->size_adjust)
		       == (frag[1].offset + frag[1].offset_adjust));
	}
    }

  /* Adjust reloc addends and DIFF32 differences */
  if (!adjust_relocs(abfd, sec, info))
    return FALSE;

  ret = TRUE;

 out:
  release_contents(sec, contents);
  release_internal_relocs(sec, relocs);
  return ret;
}

static bfd_boolean
avr32_elf_relax_section(bfd *abfd, asection *sec,
			struct bfd_link_info *info, bfd_boolean *again)
{
  struct elf_avr32_link_hash_table *htab;
  struct avr32_relax_data *rd;

  *again = FALSE;
  if (info->relocatable)
    return TRUE;

  htab = avr32_elf_hash_table(info);
  if ((!(sec->flags & SEC_RELOC) || sec->reloc_count == 0)
      && sec != htab->sgot)
    return TRUE;

  if (!htab->relocations_analyzed)
    {
      if (!analyze_relocations(info))
	return FALSE;
      htab->relocations_analyzed = TRUE;
    }

  rd = avr32_relax_data(sec);

  if (rd->iteration != htab->relax_iteration)
    {
      if (!htab->repeat_pass)
	htab->relax_pass++;
      htab->relax_iteration++;
      htab->repeat_pass = FALSE;
    }

  rd->iteration++;

  switch (htab->relax_pass)
    {
    case RELAX_PASS_SIZE_FRAGS:
      if (!avr32_size_frags(abfd, sec, info))
	return FALSE;
      *again = TRUE;
      break;
    case RELAX_PASS_MOVE_DATA:
      if (!avr32_move_data(abfd, sec, info))
	return FALSE;
      break;
  }

  return TRUE;
}


/* Relocation */

static bfd_reloc_status_type
avr32_check_reloc_value(asection *sec, Elf_Internal_Rela *rela,
			bfd_signed_vma relocation, reloc_howto_type *howto);
static bfd_reloc_status_type
avr32_final_link_relocate(reloc_howto_type *howto, bfd *input_bfd,
			  asection *input_section, bfd_byte *contents,
			  Elf_Internal_Rela *rel, bfd_vma value);
static bfd_boolean
avr32_elf_relocate_section(bfd *output_bfd, struct bfd_link_info *info,
			   bfd *input_bfd, asection *input_section,
			   bfd_byte *contents, Elf_Internal_Rela *relocs,
			   Elf_Internal_Sym *local_syms,
			   asection **local_sections);


#define symbol_address(symbol) \
  symbol->value + symbol->section->output_section->vma \
  + symbol->section->output_offset

#define avr32_elf_insert_field(size, field, abfd, reloc_entry, data)	\
  do									\
    {									\
      unsigned long x;							\
      x = bfd_get_##size (abfd, data + reloc_entry->address);		\
      x &= ~reloc_entry->howto->dst_mask;				\
      x |= field & reloc_entry->howto->dst_mask;			\
      bfd_put_##size (abfd, (bfd_vma) x, data + reloc_entry->address);	\
    }									\
  while(0)

static bfd_reloc_status_type
avr32_check_reloc_value(asection *sec ATTRIBUTE_UNUSED,
			Elf_Internal_Rela *rela ATTRIBUTE_UNUSED,
			bfd_signed_vma relocation,
			reloc_howto_type *howto)
{
  bfd_vma reloc_u;

  /* We take "complain_overflow_dont" to mean "don't complain on
     alignment either". This way, we don't have to special-case
     R_AVR32_HI16 */
  if (howto->complain_on_overflow == complain_overflow_dont)
    return bfd_reloc_ok;

  /* Check if the value is correctly aligned */
  if (relocation & ((1 << howto->rightshift) - 1))
    {
      RDBG("misaligned: %s<%s+%lx>: %s: 0x%lx (align %u)\n",
	   sec->owner->filename, sec->name, rela->r_offset,
	   howto->name, relocation, howto->rightshift);
      return bfd_reloc_overflow;
    }

  /* Now, get rid of the unnecessary bits */
  relocation >>= howto->rightshift;
  reloc_u = (bfd_vma)relocation;

  switch (howto->complain_on_overflow)
    {
    case complain_overflow_unsigned:
    case complain_overflow_bitfield:
      if (reloc_u > (unsigned long)((1 << howto->bitsize) - 1))
	{
	  RDBG("unsigned overflow: %s<%s+%lx>: %s: 0x%lx (size %u)\n",
	       sec->owner->filename, sec->name, rela->r_offset,
	       howto->name, reloc_u, howto->bitsize);
	  RDBG("reloc vma: 0x%lx\n",
	       sec->output_section->vma + sec->output_offset + rela->r_offset);

	  return bfd_reloc_overflow;
	}
      break;
    case complain_overflow_signed:
      if (relocation > (1 << (howto->bitsize - 1)) - 1)
	{
	  RDBG("signed overflow: %s<%s+%lx>: %s: 0x%lx (size %u)\n",
	       sec->owner->filename, sec->name, rela->r_offset,
	       howto->name, reloc_u, howto->bitsize);
	  RDBG("reloc vma: 0x%lx\n",
	       sec->output_section->vma + sec->output_offset + rela->r_offset);

	  return bfd_reloc_overflow;
	}
      if (relocation < -(1 << (howto->bitsize - 1)))
	{
	  RDBG("signed overflow: %s<%s+%lx>: %s: -0x%lx (size %u)\n",
	       sec->owner->filename, sec->name, rela->r_offset,
	       howto->name, -relocation, howto->bitsize);
	  RDBG("reloc vma: 0x%lx\n",
	       sec->output_section->vma + sec->output_offset + rela->r_offset);

	  return bfd_reloc_overflow;
	}
      break;
    default:
      abort();
    }

  return bfd_reloc_ok;
}


static bfd_reloc_status_type
avr32_final_link_relocate(reloc_howto_type *howto,
			  bfd *input_bfd,
			  asection *input_section,
			  bfd_byte *contents,
			  Elf_Internal_Rela *rel,
			  bfd_vma value)
{
  bfd_vma field;
  bfd_vma relocation;
  bfd_reloc_status_type status;
  bfd_byte *p = contents + rel->r_offset;
  unsigned long x;

  pr_debug("  (6b) final link relocate\n");

  /* Sanity check the address */
  if (rel->r_offset >= input_section->size
        && rel->r_offset >= input_section->rawsize)
    {
      (*_bfd_error_handler)
	("%B: %A+0x%lx: offset out of range (section size: 0x%lx)",
	 input_bfd, input_section, rel->r_offset, input_section->size);
      return bfd_reloc_outofrange;
    }

  relocation = value + rel->r_addend;

  if (howto->pc_relative)
    {
      bfd_vma addr;

      addr = input_section->output_section->vma
	+ input_section->output_offset + rel->r_offset;
      addr &= ~0UL << howto->rightshift;
      relocation -= addr;
    }

  switch (ELF32_R_TYPE(rel->r_info))
    {
    case R_AVR32_16N_PCREL:
      /* sub reg, pc, . - (sym + addend) */
      relocation = -relocation;
      break;
    }

  status = avr32_check_reloc_value(input_section, rel, relocation, howto);

  relocation >>= howto->rightshift;
  if (howto->bitsize == 21)
    field = (relocation & 0xffff)
      | ((relocation & 0x10000) << 4)
      | ((relocation & 0x1e0000) << 8);
  else if (howto->bitsize == 12)
    field = (relocation & 0xff) | ((relocation & 0xf00) << 4);
  else if (howto->bitsize == 10)
    field = ((relocation & 0xff) << 4)
      | ((relocation & 0x300) >> 8);
  else
    field = relocation << howto->bitpos;

  switch (howto->size)
    {
    case 0:
      x = bfd_get_8 (input_bfd, p);
      x &= ~howto->dst_mask;
      x |= field & howto->dst_mask;
      bfd_put_8 (input_bfd, (bfd_vma) x, p);
      break;
    case 1:
      x = bfd_get_16 (input_bfd, p);
      x &= ~howto->dst_mask;
      x |= field & howto->dst_mask;
      bfd_put_16 (input_bfd, (bfd_vma) x, p);
      break;
    case 2:
      x = bfd_get_32 (input_bfd, p);
      x &= ~howto->dst_mask;
      x |= field & howto->dst_mask;
      bfd_put_32 (input_bfd, (bfd_vma) x, p);
      break;
    default:
      abort();
    }

  return status;
}

/* (6) Apply relocations to the normal (non-dynamic) sections */

static bfd_boolean
avr32_elf_relocate_section(bfd *output_bfd, struct bfd_link_info *info,
			   bfd *input_bfd, asection *input_section,
			   bfd_byte *contents, Elf_Internal_Rela *relocs,
			   Elf_Internal_Sym *local_syms,
			   asection **local_sections)
{
  struct elf_avr32_link_hash_table *htab;
  Elf_Internal_Shdr *symtab_hdr;
  Elf_Internal_Rela *rel, *relend;
  struct elf_link_hash_entry **sym_hashes;
  struct got_entry **local_got_ents;
  asection *sgot;
  asection *srelgot;

  pr_debug("(6) relocate section %s:<%s> (size 0x%lx)\n",
	   input_bfd->filename, input_section->name, input_section->size);

  /* If we're doing a partial link, we don't have to do anything since
     we're using RELA relocations */
  if (info->relocatable)
    return TRUE;

  htab = avr32_elf_hash_table(info);
  symtab_hdr = &elf_tdata(input_bfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes(input_bfd);
  local_got_ents = elf_local_got_ents(input_bfd);
  sgot = htab->sgot;
  srelgot = htab->srelgot;

  relend = relocs + input_section->reloc_count;
  for (rel = relocs; rel < relend; rel++)
    {
      unsigned long r_type, r_symndx;
      reloc_howto_type *howto;
      Elf_Internal_Sym *sym = NULL;
      struct elf_link_hash_entry *h = NULL;
      asection *sec = NULL;
      bfd_vma value;
      bfd_vma offset;
      bfd_reloc_status_type status;

      r_type = ELF32_R_TYPE(rel->r_info);
      r_symndx = ELF32_R_SYM(rel->r_info);

      if (r_type == R_AVR32_NONE
	  || r_type == R_AVR32_ALIGN
	  || r_type == R_AVR32_DIFF32
	  || r_type == R_AVR32_DIFF16
	  || r_type == R_AVR32_DIFF8)
	continue;

      /* Sanity check */
      if (r_type > R_AVR32_max)
	{
	  bfd_set_error(bfd_error_bad_value);
	  return FALSE;
	}

      howto = &elf_avr32_howto_table[r_type];

      if (r_symndx < symtab_hdr->sh_info)
	{
	  sym = local_syms + r_symndx;
	  sec = local_sections[r_symndx];

	  pr_debug("  (6a) processing %s against local symbol %lu\n",
		   howto->name, r_symndx);

	  /* The following function changes rel->r_addend behind our back. */
	  value = _bfd_elf_rela_local_sym(output_bfd, sym, &sec, rel);
	  pr_debug("    => value: %lx, addend: %lx\n", value, rel->r_addend);
	}
      else
	{
	  if (sym_hashes == NULL)
	    return FALSE;

	  h = sym_hashes[r_symndx - symtab_hdr->sh_info];
	  while (h->root.type == bfd_link_hash_indirect
		 || h->root.type == bfd_link_hash_warning)
	    h = (struct elf_link_hash_entry *)h->root.u.i.link;

	  pr_debug("  (6a) processing %s against symbol %s\n",
		   howto->name, h->root.root.string);

	  if (h->root.type == bfd_link_hash_defined
	      || h->root.type == bfd_link_hash_defweak)
	    {
	      bfd_boolean dyn;

	      dyn = htab->root.dynamic_sections_created;
	      sec = h->root.u.def.section;

	      if (sec->output_section)
		value = (h->root.u.def.value
			 + sec->output_section->vma
			 + sec->output_offset);
	      else
		value = h->root.u.def.value;
	    }
	  else if (h->root.type == bfd_link_hash_undefweak)
	    value = 0;
	  else if (info->unresolved_syms_in_objects == RM_IGNORE
		   && ELF_ST_VISIBILITY(h->other) == STV_DEFAULT)
	    value = 0;
	  else
	    {
	      bfd_boolean err;
	      err = (info->unresolved_syms_in_objects == RM_GENERATE_ERROR
		     || ELF_ST_VISIBILITY(h->other) != STV_DEFAULT);
	      if (!info->callbacks->undefined_symbol
		  (info, h->root.root.string, input_bfd,
		   input_section, rel->r_offset, err))
		return FALSE;
	      value = 0;
	    }

	  pr_debug("    => value: %lx, addend: %lx\n", value, rel->r_addend);
	}

      switch (r_type)
	{
	case R_AVR32_GOT32:
	case R_AVR32_GOT16:
	case R_AVR32_GOT8:
	case R_AVR32_GOT21S:
	case R_AVR32_GOT18SW:
	case R_AVR32_GOT16S:
	case R_AVR32_GOT7UW:
	case R_AVR32_LDA_GOT:
	case R_AVR32_GOTCALL:
	  BFD_ASSERT(sgot != NULL);

	  if (h != NULL)
	    {
	      BFD_ASSERT(h->got.glist->refcount > 0);
	      offset = h->got.glist->offset;

	      BFD_ASSERT(offset < sgot->size);
	      if (!elf_hash_table(info)->dynamic_sections_created
		  || (h->def_regular
		      && (!info->shared
			  || info->symbolic
			  || h->dynindx == -1)))
		{
		  /* This is actually a static link, or it is a
		     -Bsymbolic link and the symbol is defined
		     locally, or the symbol was forced to be local.  */
		  bfd_put_32(output_bfd, value, sgot->contents + offset);
		}
	    }
	  else
	    {
	      BFD_ASSERT(local_got_ents &&
			 local_got_ents[r_symndx]->refcount > 0);
	      offset = local_got_ents[r_symndx]->offset;

	      /* Local GOT entries don't have relocs.  If this is a
		 shared library, the dynamic linker will add the load
		 address to the initial value at startup.  */
	      BFD_ASSERT(offset < sgot->size);
	      pr_debug("Initializing GOT entry at offset %lu: 0x%lx\n",
		       offset, value);
	      bfd_put_32 (output_bfd, value, sgot->contents + offset);
	    }

	  value = sgot->output_offset + offset;
	  pr_debug("GOT reference: New value %lx\n", value);
	  break;

	case R_AVR32_GOTPC:
	  /* This relocation type is for constant pool entries used in
	     the calculation "Rd = PC - (PC - GOT)", where the
	     constant pool supplies the constant (PC - GOT)
	     offset. The symbol value + addend indicates where the
	     value of PC is taken. */
	  value -= sgot->output_section->vma;
	  break;

	case R_AVR32_32_PCREL:
	  /* We must adjust r_offset to account for discarded data in
	     the .eh_frame section.  This is probably not the right
	     way to do this, since AFAICS all other architectures do
	     it some other way.  I just can't figure out how...  */
	  {
	    bfd_vma r_offset;

	    r_offset = _bfd_elf_section_offset(output_bfd, info,
					       input_section,
					       rel->r_offset);
	    if (r_offset == (bfd_vma)-1
		|| r_offset == (bfd_vma)-2)
	      continue;
	    rel->r_offset = r_offset;
	  }
	  break;

	case R_AVR32_32:
	  /* We need to emit a run-time relocation in the following cases:
	       - we're creating a shared library
	       - the symbol is not defined in any regular objects

	     Of course, sections that aren't going to be part of the
	     run-time image will not get any relocs, and undefined
	     symbols won't have any either (only weak undefined
	     symbols should get this far).  */
	  if ((info->shared
	       || (elf_hash_table(info)->dynamic_sections_created
		   && h != NULL
		   && h->def_dynamic
		   && !h->def_regular))
	      && r_symndx != 0
	      && (input_section->flags & SEC_ALLOC))
	    {
	      Elf_Internal_Rela outrel;
	      bfd_byte *loc;
	      bfd_boolean skip, relocate;
	      struct elf_avr32_link_hash_entry *avrh;

	      pr_debug("Going to generate dynamic reloc...\n");

	      skip = FALSE;
	      relocate = FALSE;

	      outrel.r_offset = _bfd_elf_section_offset(output_bfd, info,
							input_section,
							rel->r_offset);
	      if (outrel.r_offset == (bfd_vma)-1)
		skip = TRUE;
	      else if (outrel.r_offset == (bfd_vma)-2)
		skip = TRUE, relocate = TRUE;

	      outrel.r_offset += (input_section->output_section->vma
				  + input_section->output_offset);

	      pr_debug("    ... offset %lx, dynindx %ld\n",
		       outrel.r_offset, h ? h->dynindx : -1);

	      if (skip)
		memset(&outrel, 0, sizeof(outrel));
	      else
		{
		  avrh = (struct elf_avr32_link_hash_entry *)h;
		  /* h->dynindx may be -1 if this symbol was marked to
		     become local.  */
		  if (h == NULL
		      || ((info->symbolic || h->dynindx == -1)
			  && h->def_regular))
		    {
		      relocate = TRUE;
		      outrel.r_info = ELF32_R_INFO(0, R_AVR32_RELATIVE);
		      outrel.r_addend = value + rel->r_addend;
		      pr_debug("    ... R_AVR32_RELATIVE\n");
		    }
		  else
		    {
		      BFD_ASSERT(h->dynindx != -1);
		      relocate = TRUE;
		      outrel.r_info = ELF32_R_INFO(h->dynindx, R_AVR32_GLOB_DAT);
		      outrel.r_addend = rel->r_addend;
		      pr_debug("    ... R_AVR32_GLOB_DAT\n");
		    }
		}

	      pr_debug("srelgot reloc_count: %d, size %lu\n",
		       srelgot->reloc_count, srelgot->size);

	      loc = srelgot->contents;
	      loc += srelgot->reloc_count++ * sizeof(Elf32_External_Rela);
	      bfd_elf32_swap_reloca_out(output_bfd, &outrel, loc);

	      BFD_ASSERT(srelgot->reloc_count * sizeof(Elf32_External_Rela)
			 <= srelgot->size);

	      if (!relocate)
		continue;
	    }
	  break;
	}

      status = avr32_final_link_relocate(howto, input_bfd, input_section,
					 contents, rel, value);

      switch (status)
	{
	case bfd_reloc_ok:
	  break;

	case bfd_reloc_overflow:
	  {
	    const char *name;

	    if (h != NULL)
	      name = h->root.root.string;
	    else
	      {
		name = bfd_elf_string_from_elf_section(input_bfd,
						       symtab_hdr->sh_link,
						       sym->st_name);
		if (name == NULL)
		  return FALSE;
		if (*name == '\0')
		  name = bfd_section_name(input_bfd, sec);
	      }
	    if (!((*info->callbacks->reloc_overflow)
		  (info, (h ? &h->root : NULL), name, howto->name,
		   rel->r_addend, input_bfd, input_section, rel->r_offset)))
	      return FALSE;
	  }
	  break;

	case bfd_reloc_outofrange:
	default:
	  abort();
	}
    }

  return TRUE;
}


/* Additional processing of dynamic sections after relocation */

static bfd_boolean
avr32_elf_finish_dynamic_symbol(bfd *output_bfd, struct bfd_link_info *info,
				struct elf_link_hash_entry *h,
				Elf_Internal_Sym *sym);
static bfd_boolean
avr32_elf_finish_dynamic_sections(bfd *output_bfd, struct bfd_link_info *info);


/* (7) Initialize the contents of a dynamic symbol and/or emit
   relocations for it */

static bfd_boolean
avr32_elf_finish_dynamic_symbol(bfd *output_bfd, struct bfd_link_info *info,
				struct elf_link_hash_entry *h,
				Elf_Internal_Sym *sym)
{
  struct elf_avr32_link_hash_table *htab;
  struct got_entry *got;

  pr_debug("(7) finish dynamic symbol: %s\n", h->root.root.string);

  htab = avr32_elf_hash_table(info);
  got = h->got.glist;

  if (got && got->refcount > 0)
    {
      asection *sgot;
      asection *srelgot;
      Elf_Internal_Rela rel;
      bfd_byte *loc;

      /* This symbol has an entry in the GOT. Set it up. */
      sgot = htab->sgot;
      srelgot = htab->srelgot;
      BFD_ASSERT(sgot && srelgot);

      rel.r_offset = (sgot->output_section->vma
		      + sgot->output_offset
		      + got->offset);

      /* If this is a static link, or it is a -Bsymbolic link and the
	 symbol is defined locally or was forced to be local because
	 of a version file, we just want to emit a RELATIVE reloc. The
	 entry in the global offset table will already have been
	 initialized in the relocate_section function. */
      if ((info->shared
	   && !info->symbolic
	   && h->dynindx != -1)
	  || (htab->root.dynamic_sections_created
	      && h->def_dynamic
	      && !h->def_regular))
	{
	  bfd_put_32(output_bfd, 0, sgot->contents + got->offset);
	  rel.r_info = ELF32_R_INFO(h->dynindx, R_AVR32_GLOB_DAT);
	  rel.r_addend = 0;

	  pr_debug("GOT reloc R_AVR32_GLOB_DAT, dynindx: %ld\n", h->dynindx);
	  pr_debug("    srelgot reloc_count: %d, size: %lu\n",
		   srelgot->reloc_count, srelgot->size);

	  loc = (srelgot->contents
		 + srelgot->reloc_count++ * sizeof(Elf32_External_Rela));
	  bfd_elf32_swap_reloca_out(output_bfd, &rel, loc);

	  BFD_ASSERT(srelgot->reloc_count * sizeof(Elf32_External_Rela)
		     <= srelgot->size);
	}
    }

  /* Mark _DYNAMIC and _GLOBAL_OFFSET_TABLE_ as absolute */
  if (strcmp(h->root.root.string, "_DYNAMIC") == 0
      || strcmp(h->root.root.string, "_GLOBAL_OFFSET_TABLE_") == 0)
    sym->st_shndx = SHN_ABS;

  return TRUE;
}

/* (8) Do any remaining initialization of the dynamic sections */

static bfd_boolean
avr32_elf_finish_dynamic_sections(bfd *output_bfd, struct bfd_link_info *info)
{
  struct elf_avr32_link_hash_table *htab;
  asection *sgot, *sdyn;

  pr_debug("(8) finish dynamic sections\n");

  htab = avr32_elf_hash_table(info);
  sgot = htab->sgot;
  sdyn = bfd_get_section_by_name(htab->root.dynobj, ".dynamic");

  if (htab->root.dynamic_sections_created)
    {
      Elf32_External_Dyn *dyncon, *dynconend;

      BFD_ASSERT(sdyn && sgot && sgot->size >= AVR32_GOT_HEADER_SIZE);

      dyncon = (Elf32_External_Dyn *)sdyn->contents;
      dynconend = (Elf32_External_Dyn *)(sdyn->contents + sdyn->size);
      for (; dyncon < dynconend; dyncon++)
	{
	  Elf_Internal_Dyn dyn;
	  asection *s;

	  bfd_elf32_swap_dyn_in(htab->root.dynobj, dyncon, &dyn);

	  switch (dyn.d_tag)
	    {
	    default:
	      break;

	    case DT_PLTGOT:
	      s = sgot->output_section;
	      BFD_ASSERT(s != NULL);
	      dyn.d_un.d_ptr = s->vma;
	      bfd_elf32_swap_dyn_out(output_bfd, &dyn, dyncon);
	      break;

	    case DT_AVR32_GOTSZ:
	      s = sgot->output_section;
	      BFD_ASSERT(s != NULL);
	      dyn.d_un.d_val = s->size;
	      bfd_elf32_swap_dyn_out(output_bfd, &dyn, dyncon);
	      break;
	    }
	}

      /* Fill in the first two entries in the global offset table */
      bfd_put_32(output_bfd,
		 sdyn->output_section->vma + sdyn->output_offset,
		 sgot->contents);

      /* The runtime linker will fill this one in with the address of
	 the run-time link map */
      bfd_put_32(output_bfd, 0, sgot->contents + 4);
    }

  if (sgot)
    elf_section_data(sgot->output_section)->this_hdr.sh_entsize = 4;

  return TRUE;
}


/* AVR32-specific private ELF data */

static bfd_boolean
avr32_elf_set_private_flags(bfd *abfd, flagword flags);
static bfd_boolean
avr32_elf_copy_private_bfd_data(bfd *ibfd, bfd *obfd);
static bfd_boolean
avr32_elf_merge_private_bfd_data(bfd *ibfd, bfd *obfd);
static bfd_boolean
avr32_elf_print_private_bfd_data(bfd *abfd, void *ptr);

static bfd_boolean
avr32_elf_set_private_flags(bfd *abfd, flagword flags)
{
  elf_elfheader(abfd)->e_flags = flags;
  elf_flags_init(abfd) = TRUE;

  return TRUE;
}

/* Copy backend specific data from one object module to another.  */

static bfd_boolean
avr32_elf_copy_private_bfd_data(bfd *ibfd, bfd *obfd)
{
  elf_elfheader(obfd)->e_flags = elf_elfheader(ibfd)->e_flags;
  return TRUE;
}

/* Merge backend specific data from an object file to the output
   object file when linking.  */

static bfd_boolean
avr32_elf_merge_private_bfd_data(bfd *ibfd, bfd *obfd)
{
  flagword out_flags, in_flags;

  pr_debug("(0) merge_private_bfd_data: %s -> %s\n",
	   ibfd->filename, obfd->filename);

  in_flags = elf_elfheader(ibfd)->e_flags;
  out_flags = elf_elfheader(obfd)->e_flags;

  if (elf_flags_init(obfd))
    {
      /* If one of the inputs are non-PIC, the output must be
	 considered non-PIC.  The same applies to linkrelax.  */
      if (!(in_flags & EF_AVR32_PIC))
	out_flags &= ~EF_AVR32_PIC;
      if (!(in_flags & EF_AVR32_LINKRELAX))
	out_flags &= ~EF_AVR32_LINKRELAX;
    }
  else
    {
      elf_flags_init(obfd) = TRUE;
      out_flags = in_flags;
    }

  elf_elfheader(obfd)->e_flags = out_flags;

  return TRUE;
}

static bfd_boolean
avr32_elf_print_private_bfd_data(bfd *abfd, void *ptr)
{
  FILE *file = (FILE *)ptr;
  unsigned long flags;

  BFD_ASSERT(abfd != NULL && ptr != NULL);

  _bfd_elf_print_private_bfd_data(abfd, ptr);

  flags = elf_elfheader(abfd)->e_flags;

  fprintf(file, _("private flags = %lx:"), elf_elfheader(abfd)->e_flags);

  if (flags & EF_AVR32_PIC)
    fprintf(file, " [PIC]");
  if (flags & EF_AVR32_LINKRELAX)
    fprintf(file, " [linker relaxable]");

  flags &= ~(EF_AVR32_PIC | EF_AVR32_LINKRELAX);

  if (flags)
    fprintf(file, _("<Unrecognized flag bits set>"));

  fputc('\n', file);

  return TRUE;
}

/* Set avr32-specific linker options.  */
void bfd_elf32_avr32_set_options(struct bfd_link_info *info,
				 int direct_data_refs)
{
  struct elf_avr32_link_hash_table *htab;

  htab = avr32_elf_hash_table (info);
  htab->direct_data_refs = !!direct_data_refs;
}



/* Understanding core dumps */

static bfd_boolean
avr32_elf_grok_prstatus(bfd *abfd, Elf_Internal_Note *note);
static bfd_boolean
avr32_elf_grok_psinfo(bfd *abfd, Elf_Internal_Note *note);

static bfd_boolean
avr32_elf_grok_prstatus(bfd *abfd, Elf_Internal_Note *note)
{
  /* Linux/AVR32B elf_prstatus */
  if (note->descsz != 148)
    return FALSE;

  /* pr_cursig */
  elf_tdata(abfd)->core_signal = bfd_get_16(abfd, note->descdata + 12);

  /* pr_pid */
  elf_tdata(abfd)->core_pid = bfd_get_32(abfd, note->descdata + 24);

  /* Make a ".reg/999" section for pr_reg. The size is for 16
     general-purpose registers, SR and r12_orig (18 * 4 = 72).  */
  return _bfd_elfcore_make_pseudosection(abfd, ".reg", 72,
					 note->descpos + 72);
}

static bfd_boolean
avr32_elf_grok_psinfo(bfd *abfd, Elf_Internal_Note *note)
{
  /* Linux/AVR32B elf_prpsinfo */
  if (note->descsz != 128)
    return FALSE;

  elf_tdata(abfd)->core_program
    = _bfd_elfcore_strndup(abfd, note->descdata + 32, 16);
  elf_tdata(abfd)->core_command
    = _bfd_elfcore_strndup(abfd, note->descdata + 48, 80);

  /* Note that for some reason, a spurious space is tacked
     onto the end of the args in some (at least one anyway)
     implementations, so strip it off if it exists.  */

  {
    char *command = elf_tdata (abfd)->core_command;
    int n = strlen (command);

    if (0 < n && command[n - 1] == ' ')
      command[n - 1] = '\0';
  }

  return TRUE;
}


#define ELF_ARCH			bfd_arch_avr32
#define ELF_MACHINE_CODE		EM_AVR32
#define ELF_MACHINE_ALT1	        EM_AVR32_OLD
#define ELF_TARGET_ID			AVR32_ELF_DATA
#define ELF_MAXPAGESIZE			1024

#define TARGET_BIG_SYM			bfd_elf32_avr32_vec
#define TARGET_BIG_NAME			"elf32-avr32"

#define elf_backend_grok_prstatus	avr32_elf_grok_prstatus
#define elf_backend_grok_psinfo		avr32_elf_grok_psinfo

/* Only RELA relocations are used */
#define elf_backend_may_use_rel_p	0
#define elf_backend_may_use_rela_p	1
#define elf_backend_default_use_rela_p	1
#define elf_backend_rela_normal		1
#define elf_info_to_howto_rel		NULL
#define elf_info_to_howto		avr32_info_to_howto

#define bfd_elf32_bfd_copy_private_bfd_data	avr32_elf_copy_private_bfd_data
#define bfd_elf32_bfd_merge_private_bfd_data	avr32_elf_merge_private_bfd_data
#define bfd_elf32_bfd_set_private_flags		avr32_elf_set_private_flags
#define bfd_elf32_bfd_print_private_bfd_data	avr32_elf_print_private_bfd_data
#define bfd_elf32_new_section_hook		avr32_elf_new_section_hook

#define elf_backend_gc_mark_hook		avr32_elf_gc_mark_hook
#define elf_backend_gc_sweep_hook		avr32_elf_gc_sweep_hook
#define elf_backend_relocate_section	avr32_elf_relocate_section
#define elf_backend_copy_indirect_symbol avr32_elf_copy_indirect_symbol
#define elf_backend_create_dynamic_sections avr32_elf_create_dynamic_sections
#define bfd_elf32_bfd_link_hash_table_create avr32_elf_link_hash_table_create
#define elf_backend_adjust_dynamic_symbol avr32_elf_adjust_dynamic_symbol
#define elf_backend_size_dynamic_sections avr32_elf_size_dynamic_sections
#define elf_backend_finish_dynamic_symbol avr32_elf_finish_dynamic_symbol
#define elf_backend_finish_dynamic_sections avr32_elf_finish_dynamic_sections

#define bfd_elf32_bfd_relax_section	avr32_elf_relax_section

/* Find out which symbols need an entry in .got. */
#define elf_backend_check_relocs	avr32_check_relocs
#define elf_backend_can_refcount	1
#define elf_backend_can_gc_sections	1
#define elf_backend_plt_readonly	1
#define elf_backend_plt_not_loaded	1
#define elf_backend_want_plt_sym	0
#define elf_backend_plt_alignment	2
#define elf_backend_want_dynbss		0
#define elf_backend_want_got_plt	0
#define elf_backend_want_got_sym	1
#define elf_backend_got_header_size	AVR32_GOT_HEADER_SIZE

#include "elf32-target.h"
