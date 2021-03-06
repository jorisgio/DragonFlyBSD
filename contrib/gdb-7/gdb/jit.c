/* Handle JIT code generation in the inferior for GDB, the GNU Debugger.

   Copyright (C) 2009-2012 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "defs.h"

#include "jit.h"
#include "jit-reader.h"
#include "block.h"
#include "breakpoint.h"
#include "command.h"
#include "dictionary.h"
#include "frame-unwind.h"
#include "gdbcmd.h"
#include "gdbcore.h"
#include "inferior.h"
#include "observer.h"
#include "objfiles.h"
#include "regcache.h"
#include "symfile.h"
#include "symtab.h"
#include "target.h"
#include "gdb-dlfcn.h"
#include "gdb_stat.h"
#include "exceptions.h"

static const char *jit_reader_dir = NULL;

static const struct objfile_data *jit_objfile_data;

static const char *const jit_break_name = "__jit_debug_register_code";

static const char *const jit_descriptor_name = "__jit_debug_descriptor";

static const struct inferior_data *jit_inferior_data = NULL;

static void jit_inferior_init (struct gdbarch *gdbarch);

/* An unwinder is registered for every gdbarch.  This key is used to
   remember if the unwinder has been registered for a particular
   gdbarch.  */

static struct gdbarch_data *jit_gdbarch_data;

/* Non-zero if we want to see trace of jit level stuff.  */

static int jit_debug = 0;

static void
show_jit_debug (struct ui_file *file, int from_tty,
		struct cmd_list_element *c, const char *value)
{
  fprintf_filtered (file, _("JIT debugging is %s.\n"), value);
}

struct target_buffer
{
  CORE_ADDR base;
  ULONGEST size;
};

/* Openning the file is a no-op.  */

static void *
mem_bfd_iovec_open (struct bfd *abfd, void *open_closure)
{
  return open_closure;
}

/* Closing the file is just freeing the base/size pair on our side.  */

static int
mem_bfd_iovec_close (struct bfd *abfd, void *stream)
{
  xfree (stream);
  return 1;
}

/* For reading the file, we just need to pass through to target_read_memory and
   fix up the arguments and return values.  */

static file_ptr
mem_bfd_iovec_pread (struct bfd *abfd, void *stream, void *buf,
                     file_ptr nbytes, file_ptr offset)
{
  int err;
  struct target_buffer *buffer = (struct target_buffer *) stream;

  /* If this read will read all of the file, limit it to just the rest.  */
  if (offset + nbytes > buffer->size)
    nbytes = buffer->size - offset;

  /* If there are no more bytes left, we've reached EOF.  */
  if (nbytes == 0)
    return 0;

  err = target_read_memory (buffer->base + offset, (gdb_byte *) buf, nbytes);
  if (err)
    return -1;

  return nbytes;
}

/* For statting the file, we only support the st_size attribute.  */

static int
mem_bfd_iovec_stat (struct bfd *abfd, void *stream, struct stat *sb)
{
  struct target_buffer *buffer = (struct target_buffer*) stream;

  sb->st_size = buffer->size;
  return 0;
}

/* One reader that has been loaded successfully, and can potentially be used to
   parse debug info.  */

static struct jit_reader
{
  struct gdb_reader_funcs *functions;
  void *handle;
} *loaded_jit_reader = NULL;

typedef struct gdb_reader_funcs * (reader_init_fn_type) (void);
static const char *reader_init_fn_sym = "gdb_init_reader";

/* Try to load FILE_NAME as a JIT debug info reader.  */

static struct jit_reader *
jit_reader_load (const char *file_name)
{
  void *so;
  reader_init_fn_type *init_fn;
  struct jit_reader *new_reader = NULL;
  struct gdb_reader_funcs *funcs = NULL;
  struct cleanup *old_cleanups;

  if (jit_debug)
    fprintf_unfiltered (gdb_stdlog, _("Opening shared object %s.\n"),
                        file_name);
  so = gdb_dlopen (file_name);
  old_cleanups = make_cleanup_dlclose (so);

  init_fn = gdb_dlsym (so, reader_init_fn_sym);
  if (!init_fn)
    error (_("Could not locate initialization function: %s."),
          reader_init_fn_sym);

  if (gdb_dlsym (so, "plugin_is_GPL_compatible") == NULL)
    error (_("Reader not GPL compatible."));

  funcs = init_fn ();
  if (funcs->reader_version != GDB_READER_INTERFACE_VERSION)
    error (_("Reader version does not match GDB version."));

  new_reader = XZALLOC (struct jit_reader);
  new_reader->functions = funcs;
  new_reader->handle = so;

  discard_cleanups (old_cleanups);
  return new_reader;
}

/* Provides the jit-reader-load command.  */

static void
jit_reader_load_command (char *args, int from_tty)
{
  char *so_name;
  int len;
  struct cleanup *prev_cleanup;

  if (args == NULL)
    error (_("No reader name provided."));

  if (loaded_jit_reader != NULL)
    error (_("JIT reader already loaded.  Run jit-reader-unload first."));

  so_name = xstrprintf ("%s/%s", jit_reader_dir, args);
  prev_cleanup = make_cleanup (xfree, so_name);

  loaded_jit_reader = jit_reader_load (so_name);
  do_cleanups (prev_cleanup);
}

/* Provides the jit-reader-unload command.  */

static void
jit_reader_unload_command (char *args, int from_tty)
{
  if (!loaded_jit_reader)
    error (_("No JIT reader loaded."));

  loaded_jit_reader->functions->destroy (loaded_jit_reader->functions);

  gdb_dlclose (loaded_jit_reader->handle);
  xfree (loaded_jit_reader);
  loaded_jit_reader = NULL;
}

/* Open a BFD from the target's memory.  */

static struct bfd *
bfd_open_from_target_memory (CORE_ADDR addr, ULONGEST size, char *target)
{
  const char *filename = xstrdup ("<in-memory>");
  struct target_buffer *buffer = xmalloc (sizeof (struct target_buffer));

  buffer->base = addr;
  buffer->size = size;
  return bfd_openr_iovec (filename, target,
                          mem_bfd_iovec_open,
                          buffer,
                          mem_bfd_iovec_pread,
                          mem_bfd_iovec_close,
                          mem_bfd_iovec_stat);
}

/* Per-inferior structure recording the addresses in the inferior.  */

struct jit_inferior_data
{
  CORE_ADDR breakpoint_addr;  /* &__jit_debug_register_code()  */
  CORE_ADDR descriptor_addr;  /* &__jit_debug_descriptor  */
};

/* Remember OBJFILE has been created for struct jit_code_entry located
   at inferior address ENTRY.  */

static void
add_objfile_entry (struct objfile *objfile, CORE_ADDR entry)
{
  CORE_ADDR *entry_addr_ptr;

  entry_addr_ptr = xmalloc (sizeof (CORE_ADDR));
  *entry_addr_ptr = entry;
  set_objfile_data (objfile, jit_objfile_data, entry_addr_ptr);
}

/* Return jit_inferior_data for current inferior.  Allocate if not already
   present.  */

static struct jit_inferior_data *
get_jit_inferior_data (void)
{
  struct inferior *inf;
  struct jit_inferior_data *inf_data;

  inf = current_inferior ();
  inf_data = inferior_data (inf, jit_inferior_data);
  if (inf_data == NULL)
    {
      inf_data = XZALLOC (struct jit_inferior_data);
      set_inferior_data (inf, jit_inferior_data, inf_data);
    }

  return inf_data;
}

static void
jit_inferior_data_cleanup (struct inferior *inf, void *arg)
{
  xfree (arg);
}

/* Helper function for reading the global JIT descriptor from remote
   memory.  */

static void
jit_read_descriptor (struct gdbarch *gdbarch,
		     struct jit_descriptor *descriptor,
		     CORE_ADDR descriptor_addr)
{
  int err;
  struct type *ptr_type;
  int ptr_size;
  int desc_size;
  gdb_byte *desc_buf;
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);

  /* Figure out how big the descriptor is on the remote and how to read it.  */
  ptr_type = builtin_type (gdbarch)->builtin_data_ptr;
  ptr_size = TYPE_LENGTH (ptr_type);
  desc_size = 8 + 2 * ptr_size;  /* Two 32-bit ints and two pointers.  */
  desc_buf = alloca (desc_size);

  /* Read the descriptor.  */
  err = target_read_memory (descriptor_addr, desc_buf, desc_size);
  if (err)
    error (_("Unable to read JIT descriptor from remote memory!"));

  /* Fix the endianness to match the host.  */
  descriptor->version = extract_unsigned_integer (&desc_buf[0], 4, byte_order);
  descriptor->action_flag =
      extract_unsigned_integer (&desc_buf[4], 4, byte_order);
  descriptor->relevant_entry = extract_typed_address (&desc_buf[8], ptr_type);
  descriptor->first_entry =
      extract_typed_address (&desc_buf[8 + ptr_size], ptr_type);
}

/* Helper function for reading a JITed code entry from remote memory.  */

static void
jit_read_code_entry (struct gdbarch *gdbarch,
		     CORE_ADDR code_addr, struct jit_code_entry *code_entry)
{
  int err, off;
  struct type *ptr_type;
  int ptr_size;
  int entry_size;
  int align_bytes;
  gdb_byte *entry_buf;
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);

  /* Figure out how big the entry is on the remote and how to read it.  */
  ptr_type = builtin_type (gdbarch)->builtin_data_ptr;
  ptr_size = TYPE_LENGTH (ptr_type);
  entry_size = 3 * ptr_size + 8;  /* Three pointers and one 64-bit int.  */
  entry_buf = alloca (entry_size);

  /* Read the entry.  */
  err = target_read_memory (code_addr, entry_buf, entry_size);
  if (err)
    error (_("Unable to read JIT code entry from remote memory!"));

  /* Fix the endianness to match the host.  */
  ptr_type = builtin_type (gdbarch)->builtin_data_ptr;
  code_entry->next_entry = extract_typed_address (&entry_buf[0], ptr_type);
  code_entry->prev_entry =
      extract_typed_address (&entry_buf[ptr_size], ptr_type);
  code_entry->symfile_addr =
      extract_typed_address (&entry_buf[2 * ptr_size], ptr_type);

  align_bytes = gdbarch_long_long_align_bit (gdbarch) / 8;
  off = 3 * ptr_size;
  off = (off + (align_bytes - 1)) & ~(align_bytes - 1);

  code_entry->symfile_size =
      extract_unsigned_integer (&entry_buf[off], 8, byte_order);
}

/* Proxy object for building a block.  */

struct gdb_block
{
  /* gdb_blocks are linked into a tree structure.  Next points to the
     next node at the same depth as this block and parent to the
     parent gdb_block.  */
  struct gdb_block *next, *parent;

  /* Points to the "real" block that is being built out of this
     instance.  This block will be added to a blockvector, which will
     then be added to a symtab.  */
  struct block *real_block;

  /* The first and last code address corresponding to this block.  */
  CORE_ADDR begin, end;

  /* The name of this block (if any).  If this is non-NULL, the
     FUNCTION symbol symbol is set to this value.  */
  const char *name;
};

/* Proxy object for building a symtab.  */

struct gdb_symtab
{
  /* The list of blocks in this symtab.  These will eventually be
     converted to real blocks.  */
  struct gdb_block *blocks;

  /* The number of blocks inserted.  */
  int nblocks;

  /* A mapping between line numbers to PC.  */
  struct linetable *linetable;

  /* The source file for this symtab.  */
  const char *file_name;
  struct gdb_symtab *next;
};

/* Proxy object for building an object.  */

struct gdb_object
{
  struct gdb_symtab *symtabs;
};

/* The type of the `private' data passed around by the callback
   functions.  */

typedef CORE_ADDR jit_dbg_reader_data;

/* The reader calls into this function to read data off the targets
   address space.  */

static enum gdb_status
jit_target_read_impl (GDB_CORE_ADDR target_mem, void *gdb_buf, int len)
{
  int result = target_read_memory ((CORE_ADDR) target_mem, gdb_buf, len);
  if (result == 0)
    return GDB_SUCCESS;
  else
    return GDB_FAIL;
}

/* The reader calls into this function to create a new gdb_object
   which it can then pass around to the other callbacks.  Right now,
   all that is required is allocating the memory.  */

static struct gdb_object *
jit_object_open_impl (struct gdb_symbol_callbacks *cb)
{
  /* CB is not required right now, but sometime in the future we might
     need a handle to it, and we'd like to do that without breaking
     the ABI.  */
  return XZALLOC (struct gdb_object);
}

/* Readers call into this function to open a new gdb_symtab, which,
   again, is passed around to other callbacks.  */

static struct gdb_symtab *
jit_symtab_open_impl (struct gdb_symbol_callbacks *cb,
                      struct gdb_object *object,
                      const char *file_name)
{
  struct gdb_symtab *ret;

  /* CB stays unused.  See comment in jit_object_open_impl.  */

  ret = XZALLOC (struct gdb_symtab);
  ret->file_name = file_name ? xstrdup (file_name) : xstrdup ("");
  ret->next = object->symtabs;
  object->symtabs = ret;
  return ret;
}

/* Returns true if the block corresponding to old should be placed
   before the block corresponding to new in the final blockvector.  */

static int
compare_block (const struct gdb_block *const old,
               const struct gdb_block *const new)
{
  if (old == NULL)
    return 1;
  if (old->begin < new->begin)
    return 1;
  else if (old->begin == new->begin)
    {
      if (old->end > new->end)
        return 1;
      else
        return 0;
    }
  else
    return 0;
}

/* Called by readers to open a new gdb_block.  This function also
   inserts the new gdb_block in the correct place in the corresponding
   gdb_symtab.  */

static struct gdb_block *
jit_block_open_impl (struct gdb_symbol_callbacks *cb,
                     struct gdb_symtab *symtab, struct gdb_block *parent,
                     GDB_CORE_ADDR begin, GDB_CORE_ADDR end, const char *name)
{
  struct gdb_block *block = XZALLOC (struct gdb_block);

  block->next = symtab->blocks;
  block->begin = (CORE_ADDR) begin;
  block->end = (CORE_ADDR) end;
  block->name = name ? xstrdup (name) : NULL;
  block->parent = parent;

  /* Ensure that the blocks are inserted in the correct (reverse of
     the order expected by blockvector).  */
  if (compare_block (symtab->blocks, block))
    {
      symtab->blocks = block;
    }
  else
    {
      struct gdb_block *i = symtab->blocks;

      for (;; i = i->next)
        {
          /* Guaranteed to terminate, since compare_block (NULL, _)
             returns 1.  */
          if (compare_block (i->next, block))
            {
              block->next = i->next;
              i->next = block;
              break;
            }
        }
    }
  symtab->nblocks++;

  return block;
}

/* Readers call this to add a line mapping (from PC to line number) to
   a gdb_symtab.  */

static void
jit_symtab_line_mapping_add_impl (struct gdb_symbol_callbacks *cb,
                                  struct gdb_symtab *stab, int nlines,
                                  struct gdb_line_mapping *map)
{
  int i;

  if (nlines < 1)
    return;

  stab->linetable = xmalloc (sizeof (struct linetable)
                             + (nlines - 1) * sizeof (struct linetable_entry));
  stab->linetable->nitems = nlines;
  for (i = 0; i < nlines; i++)
    {
      stab->linetable->item[i].pc = (CORE_ADDR) map[i].pc;
      stab->linetable->item[i].line = map[i].line;
    }
}

/* Called by readers to close a gdb_symtab.  Does not need to do
   anything as of now.  */

static void
jit_symtab_close_impl (struct gdb_symbol_callbacks *cb,
                       struct gdb_symtab *stab)
{
  /* Right now nothing needs to be done here.  We may need to do some
     cleanup here in the future (again, without breaking the plugin
     ABI).  */
}

/* Transform STAB to a proper symtab, and add it it OBJFILE.  */

static void
finalize_symtab (struct gdb_symtab *stab, struct objfile *objfile)
{
  struct symtab *symtab;
  struct gdb_block *gdb_block_iter, *gdb_block_iter_tmp;
  struct block *block_iter;
  int actual_nblocks, i, blockvector_size;
  CORE_ADDR begin, end;

  actual_nblocks = FIRST_LOCAL_BLOCK + stab->nblocks;

  symtab = allocate_symtab (stab->file_name, objfile);
  /* JIT compilers compile in memory.  */
  symtab->dirname = NULL;

  /* Copy over the linetable entry if one was provided.  */
  if (stab->linetable)
    {
      int size = ((stab->linetable->nitems - 1)
                  * sizeof (struct linetable_entry)
                  + sizeof (struct linetable));
      LINETABLE (symtab) = obstack_alloc (&objfile->objfile_obstack, size);
      memcpy (LINETABLE (symtab), stab->linetable, size);
    }
  else
    {
      LINETABLE (symtab) = NULL;
    }

  blockvector_size = (sizeof (struct blockvector)
                      + (actual_nblocks - 1) * sizeof (struct block *));
  symtab->blockvector = obstack_alloc (&objfile->objfile_obstack,
                                       blockvector_size);

  /* (begin, end) will contain the PC range this entire blockvector
     spans.  */
  symtab->primary = 1;
  BLOCKVECTOR_MAP (symtab->blockvector) = NULL;
  begin = stab->blocks->begin;
  end = stab->blocks->end;
  BLOCKVECTOR_NBLOCKS (symtab->blockvector) = actual_nblocks;

  /* First run over all the gdb_block objects, creating a real block
     object for each.  Simultaneously, keep setting the real_block
     fields.  */
  for (i = (actual_nblocks - 1), gdb_block_iter = stab->blocks;
       i >= FIRST_LOCAL_BLOCK;
       i--, gdb_block_iter = gdb_block_iter->next)
    {
      struct block *new_block = allocate_block (&objfile->objfile_obstack);
      struct symbol *block_name = obstack_alloc (&objfile->objfile_obstack,
                                                 sizeof (struct symbol));

      BLOCK_DICT (new_block) = dict_create_linear (&objfile->objfile_obstack,
                                                   NULL);
      /* The address range.  */
      BLOCK_START (new_block) = (CORE_ADDR) gdb_block_iter->begin;
      BLOCK_END (new_block) = (CORE_ADDR) gdb_block_iter->end;

      /* The name.  */
      memset (block_name, 0, sizeof (struct symbol));
      SYMBOL_DOMAIN (block_name) = VAR_DOMAIN;
      SYMBOL_CLASS (block_name) = LOC_BLOCK;
      SYMBOL_SYMTAB (block_name) = symtab;
      SYMBOL_BLOCK_VALUE (block_name) = new_block;

      block_name->ginfo.name = obsavestring (gdb_block_iter->name,
                                             strlen (gdb_block_iter->name),
                                             &objfile->objfile_obstack);

      BLOCK_FUNCTION (new_block) = block_name;

      BLOCKVECTOR_BLOCK (symtab->blockvector, i) = new_block;
      if (begin > BLOCK_START (new_block))
        begin = BLOCK_START (new_block);
      if (end < BLOCK_END (new_block))
        end = BLOCK_END (new_block);

      gdb_block_iter->real_block = new_block;
    }

  /* Now add the special blocks.  */
  block_iter = NULL;
  for (i = 0; i < FIRST_LOCAL_BLOCK; i++)
    {
      struct block *new_block = allocate_block (&objfile->objfile_obstack);
      BLOCK_DICT (new_block) = dict_create_linear (&objfile->objfile_obstack,
                                                   NULL);
      BLOCK_SUPERBLOCK (new_block) = block_iter;
      block_iter = new_block;

      BLOCK_START (new_block) = (CORE_ADDR) begin;
      BLOCK_END (new_block) = (CORE_ADDR) end;

      BLOCKVECTOR_BLOCK (symtab->blockvector, i) = new_block;
    }

  /* Fill up the superblock fields for the real blocks, using the
     real_block fields populated earlier.  */
  for (gdb_block_iter = stab->blocks;
       gdb_block_iter;
       gdb_block_iter = gdb_block_iter->next)
    {
      if (gdb_block_iter->parent != NULL)
        BLOCK_SUPERBLOCK (gdb_block_iter->real_block) =
          gdb_block_iter->parent->real_block;
    }

  /* Free memory.  */
  gdb_block_iter = stab->blocks;

  for (gdb_block_iter = stab->blocks, gdb_block_iter_tmp = gdb_block_iter->next;
       gdb_block_iter;
       gdb_block_iter = gdb_block_iter_tmp)
    {
      xfree ((void *) gdb_block_iter->name);
      xfree (gdb_block_iter);
    }
  xfree (stab->linetable);
  xfree ((char *) stab->file_name);
  xfree (stab);
}

/* Called when closing a gdb_objfile.  Converts OBJ to a proper
   objfile.  */

static void
jit_object_close_impl (struct gdb_symbol_callbacks *cb,
                       struct gdb_object *obj)
{
  struct gdb_symtab *i, *j;
  struct objfile *objfile;
  jit_dbg_reader_data *priv_data;

  priv_data = cb->priv_data;

  objfile = allocate_objfile (NULL, 0);
  objfile->gdbarch = target_gdbarch;

  objfile->msymbols = obstack_alloc (&objfile->objfile_obstack,
                                     sizeof (struct minimal_symbol));
  memset (objfile->msymbols, 0, sizeof (struct minimal_symbol));

  xfree (objfile->name);
  objfile->name = xstrdup ("<< JIT compiled code >>");

  j = NULL;
  for (i = obj->symtabs; i; i = j)
    {
      j = i->next;
      finalize_symtab (i, objfile);
    }
  add_objfile_entry (objfile, *priv_data);
  xfree (obj);
}

/* Try to read CODE_ENTRY using the loaded jit reader (if any).
   ENTRY_ADDR is the address of the struct jit_code_entry in the
   inferior address space.  */

static int
jit_reader_try_read_symtab (struct jit_code_entry *code_entry,
                            CORE_ADDR entry_addr)
{
  void *gdb_mem;
  int status;
  struct jit_dbg_reader *i;
  jit_dbg_reader_data priv_data;
  struct gdb_reader_funcs *funcs;
  volatile struct gdb_exception e;
  struct gdb_symbol_callbacks callbacks =
    {
      jit_object_open_impl,
      jit_symtab_open_impl,
      jit_block_open_impl,
      jit_symtab_close_impl,
      jit_object_close_impl,

      jit_symtab_line_mapping_add_impl,
      jit_target_read_impl,

      &priv_data
    };

  priv_data = entry_addr;

  if (!loaded_jit_reader)
    return 0;

  gdb_mem = xmalloc (code_entry->symfile_size);

  status = 1;
  TRY_CATCH (e, RETURN_MASK_ALL)
    if (target_read_memory (code_entry->symfile_addr, gdb_mem,
                            code_entry->symfile_size))
      status = 0;
  if (e.reason < 0)
    status = 0;

  if (status)
    {
      funcs = loaded_jit_reader->functions;
      if (funcs->read (funcs, &callbacks, gdb_mem, code_entry->symfile_size)
          != GDB_SUCCESS)
        status = 0;
    }

  xfree (gdb_mem);
  if (jit_debug && status == 0)
    fprintf_unfiltered (gdb_stdlog,
                        "Could not read symtab using the loaded JIT reader.\n");
  return status;
}

/* Try to read CODE_ENTRY using BFD.  ENTRY_ADDR is the address of the
   struct jit_code_entry in the inferior address space.  */

static void
jit_bfd_try_read_symtab (struct jit_code_entry *code_entry,
                         CORE_ADDR entry_addr,
                         struct gdbarch *gdbarch)
{
  bfd *nbfd;
  struct section_addr_info *sai;
  struct bfd_section *sec;
  struct objfile *objfile;
  struct cleanup *old_cleanups;
  int i;
  const struct bfd_arch_info *b;

  if (jit_debug)
    fprintf_unfiltered (gdb_stdlog,
			"jit_register_code, symfile_addr = %s, "
			"symfile_size = %s\n",
			paddress (gdbarch, code_entry->symfile_addr),
			pulongest (code_entry->symfile_size));

  nbfd = bfd_open_from_target_memory (code_entry->symfile_addr,
                                      code_entry->symfile_size, gnutarget);
  if (nbfd == NULL)
    {
      puts_unfiltered (_("Error opening JITed symbol file, ignoring it.\n"));
      return;
    }

  /* Check the format.  NOTE: This initializes important data that GDB uses!
     We would segfault later without this line.  */
  if (!bfd_check_format (nbfd, bfd_object))
    {
      printf_unfiltered (_("\
JITed symbol file is not an object file, ignoring it.\n"));
      bfd_close (nbfd);
      return;
    }

  /* Check bfd arch.  */
  b = gdbarch_bfd_arch_info (gdbarch);
  if (b->compatible (b, bfd_get_arch_info (nbfd)) != b)
    warning (_("JITed object file architecture %s is not compatible "
               "with target architecture %s."), bfd_get_arch_info
             (nbfd)->printable_name, b->printable_name);

  /* Read the section address information out of the symbol file.  Since the
     file is generated by the JIT at runtime, it should all of the absolute
     addresses that we care about.  */
  sai = alloc_section_addr_info (bfd_count_sections (nbfd));
  old_cleanups = make_cleanup_free_section_addr_info (sai);
  i = 0;
  for (sec = nbfd->sections; sec != NULL; sec = sec->next)
    if ((bfd_get_section_flags (nbfd, sec) & (SEC_ALLOC|SEC_LOAD)) != 0)
      {
        /* We assume that these virtual addresses are absolute, and do not
           treat them as offsets.  */
        sai->other[i].addr = bfd_get_section_vma (nbfd, sec);
        sai->other[i].name = xstrdup (bfd_get_section_name (nbfd, sec));
        sai->other[i].sectindex = sec->index;
        ++i;
      }

  /* This call takes ownership of NBFD.  It does not take ownership of SAI.  */
  objfile = symbol_file_add_from_bfd (nbfd, 0, sai, OBJF_SHARED, NULL);

  do_cleanups (old_cleanups);
  add_objfile_entry (objfile, entry_addr);
}

/* This function registers code associated with a JIT code entry.  It uses the
   pointer and size pair in the entry to read the symbol file from the remote
   and then calls symbol_file_add_from_local_memory to add it as though it were
   a symbol file added by the user.  */

static void
jit_register_code (struct gdbarch *gdbarch,
                   CORE_ADDR entry_addr, struct jit_code_entry *code_entry)
{
  int i, success;
  const struct bfd_arch_info *b;
  struct jit_inferior_data *inf_data = get_jit_inferior_data ();

  if (jit_debug)
    fprintf_unfiltered (gdb_stdlog,
                        "jit_register_code, symfile_addr = %s, "
                        "symfile_size = %s\n",
                        paddress (gdbarch, code_entry->symfile_addr),
                        pulongest (code_entry->symfile_size));

  success = jit_reader_try_read_symtab (code_entry, entry_addr);

  if (!success)
    jit_bfd_try_read_symtab (code_entry, entry_addr, gdbarch);
}

/* This function unregisters JITed code and frees the corresponding
   objfile.  */

static void
jit_unregister_code (struct objfile *objfile)
{
  free_objfile (objfile);
}

/* Look up the objfile with this code entry address.  */

static struct objfile *
jit_find_objf_with_entry_addr (CORE_ADDR entry_addr)
{
  struct objfile *objf;
  CORE_ADDR *objf_entry_addr;

  ALL_OBJFILES (objf)
    {
      objf_entry_addr = (CORE_ADDR *) objfile_data (objf, jit_objfile_data);
      if (objf_entry_addr != NULL && *objf_entry_addr == entry_addr)
        return objf;
    }
  return NULL;
}

/* (Re-)Initialize the jit breakpoint if necessary.
   Return 0 on success.  */

static int
jit_breakpoint_re_set_internal (struct gdbarch *gdbarch,
				struct jit_inferior_data *inf_data)
{
  if (inf_data->breakpoint_addr == 0)
    {
      struct minimal_symbol *reg_symbol;

      /* Lookup the registration symbol.  If it is missing, then we assume
	 we are not attached to a JIT.  */
      reg_symbol = lookup_minimal_symbol (jit_break_name, NULL, NULL);
      if (reg_symbol == NULL)
	return 1;
      inf_data->breakpoint_addr = SYMBOL_VALUE_ADDRESS (reg_symbol);
      if (inf_data->breakpoint_addr == 0)
	return 2;

      /* If we have not read the jit descriptor yet (e.g. because the JITer
	 itself is in a shared library which just got loaded), do so now.  */
      if (inf_data->descriptor_addr == 0)
	jit_inferior_init (gdbarch);
    }
  else
    return 0;

  if (jit_debug)
    fprintf_unfiltered (gdb_stdlog,
			"jit_breakpoint_re_set_internal, "
			"breakpoint_addr = %s\n",
			paddress (gdbarch, inf_data->breakpoint_addr));

  /* Put a breakpoint in the registration symbol.  */
  create_jit_event_breakpoint (gdbarch, inf_data->breakpoint_addr);

  return 0;
}

/* The private data passed around in the frame unwind callback
   functions.  */

struct jit_unwind_private
{
  /* Cached register values.  See jit_frame_sniffer to see how this
     works.  */
  struct gdb_reg_value **registers;

  /* The frame being unwound.  */
  struct frame_info *this_frame;
};

/* Sets the value of a particular register in this frame.  */

static void
jit_unwind_reg_set_impl (struct gdb_unwind_callbacks *cb, int dwarf_regnum,
                         struct gdb_reg_value *value)
{
  struct jit_unwind_private *priv;
  int gdb_reg;

  priv = cb->priv_data;

  gdb_reg = gdbarch_dwarf2_reg_to_regnum (get_frame_arch (priv->this_frame),
                                          dwarf_regnum);
  if (gdb_reg == -1)
    {
      if (jit_debug)
        fprintf_unfiltered (gdb_stdlog,
                            _("Could not recognize DWARF regnum %d"),
                            dwarf_regnum);
      return;
    }

  gdb_assert (priv->registers);
  priv->registers[gdb_reg] = value;
}

static void
reg_value_free_impl (struct gdb_reg_value *value)
{
  xfree (value);
}

/* Get the value of register REGNUM in the previous frame.  */

static struct gdb_reg_value *
jit_unwind_reg_get_impl (struct gdb_unwind_callbacks *cb, int regnum)
{
  struct jit_unwind_private *priv;
  struct gdb_reg_value *value;
  int gdb_reg, size;
  struct gdbarch *frame_arch;

  priv = cb->priv_data;
  frame_arch = get_frame_arch (priv->this_frame);

  gdb_reg = gdbarch_dwarf2_reg_to_regnum (frame_arch, regnum);
  size = register_size (frame_arch, gdb_reg);
  value = xmalloc (sizeof (struct gdb_reg_value) + size - 1);
  value->defined = frame_register_read (priv->this_frame, gdb_reg,
                                        value->value);
  value->size = size;
  value->free = reg_value_free_impl;
  return value;
}

/* gdb_reg_value has a free function, which must be called on each
   saved register value.  */

static void
jit_dealloc_cache (struct frame_info *this_frame, void *cache)
{
  struct jit_unwind_private *priv_data = cache;
  struct gdbarch *frame_arch;
  int i;

  gdb_assert (priv_data->registers);
  frame_arch = get_frame_arch (priv_data->this_frame);

  for (i = 0; i < gdbarch_num_regs (frame_arch); i++)
    if (priv_data->registers[i] && priv_data->registers[i]->free)
      priv_data->registers[i]->free (priv_data->registers[i]);

  xfree (priv_data->registers);
  xfree (priv_data);
}

/* The frame sniffer for the pseudo unwinder.

   While this is nominally a frame sniffer, in the case where the JIT
   reader actually recognizes the frame, it does a lot more work -- it
   unwinds the frame and saves the corresponding register values in
   the cache.  jit_frame_prev_register simply returns the saved
   register values.  */

static int
jit_frame_sniffer (const struct frame_unwind *self,
                   struct frame_info *this_frame, void **cache)
{
  struct jit_inferior_data *inf_data;
  struct jit_unwind_private *priv_data;
  struct jit_dbg_reader *iter;
  struct gdb_unwind_callbacks callbacks;
  struct gdb_reader_funcs *funcs;

  inf_data = get_jit_inferior_data ();

  callbacks.reg_get = jit_unwind_reg_get_impl;
  callbacks.reg_set = jit_unwind_reg_set_impl;
  callbacks.target_read = jit_target_read_impl;

  if (loaded_jit_reader == NULL)
    return 0;

  funcs = loaded_jit_reader->functions;

  gdb_assert (!*cache);

  *cache = XZALLOC (struct jit_unwind_private);
  priv_data = *cache;
  priv_data->registers =
    XCALLOC (gdbarch_num_regs (get_frame_arch (this_frame)),
             struct gdb_reg_value *);
  priv_data->this_frame = this_frame;

  callbacks.priv_data = priv_data;

  /* Try to coax the provided unwinder to unwind the stack */
  if (funcs->unwind (funcs, &callbacks) == GDB_SUCCESS)
    {
      if (jit_debug)
        fprintf_unfiltered (gdb_stdlog, _("Successfully unwound frame using "
                                          "JIT reader.\n"));
      return 1;
    }
  if (jit_debug)
    fprintf_unfiltered (gdb_stdlog, _("Could not unwind frame using "
                                      "JIT reader.\n"));

  jit_dealloc_cache (this_frame, *cache);
  *cache = NULL;

  return 0;
}


/* The frame_id function for the pseudo unwinder.  Relays the call to
   the loaded plugin.  */

static void
jit_frame_this_id (struct frame_info *this_frame, void **cache,
                   struct frame_id *this_id)
{
  struct jit_unwind_private private;
  struct gdb_frame_id frame_id;
  struct gdb_reader_funcs *funcs;
  struct gdb_unwind_callbacks callbacks;

  private.registers = NULL;
  private.this_frame = this_frame;

  /* We don't expect the frame_id function to set any registers, so we
     set reg_set to NULL.  */
  callbacks.reg_get = jit_unwind_reg_get_impl;
  callbacks.reg_set = NULL;
  callbacks.target_read = jit_target_read_impl;
  callbacks.priv_data = &private;

  gdb_assert (loaded_jit_reader);
  funcs = loaded_jit_reader->functions;

  frame_id = funcs->get_frame_id (funcs, &callbacks);
  *this_id = frame_id_build (frame_id.stack_address, frame_id.code_address);
}

/* Pseudo unwinder function.  Reads the previously fetched value for
   the register from the cache.  */

static struct value *
jit_frame_prev_register (struct frame_info *this_frame, void **cache, int reg)
{
  struct jit_unwind_private *priv = *cache;
  struct gdb_reg_value *value;

  if (priv == NULL)
    return frame_unwind_got_optimized (this_frame, reg);

  gdb_assert (priv->registers);
  value = priv->registers[reg];
  if (value && value->defined)
    return frame_unwind_got_bytes (this_frame, reg, value->value);
  else
    return frame_unwind_got_optimized (this_frame, reg);
}

/* Relay everything back to the unwinder registered by the JIT debug
   info reader.*/

static const struct frame_unwind jit_frame_unwind =
{
  NORMAL_FRAME,
  default_frame_unwind_stop_reason,
  jit_frame_this_id,
  jit_frame_prev_register,
  NULL,
  jit_frame_sniffer,
  jit_dealloc_cache
};


/* This is the information that is stored at jit_gdbarch_data for each
   architecture.  */

struct jit_gdbarch_data_type
{
  /* Has the (pseudo) unwinder been prepended? */
  int unwinder_registered;
};

/* Check GDBARCH and prepend the pseudo JIT unwinder if needed.  */

static void
jit_prepend_unwinder (struct gdbarch *gdbarch)
{
  struct jit_gdbarch_data_type *data;

  data = gdbarch_data (gdbarch, jit_gdbarch_data);
  if (!data->unwinder_registered)
    {
      frame_unwind_prepend_unwinder (gdbarch, &jit_frame_unwind);
      data->unwinder_registered = 1;
    }
}

/* Register any already created translations.  */

static void
jit_inferior_init (struct gdbarch *gdbarch)
{
  struct jit_descriptor descriptor;
  struct jit_code_entry cur_entry;
  struct jit_inferior_data *inf_data;
  CORE_ADDR cur_entry_addr;

  if (jit_debug)
    fprintf_unfiltered (gdb_stdlog, "jit_inferior_init\n");

  jit_prepend_unwinder (gdbarch);

  inf_data = get_jit_inferior_data ();
  if (jit_breakpoint_re_set_internal (gdbarch, inf_data) != 0)
    return;

  if (inf_data->descriptor_addr == 0)
    {
      struct minimal_symbol *desc_symbol;

      /* Lookup the descriptor symbol and cache the addr.  If it is
	 missing, we assume we are not attached to a JIT and return early.  */
      desc_symbol = lookup_minimal_symbol (jit_descriptor_name, NULL, NULL);
      if (desc_symbol == NULL)
	return;

      inf_data->descriptor_addr = SYMBOL_VALUE_ADDRESS (desc_symbol);
      if (inf_data->descriptor_addr == 0)
	return;
    }

  if (jit_debug)
    fprintf_unfiltered (gdb_stdlog,
			"jit_inferior_init, descriptor_addr = %s\n",
			paddress (gdbarch, inf_data->descriptor_addr));

  /* Read the descriptor so we can check the version number and load
     any already JITed functions.  */
  jit_read_descriptor (gdbarch, &descriptor, inf_data->descriptor_addr);

  /* Check that the version number agrees with that we support.  */
  if (descriptor.version != 1)
    error (_("Unsupported JIT protocol version in descriptor!"));

  /* If we've attached to a running program, we need to check the descriptor
     to register any functions that were already generated.  */
  for (cur_entry_addr = descriptor.first_entry;
       cur_entry_addr != 0;
       cur_entry_addr = cur_entry.next_entry)
    {
      jit_read_code_entry (gdbarch, cur_entry_addr, &cur_entry);

      /* This hook may be called many times during setup, so make sure we don't
         add the same symbol file twice.  */
      if (jit_find_objf_with_entry_addr (cur_entry_addr) != NULL)
        continue;

      jit_register_code (gdbarch, cur_entry_addr, &cur_entry);
    }
}

/* Exported routine to call when an inferior has been created.  */

void
jit_inferior_created_hook (void)
{
  jit_inferior_init (target_gdbarch);
}

/* Exported routine to call to re-set the jit breakpoints,
   e.g. when a program is rerun.  */

void
jit_breakpoint_re_set (void)
{
  jit_breakpoint_re_set_internal (target_gdbarch,
				  get_jit_inferior_data ());
}

/* Reset inferior_data, so sybols will be looked up again, and jit_breakpoint
   will be reset.  */

static void
jit_reset_inferior_data_and_breakpoints (void)
{
  struct jit_inferior_data *inf_data;

  /* Force jit_inferior_init to re-lookup of jit symbol addresses.  */
  inf_data = get_jit_inferior_data ();
  inf_data->breakpoint_addr = 0;
  inf_data->descriptor_addr = 0;

  /* Remove any existing JIT breakpoint(s).  */
  remove_jit_event_breakpoints ();

  jit_inferior_init (target_gdbarch);
}

/* Wrapper to match the observer function pointer prototype.  */

static void
jit_inferior_created_observer (struct target_ops *objfile, int from_tty)
{
  jit_reset_inferior_data_and_breakpoints ();
}

/* This function cleans up any code entries left over when the
   inferior exits.  We get left over code when the inferior exits
   without unregistering its code, for example when it crashes.  */

static void
jit_inferior_exit_hook (struct inferior *inf)
{
  struct objfile *objf;
  struct objfile *temp;

  ALL_OBJFILES_SAFE (objf, temp)
    if (objfile_data (objf, jit_objfile_data) != NULL)
      jit_unregister_code (objf);
}

static void
jit_executable_changed_observer (void)
{
  jit_reset_inferior_data_and_breakpoints ();
}

void
jit_event_handler (struct gdbarch *gdbarch)
{
  struct jit_descriptor descriptor;
  struct jit_code_entry code_entry;
  CORE_ADDR entry_addr;
  struct objfile *objf;

  /* Read the descriptor from remote memory.  */
  jit_read_descriptor (gdbarch, &descriptor,
		       get_jit_inferior_data ()->descriptor_addr);
  entry_addr = descriptor.relevant_entry;

  /* Do the corresponding action.  */
  switch (descriptor.action_flag)
    {
    case JIT_NOACTION:
      break;
    case JIT_REGISTER:
      jit_read_code_entry (gdbarch, entry_addr, &code_entry);
      jit_register_code (gdbarch, entry_addr, &code_entry);
      break;
    case JIT_UNREGISTER:
      objf = jit_find_objf_with_entry_addr (entry_addr);
      if (objf == NULL)
	printf_unfiltered (_("Unable to find JITed code "
			     "entry at address: %s\n"),
			   paddress (gdbarch, entry_addr));
      else
        jit_unregister_code (objf);

      break;
    default:
      error (_("Unknown action_flag value in JIT descriptor!"));
      break;
    }
}

/* Called to free the data allocated to the jit_inferior_data slot.  */

static void
free_objfile_data (struct objfile *objfile, void *data)
{
  xfree (data);
}

/* Initialize the jit_gdbarch_data slot with an instance of struct
   jit_gdbarch_data_type */

static void *
jit_gdbarch_data_init (struct obstack *obstack)
{
  struct jit_gdbarch_data_type *data;

  data = obstack_alloc (obstack, sizeof (struct jit_gdbarch_data_type));
  data->unwinder_registered = 0;
  return data;
}

/* Provide a prototype to silence -Wmissing-prototypes.  */

extern void _initialize_jit (void);

void
_initialize_jit (void)
{
  jit_reader_dir = relocate_gdb_directory (JIT_READER_DIR,
                                           JIT_READER_DIR_RELOCATABLE);
  add_setshow_zinteger_cmd ("jit", class_maintenance, &jit_debug,
			    _("Set JIT debugging."),
			    _("Show JIT debugging."),
			    _("When non-zero, JIT debugging is enabled."),
			    NULL,
			    show_jit_debug,
			    &setdebuglist, &showdebuglist);

  observer_attach_inferior_created (jit_inferior_created_observer);
  observer_attach_inferior_exit (jit_inferior_exit_hook);
  observer_attach_executable_changed (jit_executable_changed_observer);
  jit_objfile_data =
    register_objfile_data_with_cleanup (NULL, free_objfile_data);
  jit_inferior_data =
    register_inferior_data_with_cleanup (jit_inferior_data_cleanup);
  jit_gdbarch_data = gdbarch_data_register_pre_init (jit_gdbarch_data_init);
  if (is_dl_available ())
    {
      add_com ("jit-reader-load", no_class, jit_reader_load_command, _("\
Load FILE as debug info reader and unwinder for JIT compiled code.\n\
Usage: jit-reader-load FILE\n\
Try to load file FILE as a debug info reader (and unwinder) for\n\
JIT compiled code.  The file is loaded from " JIT_READER_DIR ",\n\
relocated relative to the GDB executable if required."));
      add_com ("jit-reader-unload", no_class, jit_reader_unload_command, _("\
Unload the currently loaded JIT debug info reader.\n\
Usage: jit-reader-unload FILE\n\n\
Do \"help jit-reader-load\" for info on loading debug info readers."));
    }
}
