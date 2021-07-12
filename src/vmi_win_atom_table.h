#ifndef VMI_WIN_ATOM_TABLE_H
#define VMI_WIN_ATOM_TABLE_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <wchar.h>
#include <getopt.h>

#include <libvmi/libvmi.h>

/* Datastructures */
#include <glib.h>

#include "vmi_gui_utils.h"

struct atom_entry
{
    uint16_t atom;
    uint16_t ref_count;
    addr_t hashlink;
    uint8_t name_len;
    wchar_t* name;
};

/*
 * Default _RTL_ATOM_ENTRY-structs
 * See https://github.com/volatilityfoundation/volatility/blob/\
 * a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/gui/\
 * constants.py#L34
 */
struct atom_entry ae[] =
{
    {
        .atom = 0x8000,
        .name = L"PopupMenu",
        .name_len = 9,
        .hashlink = 0,
        .ref_count = 0,
    },
    {
        .atom = 0x8001,
        .name = L"Desktop",
        .name_len = 7,
        .hashlink = 0,
        .ref_count = 0,
    },
    {
        .atom = 0x8002,
        .name = L"Dialog",
        .name_len = 6,
        .hashlink = 0,
        .ref_count = 0,
    },
    {
        .atom = 0x8003,
        .name = L"WinSwitch",
        .name_len = 9,
        .hashlink = 0,
        .ref_count = 0,
    },
    {
        .atom = 0x8004,
        .name = L"IconTitle",
        .name_len = 9,
        .hashlink = 0,
        .ref_count = 0,
    },
    {
        .atom = 0x8006,
        .name = L"ToolTip",
        .name_len = 9,
        .hashlink = 0,
        .ref_count = 0,
    }
};

void print_atom_table(GHashTable* atom_table)
{
    GHashTableIter iter;

    g_hash_table_iter_init(&iter, atom_table);
    struct atom_entry* val;
    uint16_t key;

    while (g_hash_table_iter_next(&iter, (gpointer)&key, (gpointer)&val))
    {
        printf("Atom: %" PRIx16 " %ls\n", key, val->name);
    }
}

struct atom_entry* parse_atom_entry(vmi_instance_t vmi, addr_t atom_addr)
{
    struct atom_entry* entry = malloc(sizeof(struct atom_entry));
    memset(entry, 0, sizeof(struct atom_entry));

    if (VMI_FAILURE == vmi_read_addr_va(vmi, atom_addr + off.atom_entry_hashlink_offset, 0, &entry->hashlink))
    {
        printf("Error reading HashLink at %" PRIx64 "\n", atom_addr + off.atom_entry_hashlink_offset);
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_16_va(vmi, atom_addr + off.atom_entry_atom_offset, 0, (uint16_t*)&entry->atom))
    {
        printf("Error reading Atom at %" PRIx64 "\n", atom_addr + off.atom_entry_atom_offset);
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_16_va(vmi, atom_addr + off.atom_entry_ref_count_offset, 0, (uint16_t*)&entry->ref_count))
    {
        printf("Error reading ReferenceCount at %" PRIx64 "\n", atom_addr + off.atom_entry_ref_count_offset);
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_8_va(vmi, atom_addr + off.atom_entry_name_len_offset, 0, (uint8_t*)&entry->name_len))
    {
        printf("Error reading NameLength at %" PRIx64 "\n", atom_addr + off.atom_entry_name_len_offset);
        return NULL;
    }

    entry->name = read_wchar_str(vmi, atom_addr + off.atom_entry_name_offset, (size_t)entry->name_len);

    if (!entry->name)
    {
        printf("Error reading wchar-string Name at %" PRIx64 "\n", atom_addr + off.atom_entry_name_offset);
    }

    return entry;
}

void add_default_atoms(GHashTable* atom_table)
{
    for (int i = 0; i < ARRAY_SIZE(ae); i++)
        g_hash_table_insert(atom_table, GUINT_TO_POINTER(ae[i].atom), (gpointer)&ae[i]);
}

/* https://bsodtutorials.wordpress.com/2015/11/11/understanding-atom-tables/ */
GHashTable* build_atom_table(vmi_instance_t vmi, addr_t table_addr)
{
    uint32_t num_buckets = 0;

    if (VMI_FAILURE == vmi_read_32_va(vmi, table_addr + off.atom_table_num_buckets_off, 0, (uint32_t*)&num_buckets))
    {
        printf("Failed to read num buckets-value of _RTL_ATOM_TABLE at %" PRIx64 "\n", table_addr + off.atom_table_num_buckets_off);
        return NULL;
    }

    GHashTable* ht = g_hash_table_new(g_direct_hash, g_direct_equal);
    add_default_atoms(ht);

    size_t i = 0;
    addr_t cur = 0;
    struct atom_entry* a = NULL;

    /* Iterate the array of pointers to _RTL_ATOM_TABLE_ENTRY-structs at buckets */
    while (i < num_buckets)
    {
        if (VMI_FAILURE == vmi_read_addr_va(vmi, table_addr + off.atom_table_buckets_off + i * 4, 0, &cur))
        {
            printf("Failed to read pointer to buckets entry of _RTL_ATOM_TABLE at %" PRIx64 "\n", table_addr + off.atom_table_buckets_off + i * 4);
            g_hash_table_destroy(ht);
            return NULL;
        }
        i++;

        if (!cur)
            continue;

        a = parse_atom_entry(vmi, cur);

        if (a)
        {
            g_hash_table_insert(ht, GUINT_TO_POINTER(a->atom), (gpointer)a);
        }
        /* Traverses the linked list of each top level _RTL_ATOM_TABLE_ENTRY */
        while (a && a->hashlink)
        {
            cur = a->hashlink;
            a = parse_atom_entry(vmi, cur);

            if (a)
            {
                g_hash_table_insert(ht, GUINT_TO_POINTER(a->atom), (gpointer)a);
            }
        }
    }

    return ht;
}
#endif