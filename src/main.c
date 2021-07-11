
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <getopt.h>
#include <wchar.h>

#define LIBVMI_EXTRA_JSON
#include <libvmi/libvmi.h>
#include <libvmi/libvmi_extra.h>

#include <libvmi/peparse.h>
#include <libvmi/events.h>
#include <libvmi/libvmi_extra.h>
#include <json-c/json.h>
#include <json-c/json_util.h>

#include <glib.h> /* Hash table */
#include "gfx.h"  /* Graphics rendering */

#define DEBUG

#define LEN_WIN_LIST 0x100

// Window style
#define WS_MINIMIZE 0x20000000
#define WS_VISIBLE 0x10000000
#define WS_DISABLED 0x08000000

// Window extended style (exstyle)
#define WS_EX_DLGMODALFRAME 0x00000001
#define WS_EX_NOPARENTNOTIFY 0x00000004
#define WS_EX_TOPMOST 0x00000008
#define WS_EX_ACCEPTFILES 0x00000010
#define WS_EX_TRANSPARENT 0x00000020

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define TEXT_OFFSET 5

/*
 * The following structs encapsulate only the information needed for the purpose of reconstructing the
 * GUI to a level, where dialogs could be identified for clicking
 */
struct winsta_container
{
    addr_t addr;
    /*
     * For	each GUI thread, win32k	maps, the associated desktop heap into the user-­‐mode
     * http://mista.nu/research/mandt-win32k-slides.pdf
     *
     * Therefore do it like volatility: Find a process with matching sessionID and take its VA as _MM_SESSION_SPACE for the WinSta
     * https://github.com/volatilityfoundation/volatility/blob/a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/gui/sessions.py#L49
     *
     * To accomplish this, it's the most easy way to use vmi_read_xx_va
     */
    vmi_pid_t providing_pid;
    uint32_t session_id;
    addr_t atom_table;
    bool is_interactive;
    size_t len_desktops;
    addr_t* desktops;
};

struct rect_container
{
    uint32_t x0;
    uint32_t x1;
    uint32_t y0;
    uint32_t y1;
};

struct atom_entry
{
    uint16_t atom;
    uint16_t ref_count;
    addr_t hashlink;
    uint8_t name_len;
    wchar_t* name;
    //unicode_string_t* name;
};

struct wnd_container
{
    addr_t spwnd_addr;
    uint32_t style;
    uint32_t exstyle;
    int level;
    uint16_t atom;
    struct rect_container r;
    struct rect_container rclient;
    const char* text;
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

struct Offsets
{
    addr_t ps_active_process_head;

    /* For _EPROCESS */
    addr_t active_proc_links_offset;
    addr_t pid_offset;
    addr_t name_offset;
    addr_t thread_list_head_offset;

    /* For _ETRHEAD */
    addr_t thread_list_entry_offset;
    addr_t tcb_offset;

    /* For _KTHREAD */
    addr_t teb_offset;

    /* For TEB */
    addr_t teb_win32threadinfo_offset;
    addr_t w32t_deskinfo_offset;
    addr_t w32t_pwinsta_offset; //264

    // tagWINDOWSTATION https://github.com/volatilityfoundation/volatility/blob/a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/gui/vtypes/win7_sp1_x86_vtypes_gui.py#L1578
    addr_t winsta_session_id_offset;   // 0
    addr_t winsta_pglobal_atom_table_offset; //64;
    addr_t winsta_rpdesk_list_offset;
    addr_t winsta_wsf_flags; // = 16, dword to determin if interactive

    // _RTL_ATOM_TABLE
    addr_t atom_table_buckets_off;
    addr_t atom_table_num_buckets_off;

    //_RTL_ATOM_TABLE_ENTRY
    addr_t atom_entry_atom_offset;
    addr_t atom_entry_name_offset;
    addr_t atom_entry_name_len_offset;
    addr_t atom_entry_ref_count_offset;
    addr_t atom_entry_hashlink_offset;

    // tagDESKTOP https://github.com/volatilityfoundation/volatility/blob/a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/gui/vtypes/win7_sp1_x86_vtypes_gui.py#L1079
    addr_t desk_pdeskinfo_off;   // = 4;
    addr_t desk_rpdesk_next_off; // = 12;
    addr_t desk_pwinsta_parent;  // = 16;
    addr_t desk_desktopid_off;   //24

    // tagDESKTOPINFO
    addr_t deskinfo_spwnd_offset;

    // tagWND
    // https://www.geoffchappell.com/studies/windows/win32/user32/structs/wnd/index.htm?tx=56
    // https://github.com/volatilityfoundation/volatility/blob/a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/gui/constants.py#L43
    // https://github.com/volatilityfoundation/volatility/blob/a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/gui/win32k_core.py#L503
    addr_t rc_wnd_offset; /* tagRECT of window */
    addr_t rc_client_offset; /* tagRECT of clients within the window */
    addr_t spwnd_next;
    addr_t spwnd_child;
    addr_t wnd_style;          // 32
    addr_t wnd_exstyle;        // 28
    addr_t pcls_offset;        // CLS* pcls
    addr_t wnd_strname_offset; // offset to _LARGE_UNICODE_STRING

    addr_t large_unicode_buf_offset;

    // tagRECT
    addr_t rect_left_offset;
    addr_t rect_top_offset;
    addr_t rect_right_offset;
    addr_t rect_bottom_offset;

    // tagCLS
    // https://www.geoffchappell.com/studies/windows/win32/user32/structs/cls.htm?tx=56
    addr_t cls_atom_offset;
} off; /* All fields are initialized to zero */

int sort_wnd_container(gconstpointer a, gconstpointer b)
{
    int res = 0;
    res = ((struct wnd_container*)b)->level - ((struct wnd_container*)a)->level;
    return res;
}
status_t find_offsets_from_ntoskrnl_json(vmi_instance_t vmi, const char* kernel_json)
{
    /* 
     * Parse IST-file containing debugging information to retrieve offsets 
     * Might have just used `vmi_get_kernel_json(vmi);`, but using
     * the supplied IST-file is more explicit
     */
    json_object* profile =  json_object_from_file(kernel_json); 
        
    if(!profile)
    {
        fprintf(stderr, "Error win32k-JSON at %s\n", kernel_json);
        return VMI_FAILURE;
    }
    /* Find offsets within _EPROCESS */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
            vmi, profile, "_EPROCESS", "ActiveProcessLinks",
            &off.active_proc_links_offset))
    {
        printf("Error retrieving ActiveProcessLinks-offset : %ld\n",
            off.active_proc_links_offset);
        return VMI_FAILURE;
    }
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
            vmi, profile, "_EPROCESS", "UniqueProcessId",
            &off.pid_offset))
    {
        printf("Error retrieving UniqueProcessId-offset : %ld\n", off.pid_offset);
        return VMI_FAILURE;
    }
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
            vmi, profile, "_EPROCESS", "ImageFileName",
            &off.name_offset))
    {
        printf("Error retrieving ImageFileName-offset : %ld\n", off.name_offset);
        return VMI_FAILURE;
    }
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
            vmi, profile, "_EPROCESS", "ThreadListHead",
            &off.thread_list_head_offset))
    {
        printf("Error retrieving ThreadListHead-offset : %ld\n",
            off.thread_list_head_offset);
        return VMI_FAILURE;
    }
#ifdef DEBUG
    printf("Relevant _EPROCESS-offsets\n");
    printf("Offset for ActiveProcessLinks:\t%ld\n", off.active_proc_links_offset);
    printf("Offset for ImageFileName:\t%ld\n", off.name_offset);
    printf("Offset for UniqueProcessId:\t%ld\n", off.pid_offset);
    printf("Offset for ThreadListHead:\t%ld\n", off.thread_list_head_offset);
#endif

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
            vmi, profile, "_ETHREAD", "ThreadListEntry",
            &off.thread_list_entry_offset))
    {
        printf("Error retrieving ThreadListEntry-offset : %ld\n",
            off.thread_list_entry_offset);
        return VMI_FAILURE;
    }

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
            vmi, profile, "_ETHREAD", "Tcb", &off.tcb_offset))
    {
        printf("Error retrieving Tcb-offset : %ld\n", off.tcb_offset);
        return VMI_FAILURE;
    }
#ifdef DEBUG
    printf("\nRelevant _ETHREAD-offsets\n");
    printf("Offset for Tcb:\t%ld\n", off.tcb_offset);
    printf("Offset for ThreadListEntry:\t%ld\n", off.thread_list_entry_offset);
#endif
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
            vmi, profile, "_ETHREAD", "Teb", &off.teb_offset))
    {
        printf("Error retrieving TEB at offset %ld\n", off.tcb_offset);
        return VMI_FAILURE;
    }
#ifdef DEBUG
    printf("\nRelevant _KTHREAD-offsets\n");
    printf("Offset for Teb:\t%ld\n", off.teb_offset);
#endif

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
            vmi, profile, "_RTL_ATOM_TABLE", "Buckets",
            &off.atom_table_buckets_off))
    {
        printf("Error retrieving Buckets-offset of _RTL_ATOM_TABLE\n");
        return VMI_FAILURE;
    }


    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
            vmi, profile, "_RTL_ATOM_TABLE", "NumberOfBuckets",
            &off.atom_table_num_buckets_off))
    {
        printf("Error retrieving Number of Buckets of _RTL_ATOM_TABLE\n");
        return VMI_FAILURE;
    }
    /*
     * Kernel-PDB-file supplies *wrong* offset, its not 0x3c! buf either 0xC,
     * 0x18 or 0x58 (on patched versions) -- basically subtract 0x30
     *
     * This is a preprocessor thing as stated here:
     * https://code.google.com/archive/p/volatility/issues/131
     * https://github.com/volatilityfoundation/volatility/blob/\
     * a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/\
     * gui/win32k_core.py#L659
     */
    off.atom_table_num_buckets_off = 0xC;
    off.atom_table_buckets_off = 0x10;

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
            vmi, profile, "_RTL_ATOM_TABLE_ENTRY", "HashLink",
            &off.atom_entry_hashlink_offset))
    {
        printf("Error retrieving offset toHashLink of _RTL_ATOM_TABLE_ENTRY\n");
        return VMI_FAILURE;
    }

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
            vmi, profile, "_RTL_ATOM_TABLE_ENTRY", "Name",
            &off.atom_entry_name_offset))
    {
        printf("Error retrieving offset to Name of _RTL_ATOM_TABLE_ENTRY\n");
        return VMI_FAILURE;
    }

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
            vmi, profile, "_RTL_ATOM_TABLE_ENTRY", "NameLength",
            &off.atom_entry_name_len_offset))
    {
        printf("Error retrieving offset to NameLength of _RTL_ATOM_TABLE_ENTRY\n");
        return VMI_FAILURE;
    }

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
            vmi, profile, "_RTL_ATOM_TABLE_ENTRY", "Atom",
            &off.atom_entry_atom_offset))
    {
        printf("Error retrieving offset to Atom of _RTL_ATOM_TABLE_ENTRY\n");
        return VMI_FAILURE;
    }
#ifdef DEBUG
    printf("\nRelevant ATOM-offsets\n");
    printf("Offset for Buckets:\t%ld\n", off.atom_table_buckets_off);
    printf("Offset for NumBuckets:\t%ld\n", off.atom_table_num_buckets_off);
    printf("Offset for Atom in AtomEntry:\t%ld\n", off.atom_entry_atom_offset);
    printf("Offset for Hashlink in AtomEntry:\t%ld\n", off.atom_entry_hashlink_offset);
#endif

    return VMI_SUCCESS;
}

status_t find_offsets_from_win32k_json(vmi_instance_t vmi, const char* win32k_json)
{
    json_object *w32k_json = json_object_from_file(win32k_json);
    
    if(!w32k_json)
    {
        fprintf(stderr, "Error win32k-JSON at %s\n", win32k_json);
        return VMI_FAILURE;
    }

    /* Reads offset to Win32ThreadInfo-struct from beginning of _TEB */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "_TEB", "Win32ThreadInfo",
                           &off.teb_win32threadinfo_offset))
    {
        fprintf(stderr, "Error reading offset to Win32ThreadInfo from _TEB\n");
        return VMI_FAILURE;
    }

    /* 
     * Reads offset to pDeskInfo from beginning of tagTHREADINFO, which is a 
     * Win32ThreadInfo-struct retrieved in the previous call
     */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagTHREADINFO", "pDeskInfo",
                           &off.w32t_deskinfo_offset))
    {
        fprintf(stderr, "Error reading offset to pDeskInfo from tagTHREADINFO\n");
        return VMI_FAILURE;
    }

    /* Reads offset to pwinsta from beginning of tagTHREADINFO */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagTHREADINFO", "pwinsta",
                           &off.w32t_pwinsta_offset ))
    {
        fprintf(stderr, "Error reading offset to pDeskInfo from tagTHREADINFO\n");
        return VMI_FAILURE;
    }
   
    /* Reads offset to dwSessionId from beginning of tagWINDOWSTATION */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagWINDOWSTATION", "dwSessionId",
                           &off.winsta_session_id_offset))
    {
        fprintf(stderr, "Error reading offset to session ID from tagWINDOWSTATION\n");
        return VMI_FAILURE;
    }
    
    /* Reads offset to pGlobalAtomTable from beginning of tagWINDOWSTATION */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagWINDOWSTATION", "pGlobalAtomTable",
                           &off.winsta_pglobal_atom_table_offset))
    {
        fprintf(stderr, "Error reading offset to pGlobalAtomTable from tagWINDOWSTATION\n");
        return VMI_FAILURE;
    }

    /* Reads offset to rpdeskList from beginning of tagWINDOWSTATION */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagWINDOWSTATION", "rpdeskList",
                           &off.winsta_rpdesk_list_offset))
    {
        fprintf(stderr, "Error reading offset to rpdeskList from tagWINDOWSTATION\n");
        return VMI_FAILURE;
    }

    /* Reads offset to dwWSF_Flags from beginning of tagWINDOWSTATION */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagWINDOWSTATION", "dwWSF_Flags",
                           &off.winsta_wsf_flags))
    {
        fprintf(stderr, "Error reading offset to dwWSF_Flags from tagWINDOWSTATION\n");
        return VMI_FAILURE;
    }
#ifdef DEBUG
    printf("\nRelevant tagWINDOWSTATION-offsets\n");
    printf("Offset for dwSessionId:\t%ld\n", off.winsta_session_id_offset);
    printf("Offset for pGlobalAtomTable:\t%ld\n", off.winsta_pglobal_atom_table_offset);
    printf("Offset for rpdeskList:\t%ld\n", off.winsta_rpdesk_list_offset);
    printf("Offset for dwWSF_Flags:\t%ld\n", off.winsta_wsf_flags);
#endif
    /* Reads offset to pDeskInfo from beginning of tagDESKTOP */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagDESKTOP", "pDeskInfo",
                           &off.desk_pdeskinfo_off))
    {
        fprintf(stderr, "Error reading offset to pDeskInfo from tagDESKTOP\n");
        return VMI_FAILURE;
    }

    /* Reads offset to rpdeskNext from beginning of tagDESKTOP */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagDESKTOP", "rpdeskNext",
                           &off.desk_rpdesk_next_off))
    {
        fprintf(stderr, "Error reading offset to desk_rpdesk_next_off from tagDESKTOP\n");
        return VMI_FAILURE;
    }

    /* Reads offset to rpwinstaParent from beginning of tagDESKTOP */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagDESKTOP", "rpwinstaParent",
                           &off.desk_pwinsta_parent))
    {
        fprintf(stderr, "Error reading offset to rpwinstaParent from tagDESKTOP\n");
        return VMI_FAILURE;
    }

    /* Reads offset to rpdeskNext from beginning of tagDESKTOP */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagDESKTOP", "dwDesktopId",
                           &off.desk_desktopid_off))
    {
        fprintf(stderr, "Error reading offset to dwDesktopId from tagDESKTOP\n");
        return VMI_FAILURE;
    }

    /* Reads offset to spwnd from beginning of tagDESKTOPINFO */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagDESKTOPINFO", "spwnd",
                           &off.deskinfo_spwnd_offset))
    {
        fprintf(stderr, "Error reading offset to dwDesktopId from tagDESKTOP\n");
        return VMI_FAILURE;
    }
#ifdef DEBUG
    printf("\nRelevant tagDESKTOP-offsets\n");
    printf("Offset for pDeskInfo:\t%ld\n", off.desk_pdeskinfo_off);
    printf("Offset for rpdeskNext:\t%ld\n", off.desk_rpdesk_next_off);
    printf("Offset for rpwinstaParent:\t%ld\n", off.desk_pwinsta_parent);
    printf("Offset for spwnd:\t%ld\n", off.deskinfo_spwnd_offset);
#endif
    /* Reads offset to rcWindow from beginning of tagWND */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagWND", "rcWindow",
                           &off.rc_wnd_offset))
    {
        fprintf(stderr, "Error reading offset to rcWindow from tagWND\n");
        return VMI_FAILURE;
    }

    /* Reads offset to rcWindow from beginning of tagWND */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagWND", "rcWindow",
                           &off.rc_wnd_offset))
    {
        fprintf(stderr, "Error reading offset to rcWindow from tagWND\n");
        return VMI_FAILURE;
    }

    /* Reads offset to rcClient from beginning of tagWND */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagWND", "rcClient",
                           &off.rc_client_offset))
    {
        fprintf(stderr, "Error reading offset to rcClient from tagWND\n");
        return VMI_FAILURE;
    }

    /* Reads offset to spwndNext from beginning of tagWND */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagWND", "spwndNext",
                           &off.spwnd_next))
    {
        fprintf(stderr, "Error reading offset to spwndNext from tagWND\n");
        return VMI_FAILURE;
    }

    /* Reads offset to rcClient from beginning of tagWND */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagWND", "spwndChild",
                           &off.spwnd_child))
    {
        fprintf(stderr, "Error reading offset to spwndChild from tagWND\n");
        return VMI_FAILURE;
    }
    
    /* Reads offset to style from beginning of tagWND */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagWND", "style",
                           &off.wnd_style))
    {
        fprintf(stderr, "Error reading offset to style from tagWND\n");
        return VMI_FAILURE;
    }
    
    /* Reads offset to ExStyle from beginning of tagWND */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagWND", "ExStyle",
                           &off.wnd_exstyle))
    {
        fprintf(stderr, "Error reading offset to ExStyle from tagWND\n");
        return VMI_FAILURE;
    }
    
    /* Reads offset to pcls from beginning of tagWND */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagWND", "pcls",
                           &off.pcls_offset))
    {
        fprintf(stderr, "Error reading offset to pcls from tagWND\n");
        return VMI_FAILURE;
    }

    /* Reads offset to strName from beginning of tagWND */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagWND", "strName",
                           &off.wnd_strname_offset))
    {
        fprintf(stderr, "Error reading offset to strName from tagWND\n");
        return VMI_FAILURE;
    }

    /* Reads offset to Buffer from beginning of _LARGE_UNICODE_STRING */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "_LARGE_UNICODE_STRING", "Buffer",
                           &off.large_unicode_buf_offset))
    {
        fprintf(stderr, "Error reading offset to Buffer from _LARGE_UNICODE_STRING\n");
        return VMI_FAILURE;
    }
    
    /* Reads offset to left-field from beginning of tagRECT */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagRECT", "left",
                           &off.rect_left_offset))
    {
        fprintf(stderr, "Error reading offset to left-field from tagRECT\n");
        return VMI_FAILURE;
    }
    
    /* Reads offset to top-field from beginning of tagRECT */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagRECT", "top",
                           &off.rect_top_offset))
    {
        fprintf(stderr, "Error reading offset to top-field from tagRECT\n");
        return VMI_FAILURE;
    }
    
    /* Reads offset to right-field from beginning of tagRECT */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagRECT", "right",
                           &off.rect_right_offset))
    {
        fprintf(stderr, "Error reading offset to right-field from tagRECT\n");
        return VMI_FAILURE;
    }
    
    /* Reads offset to bottom-field from beginning of tagRECT */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagRECT", "bottom",
                           &off.rect_bottom_offset))
    {
        fprintf(stderr, "Error reading offset to bottom-field from tagRECT\n");
        return VMI_FAILURE;
    }
    
    /* 
     * Reads offset to atomClassName from beginning of tagCLS 
     *
     * This contains the key for the atom table 
     * See https://www.geoffchappell.com/studies/windows/win32/user32/structs/\
     * cls.htm?tx=56
     */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(
                           vmi, w32k_json, "tagCLS", "atomClassName",
                           &off.cls_atom_offset))
    {
        fprintf(stderr, "Error reading offset to atomClassName from tagCLS\n");
        return VMI_FAILURE;
    }
    
    return VMI_SUCCESS;
}
status_t find_offsets(vmi_instance_t vmi, const char* kernel_json, const char* win32k_json)
{

    if (VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsActiveProcessHead",
            &off.ps_active_process_head))
    {
        printf("Failed to find PsActiveProcessHead\n");
        return VMI_FAILURE;
    }

    if(VMI_FAILURE == find_offsets_from_ntoskrnl_json(vmi, kernel_json))
        return VMI_FAILURE;

    if(VMI_FAILURE == find_offsets_from_win32k_json(vmi, win32k_json))
        return VMI_FAILURE;

    return VMI_SUCCESS;
}

void print_as_hex(char* cp, size_t l)
{
    for (size_t i = 0; i < l; i++)
    {
        printf("\\x %02x", cp[i]);
    }
    printf("\n");
}

/*
 * Read a Windows wchar-string into a wchar_t*, since vmi_read_unicode_str_va
 * fails to parse _RTL_ATOM_ENTRY's name-string. Expansion is performed since
 * Windows' wchar is 2 bytes versus 4 bytes on 64bit-Linux
 */
wchar_t* read_wchar_str_pid(vmi_instance_t vmi, addr_t start, size_t len, vmi_pid_t pid)
{
    wchar_t* s = malloc(sizeof(wchar_t) * len);
    memset(s, 0, sizeof(wchar_t) * len);

    for (size_t i = 0; i < len; i++)
    {
        uint16_t c = 0;
        if (VMI_FAILURE == vmi_read_16_va(vmi, start + i * 2, pid, &c))
        {
            free(s);
            return NULL;
        }
            
        s[i] = (wchar_t)c;

        if(s[i] == L'\0')
            break;
    }
    return s;
}

wchar_t* read_wchar_str(vmi_instance_t vmi, addr_t start, size_t len)
{
    return read_wchar_str_pid(vmi, start, len, 0);
}

void draw_single_wnd_container(struct wnd_container* w)
{

    if ((w->style & WS_VISIBLE) &&
        !(w->style & WS_DISABLED) &&
        !(w->style & WS_MINIMIZE) &&
        !(w->exstyle & WS_EX_TRANSPARENT))
    {
        int width = w->r.x1 - w->r.x0;
        int height = w->r.y1 - w->r.y0;

        gfx_color(80 * w->level, 80 * w->level, 80 * w->level);
        gfx_fill_rect(w->r.x0, w->r.y0, width, height);

        gfx_color(0, 0, 0);
        gfx_rect(w->r.x0, w->r.y0, width, height);

        gfx_color(85 * w->level, 85 * w->level, 85 * w->level);
        gfx_fill_rect(w->rclient.x0, w->rclient.y0, w->rclient.x1 - w->rclient.x0, w->rclient.y1 - w->rclient.y0);

        gfx_color(0, 0, 0);
        gfx_rect(w->rclient.x0, w->rclient.y0, w->rclient.x1 - w->rclient.x0, w->rclient.y1 - w->rclient.y0);

        if (w->text)
        {
            if (width > 0)
                gfx_draw_str_multiline(w->r.x0 + TEXT_OFFSET, w->r.y0, w->text, strlen(w->text), width);
            else
                gfx_draw_str(w->r.x0 + TEXT_OFFSET, w->r.y0, w->text, strlen(w->text));
        }
    }
    gfx_flush();
}

status_t draw_single_window(vmi_instance_t vmi, addr_t win, vmi_pid_t pid)
{
    status_t ret = VMI_FAILURE;

    uint32_t x0 = 0;
    uint32_t x1 = 0;
    uint32_t y0 = 0;
    uint32_t y1 = 0;

    uint32_t rx0 = 0;
    uint32_t rx1 = 0;
    uint32_t ry0 = 0;
    uint32_t ry1 = 0;

    uint32_t style = 0;
    uint32_t exstyle = 0;

    ret = vmi_read_32_va(vmi, win + off.rc_wnd_offset + off.rect_left_offset, pid, (uint32_t*)&x0);
    ret = vmi_read_32_va(vmi, win + off.rc_wnd_offset + off.rect_right_offset, pid, (uint32_t*)&x1);
    ret = vmi_read_32_va(vmi, win + off.rc_wnd_offset + off.rect_top_offset, pid, (uint32_t*)&y0);
    ret = vmi_read_32_va(vmi, win + off.rc_wnd_offset + off.rect_bottom_offset, pid, (uint32_t*)&y1);

    /* Determine, if windows is visible */
    ret = vmi_read_32_va(vmi, win + off.wnd_style, pid, (uint32_t*)&style);

    /* Determine extended style attributes */
    ret = vmi_read_32_va(vmi, win + off.wnd_exstyle, pid, (uint32_t*)&exstyle);

    /* Retrieves atom value */
    addr_t pcls = 0;
    ret = vmi_read_addr_va(vmi, win + off.pcls_offset, pid, &pcls);
    uint16_t atom = 0;
    ret = vmi_read_16_va(vmi, pcls + off.cls_atom_offset, pid, &atom);

    if ((style & WS_VISIBLE) &&
        !(style & WS_DISABLED) &&
        !(style & WS_MINIMIZE) &&
        !(exstyle & WS_EX_TRANSPARENT))
    {
        printf("atom: %" PRIx16 "\n", atom);
        gfx_color(0, 250, 0);
        gfx_fill_rect(x0, y0, x1 - x0, y1 - y0);

        gfx_color(0, 0, 0);
        gfx_rect(x0, y0, x1 - x0, y1 - y0);

        ret = vmi_read_32_va(vmi, win + off.rc_client_offset + off.rect_left_offset, pid, (uint32_t*)&rx0);
        ret = vmi_read_32_va(vmi, win + off.rc_client_offset + off.rect_right_offset, pid, (uint32_t*)&rx1);
        ret = vmi_read_32_va(vmi, win + off.rc_client_offset + off.rect_top_offset, pid, (uint32_t*)&ry0);
        ret = vmi_read_32_va(vmi, win + off.rc_client_offset + off.rect_bottom_offset, pid, (uint32_t*)&ry1);

        gfx_color(180, 0, 0);
        //gfx_fill_rect(rx0, ry0, rx1-rx0, ry1-ry0);

        gfx_color(0, 0, 0);
        gfx_rect(rx0, ry0, rx1 - rx0, ry1 - ry0);

        addr_t str_name_off;

        /* Retrieves window name */
        if (VMI_FAILURE != vmi_read_addr_va(vmi, win + off.wnd_strname_offset + off.large_unicode_buf_offset, pid, &str_name_off))
        {
            /*
             * Length is always 0, therefore always read 255 chars
             * https://github.com/volatilityfoundation/volatility/blob/a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/gui/vtypes/win7_sp1_x86_vtypes_gui.py#L650
             */
            wchar_t* wn = read_wchar_str_pid(vmi, str_name_off, (size_t)255, pid);

            if (wn)
            {
                size_t l = wcslen(wn);
                char* wn_ascii = (char*)malloc(sizeof(char) * (l + 1));
                size_t c = wcstombs(wn_ascii, wn, l);

                printf("\t\t\tWindow Name: %s\n", wn_ascii);
                printf("\t\t\tDims: %d x %d \n", x1 - x0, y1 - y0);
                if (x1 - x0 > 0)
                    gfx_draw_str_multiline(x0, y0, wn_ascii, c, x1 - x0);
                else
                    gfx_draw_str(x0, y0, wn_ascii, c);
            }
        }
        gfx_flush();
    }
    return ret;
}

status_t draw_windows(vmi_instance_t vmi, int width, int height, GArray* windows, vmi_pid_t pid)
{
    /* Prepare drawing */
    gfx_open(1280, 720, "GUI Reconstruction");
    gfx_clear_color(255, 255, 255);
    gfx_clear();
    gfx_color(0, 0, 0);

    struct wnd_container* wnd = 0;

    for (size_t i = 0; i < windows->len; i++)
    {
        wnd = g_array_index(windows, struct wnd_container*, i);
        draw_single_wnd_container(wnd);
    }

    char c = '\0';
    while (1)
    {
        c = gfx_wait();
        if (c != '\0')
            break;
    }

    gfx_close();

    return VMI_SUCCESS;
}

GHashTable* copy_hashtable(GHashTable* src)
{
    GHashTable* new = g_hash_table_new(g_int64_hash, g_int64_equal);
    guint l = g_hash_table_size(src);

    gpointer* entries = g_hash_table_get_keys_as_array(src, &l);

    for (size_t i = 0; i < l; i++)
    {
        if (entries[i])
            g_hash_table_add(new, entries[i]);
    }
    g_free(entries);

    return new;
}

/* Determine, if windows is visible; important since invisible windows might have visible children */
bool is_wnd_visible(vmi_instance_t vmi, vmi_pid_t pid, addr_t wnd)
{
    uint32_t style = 0;

    if (VMI_FAILURE == vmi_read_32_va(vmi, wnd + off.wnd_style, pid, (uint32_t*)&style))
        return false;

    if (style & WS_VISIBLE)
        return true;

    return false;
}

struct wnd_container* construct_wnd_container(vmi_instance_t vmi, vmi_pid_t pid, addr_t win, int level)
{
    status_t ret = VMI_FAILURE;

    uint32_t x0 = 0;
    uint32_t x1 = 0;
    uint32_t y0 = 0;
    uint32_t y1 = 0;

    uint32_t rx0 = 0;
    uint32_t rx1 = 0;
    uint32_t ry0 = 0;
    uint32_t ry1 = 0;

    uint32_t style = 0;
    uint32_t exstyle = 0;

    ret = vmi_read_32_va(vmi, win + off.rc_wnd_offset + off.rect_left_offset, pid, (uint32_t*)&x0);
    ret = vmi_read_32_va(vmi, win + off.rc_wnd_offset + off.rect_right_offset, pid, (uint32_t*)&x1);
    ret = vmi_read_32_va(vmi, win + off.rc_wnd_offset + off.rect_top_offset, pid, (uint32_t*)&y0);
    ret = vmi_read_32_va(vmi, win + off.rc_wnd_offset + off.rect_bottom_offset, pid, (uint32_t*)&y1);

    /* Determine, if windows is visible */
    ret = vmi_read_32_va(vmi, win + off.wnd_style, pid, (uint32_t*)&style);

    /* Determine extended style attributes */
    ret = vmi_read_32_va(vmi, win + off.wnd_exstyle, pid, (uint32_t*)&exstyle);

    /* Retrieves atom value */
    addr_t pcls = 0;
    ret = vmi_read_addr_va(vmi, win + off.pcls_offset, pid, &pcls);
    uint16_t atom = 0;
    ret = vmi_read_16_va(vmi, pcls + off.cls_atom_offset, pid, &atom);

    ret = vmi_read_32_va(vmi, win + off.rc_client_offset + off.rect_left_offset, pid, (uint32_t*)&rx0);
    ret = vmi_read_32_va(vmi, win + off.rc_client_offset + off.rect_right_offset, pid, (uint32_t*)&rx1);
    ret = vmi_read_32_va(vmi, win + off.rc_client_offset + off.rect_top_offset, pid, (uint32_t*)&ry0);
    ret = vmi_read_32_va(vmi, win + off.rc_client_offset + off.rect_bottom_offset, pid, (uint32_t*)&ry1);

    addr_t str_name_off;
    char* wn_ascii = NULL;

    /* Retrieves window name */
    if (VMI_FAILURE != vmi_read_addr_va(vmi, win + off.wnd_strname_offset + off.large_unicode_buf_offset, pid, &str_name_off))
    {
        /*
         * Length is always 0, therefore always read 255 chars
         * https://github.com/volatilityfoundation/volatility/blob/a438e768194a\
         * 9e05eb4d9ee9338b881c0fa25937/volatility/plugins/gui/vtypes/win7_sp1_\
         * x86_vtypes_gui.py#L650
         */
        wchar_t* wn = read_wchar_str_pid(vmi, str_name_off, (size_t)255, pid);

        if (wn)
        {
            size_t l = wcslen(wn);
            wn_ascii = (char*)malloc(sizeof(char) * (l + 1));
            size_t c = wcstombs(wn_ascii, wn, l);
            wn_ascii[c] = '\0'; /* Terminate ascii result */
        }
    }

    if (ret == VMI_FAILURE)
        return NULL;

    /* Populate struct, if no failure occured */
    struct wnd_container* wc = (struct wnd_container*)malloc(sizeof(struct wnd_container));
    memset(wc, 0, sizeof(struct wnd_container));

    wc->r.x0 = x0;
    wc->r.x1 = x1;
    wc->r.y0 = y0;
    wc->r.y1 = y1;

    wc->rclient.x0 = x0;
    wc->rclient.x1 = x1;
    wc->rclient.y0 = y0;
    wc->rclient.y1 = y1;

    wc->style = style;
    wc->exstyle = exstyle;
    wc->spwnd_addr = win;
    wc->text = wn_ascii;
    wc->atom = atom;
    wc->level = level;

    return wc;
}

status_t traverse_windows_pid(vmi_instance_t vmi, addr_t* win,
    vmi_pid_t pid, GHashTable* seen_windows, GArray* result_windows, int level)
{
    addr_t* cur = malloc(sizeof(addr_t));
    *cur = *win;

    /* Needed for ordered traversal */
    GArray* wins = g_array_new(true, true, sizeof(addr_t*));

    while (*cur)
    {
        if (g_hash_table_contains(seen_windows, (gconstpointer)cur))
        {
            printf("Cycle after %d siblings\n", g_hash_table_size(seen_windows));
            break;
        }

        /* Keeps track of current window in order to detect cycles later */
        g_hash_table_add(seen_windows, (gpointer)cur);

        /* Stores current window for ordered traversal */
        g_array_append_val(wins, cur);

        /* Advances to next window */
        addr_t* next = malloc(sizeof(addr_t));

        if (VMI_FAILURE == vmi_read_addr_va(vmi, *cur + off.spwnd_next, pid, next))
            return VMI_FAILURE;

        cur = next;
    }

    size_t len = wins->len;

    /*
     * Traverses the windows in the reverse order.
     * This is important to ensure correct Z ordering, since the last window
     * in the linked list is the bottom one.
     */
    for (size_t i = 0; i < len; i++)
    {
        addr_t* val = g_array_index(wins, addr_t*, len - (i + 1));

#ifdef DEBUG
        printf("\t\tWindow at %" PRIx64 "\n", *val);
#endif

        if (!is_wnd_visible(vmi, pid, *val))
            continue;

        struct wnd_container* wc = construct_wnd_container(vmi, pid, *val, level);
        g_array_append_val(result_windows, wc);

        addr_t* child = malloc(sizeof(uint64_t));

        /* Reads the window's child */
        if (VMI_FAILURE == vmi_read_addr_va(vmi, *val + off.spwnd_child, pid, child))
            return VMI_FAILURE;

        if (*child)
        {
            /* Exits the loop, if a window was already processed before */
            if (g_hash_table_contains(seen_windows, (gconstpointer)child))
                break;
            /*
             * Recursive call to process the windows children, its siblings and
             * grandchildren and their respective siblings, grandgrandchildren
             * and so on.
             */
            traverse_windows_pid(vmi, child, pid, seen_windows, result_windows, level + 1);
        }
    }

    return VMI_SUCCESS;
}

GArray* retrieve_windows_from_desktop(vmi_instance_t vmi, addr_t desktop, vmi_pid_t pid)
{
    uint32_t desk_id = 0;

    addr_t addr = desktop + off.desk_desktopid_off;

    /* Reads desktop ID */
    if (VMI_FAILURE == vmi_read_32_va(vmi, addr, pid, &desk_id))
    {
        printf("\t\tFailed to read desktop ID at %" PRIx64 "\n", desktop + off.desk_desktopid_off);
        return NULL;
    }

    addr_t desktop_info;
    addr = desktop + off.desk_pdeskinfo_off;
    // Retrieves pointer desktop info struct
    if (VMI_FAILURE == vmi_read_addr_va(vmi, addr, pid, &desktop_info))
    {
        printf("\t\tFailed to read pointer to _DESKTOPINFO at %" PRIx64 "\n", desktop + off.desk_pdeskinfo_off);
        return NULL;
    }
#ifdef DEBUG
    printf("\t_DESKTOPINFO at: %" PRIx64 "\n", desktop_info);
#endif
    addr_t spwnd = 0;

    addr = desktop_info + off.deskinfo_spwnd_offset;

    /* Retrieves pointer to struct pointer window */
    if (VMI_FAILURE == vmi_read_addr_va(vmi, addr, pid, &spwnd))
    {
        printf("\t\tFailed to read pointer to _WINDOW at %" PRIx64 "\n", desktop_info + off.deskinfo_spwnd_offset);
        return NULL;
    }

    if (!spwnd)
    {
        printf("\t\tNo valid windows for _DESKTOPINFO %" PRIx64 "\n", desktop_info);
        return NULL;
    }
#ifdef DEBUG
    printf("\t\t_WINDOW at: %" PRIx64 "\n", spwnd);

    /* Iterates over all windows */
    printf("\tStarting to traverse windows, starting at %" PRIx64 "\n", spwnd);
#endif
    addr_t* root = malloc(sizeof(uint64_t));
    *root = spwnd;

    GArray* result_windows = g_array_new(true, true, sizeof(struct wnd_container*));
    GHashTable* seen_windows = g_hash_table_new(g_int64_hash, g_int64_equal);

    traverse_windows_pid(vmi, root, pid, seen_windows, result_windows, 0);
    g_hash_table_destroy(seen_windows);

    return result_windows;
}

/* Traverses this singly-linked list of desktops belonging to one WinSta */
status_t traverse_desktops(vmi_instance_t vmi, addr_t* desktops,
    size_t* max_len, addr_t list_head)
{
    addr_t cur = list_head;
    addr_t next = 0;
    size_t i = 0;

    while (cur)
    {
        if (i < *max_len - 1)
        {
            desktops[i] = cur;
            i++;
        }
        if (VMI_FAILURE == vmi_read_addr_va(vmi, cur + off.desk_rpdesk_next_off, 0, &next))
        {
            printf("Failed to read pointer to next desktop at %" PRIx64 "\n", cur + off.desk_rpdesk_next_off);
            *max_len = i;
            return VMI_FAILURE;
        }
#ifdef DEBUG
        printf("\tDesktop at %" PRIx64 "\n", cur);
#endif
        if (next == list_head)
            break;
        cur = next;
    }
    *max_len = i;

    return VMI_SUCCESS;
}

/* Reads relevant data from tagWINDOWSTATION-structs and the child tagDESKTOPs */
status_t populate_winsta(vmi_instance_t vmi, struct winsta_container* winsta, addr_t addr, vmi_pid_t providing_pid)
{
    winsta->addr = addr;

    /*
     * Do it like volatility: Find a process with matching sessionID and take is VA as _MM_SESSION_SPACE
     * https://github.com/volatilityfoundation/volatility/blob/a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/gui/sessions.py#L49
     */
    winsta->providing_pid = providing_pid;

    /* Reads pointer to global atom table */
    if (VMI_FAILURE == vmi_read_addr_va(vmi, addr + off.winsta_pglobal_atom_table_offset, 0, &winsta->atom_table))
    {
        printf("Failed to read pointer to atom table at %" PRIx64 "\n", addr + off.winsta_pglobal_atom_table_offset);
        return VMI_FAILURE;
    }

    if (VMI_FAILURE == vmi_read_32_va(vmi, addr + off.winsta_session_id_offset, 0, &winsta->session_id))
    {
        printf("Failed to read session ID at %" PRIx64 "\n", addr + off.winsta_session_id_offset);
        return VMI_FAILURE;
    }

    uint32_t wsf_flags = 0;

    if (VMI_FAILURE == vmi_read_32_va(vmi, addr + off.winsta_wsf_flags, 0, &wsf_flags))
    {
        printf("Failed to read wsfFlags at %" PRIx64 "\n", addr + off.winsta_wsf_flags);
        return VMI_FAILURE;
    }

    /* See https://github.com/volatilityfoundation/volatility/blob/a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/gui/win32k_core.py#L350 */
    winsta->is_interactive = !(wsf_flags & 4);

    addr_t desk = 0;

    if (VMI_FAILURE == vmi_read_addr_va(vmi, addr + off.winsta_rpdesk_list_offset, 0, &desk))
    {
        printf("Failed to read pointer to rpdesklist at %" PRIx64 "\n", addr + off.winsta_rpdesk_list_offset);
        return VMI_FAILURE;
    }

    size_t len = 0x10;
    winsta->desktops = (addr_t*)malloc(len * sizeof(addr_t));
    memset(winsta->desktops, 0, sizeof(addr_t) * len);

    if (VMI_FAILURE == traverse_desktops(vmi, winsta->desktops, &len, desk))
    {
        printf("Failed to traverse desktops of winsta at %" PRIx64 "\n", winsta->addr);
        winsta->len_desktops = len;
        return VMI_FAILURE;
    }
    winsta->len_desktops = len;

#ifdef DEBUG
    printf("\tAtom table at %" PRIx64 "\n", winsta->atom_table);
    printf("\tSession ID %" PRId32 "\n", winsta->session_id);
    printf("\tFound %ld desktops\n", winsta->len_desktops);
#endif

    return VMI_SUCCESS;
}

/* Iterates over process list an retrieves all tagWINDOWSTATIONS-structs */
status_t retrieve_winstas_from_procs(vmi_instance_t vmi, struct winsta_container** winsta_ptr, size_t* len)
{
    size_t max_len = 0x100;
    struct winsta_container winstas[max_len];

    addr_t cur_list_entry = off.ps_active_process_head;
    addr_t next_list_entry = 0;

    if (VMI_FAILURE == vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry))
    {
        printf("Failed to read next pointer at %" PRIx64 "\n", cur_list_entry);
        return VMI_FAILURE;
    }

    addr_t current_process = 0;
    vmi_pid_t pid;
    size_t winsta_count = 0;

    /* Walks the process list */
    while (1)
    {
        /* Calculate offset to the start of _EPROCESS-struct */
        current_process = cur_list_entry - off.active_proc_links_offset;

        /* NOTE: _EPROCESS.UniqueProcessId is a really VOID*, but is never > 32 bits,
         * so this is safe enough for x64 Windows for example purposes */
        vmi_read_32_va(vmi, current_process + off.pid_offset, 0, (uint32_t*)&pid);

        addr_t thrd_list_head = 0;

        /* Retrieves pointer of ThreadListHead-member == associated thread */
        if (VMI_FAILURE == vmi_read_addr_va(vmi, current_process + off.thread_list_head_offset, 0, &thrd_list_head))
        {
            printf("Failed to read ThreadListHead-pointer at %" PRIx64 "\n", current_process + off.thread_list_head_offset);
            return VMI_FAILURE;
        }

#ifdef DEBUG
        char* procname;
        procname = vmi_read_str_va(vmi, current_process + off.name_offset, 0);

        if (!procname)
        {
            printf("Failed to find procname\n");
            return VMI_FAILURE;
        }

        if (procname)
        {
            free(procname);
            procname = NULL;
        }
        /* Print out the process name */
        printf("[%5d] %s (struct addr:%" PRIx64 ")\n", pid, procname, current_process);

        printf("\tThreadListHead at: %" PRIx64 "\n", thrd_list_head);
#endif

        addr_t cur_thrd_list_entry = thrd_list_head;
        addr_t cur_ethread = 0;
        addr_t next_thread_entry = 0;

        /* Walks the list of threads belonging to one process */
        while (1)
        {
            /* Calculates offset to the start of the _ETHREAD-struct */
            cur_ethread = cur_thrd_list_entry - off.thread_list_entry_offset;

            /* _ETHREAD contains a  _KTHREAD structure (of size 0x200 for Win7) in the beginning */
            addr_t cur_kthread = cur_ethread;
            addr_t teb = 0;

            /* Retrieves pointer to TEB  */
            if (VMI_FAILURE == vmi_read_addr_va(vmi, cur_kthread + off.teb_offset, 0, &teb))
            {
                printf("Failed to read Teb-pointer at %" PRIx64 "\n", cur_kthread + off.teb_offset);
                return VMI_FAILURE;
            }

            addr_t w32thrd_info = 0;

            if (teb < 0x800000)
            {
                goto next_thrd;
            }

            // Retrieves pointer to Win32ThreadInfo-struct
            if (VMI_FAILURE == vmi_read_addr_va(vmi, teb + off.teb_win32threadinfo_offset, pid, &w32thrd_info)) // TODO read offset from json
            {
#ifdef DEBUG
                printf("\t\tTEB at %" PRIx64 "\n", teb);
                printf("\t\tFailed to read pointer to w32thrd_info at %" PRIx64 "\n", teb + 64);
#endif
                goto next_thrd;
            }

            /* Since not every thread has a THREADINFO-struct, skip thread in this case */
            if (!w32thrd_info)
            {
                goto next_thrd;
            }

#ifdef DEBUG
            addr_t desktop_info = 0;
            /* Retrieves pointer desktop info struct */
            if (VMI_FAILURE == vmi_read_addr_va(vmi, w32thrd_info + off.w32t_deskinfo_offset, pid, &desktop_info))
            {
                printf("\t\tFailed to read pointer to _DESKTOPINFO at %" PRIx64 "\n", w32thrd_info + off.w32t_deskinfo_offset);
                goto next_thrd;
            }
            printf("\t\tThread at %" PRIx64 "\n", cur_ethread);
            printf("\t\tWin32Thread at: %" PRIx64 "\n", w32thrd_info);
            printf("\t\t\t_DESKTOPINFO at: %" PRIx64 "\n", desktop_info);
#endif
            addr_t cur_pwinsta = 0;

            /* Retrieves pointer to winsta struct */
            if (VMI_FAILURE == vmi_read_addr_va(vmi, w32thrd_info + off.w32t_pwinsta_offset, pid, &cur_pwinsta))
            {
                printf("\t\tFailed to read pointer to tagWINDOWSTATION at %" PRIx64 "\n", w32thrd_info + off.w32t_pwinsta_offset);
                goto next_thrd;
            }

            if (cur_pwinsta && cur_pwinsta > 0x1000)
            {
                bool is_known = false;
                size_t i = 0;

                for (; i < max_len; i++)
                {
                    if (winstas[i].addr == 0)
                        break;
                    if (winstas[i].addr == cur_pwinsta)
                        is_known = true;
                }
                if (!is_known && i < max_len)
                {
                    struct winsta_container wc;
                    populate_winsta(vmi, &wc, cur_pwinsta, pid);
                    winstas[i] = wc;
                    winsta_count++;
                }
            }

next_thrd:
            /* Retrieves pointer of ThreadListHead-member == associated thread */
            if (VMI_FAILURE == vmi_read_addr_va(vmi, cur_thrd_list_entry, 0, &next_thread_entry))
            {
                printf("Failed to read ThreadListHead-pointer at %" PRIx64 "\n", current_process + off.thread_list_head_offset);
                return VMI_FAILURE;
            }

            /* All threads processed, exit loop */
            if (next_thread_entry == thrd_list_head)
            {
                break;
            }

            cur_thrd_list_entry = next_thread_entry;
        }

        cur_list_entry = next_list_entry;
        if (VMI_FAILURE == vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry))
        {
            printf("Failed to read next pointer in loop at %" PRIx64 "\n", cur_list_entry);
            return VMI_FAILURE;
        }

        /*
         * In Windows, the next pointer points to the head of list, this pointer
         * is actually the address of PsActiveProcessHead symbol, not the
         * address of an ActiveProcessLink in EPROCESS struct. It means in
         * Windows, we should stop the loop at the last element in the list
         */
        if (next_list_entry == off.ps_active_process_head)
        {
            break;
        }
    };

    *winsta_ptr = (struct winsta_container*)malloc(winsta_count * sizeof(struct winsta_container));
    memcpy(*winsta_ptr, winstas, winsta_count * sizeof(struct winsta_container));
    *len = winsta_count;

    return VMI_SUCCESS;
}

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

void clean_up(vmi_instance_t vmi)
{
    /* Resumes the vm */
    vmi_resume_vm(vmi);

    /* Cleanup any memory associated with the LibVMI instance */
    vmi_destroy(vmi);
}

status_t vmi_reconstruct_gui(uint64_t domid, const char* kernel_json, const char* win32k_json)
{
    vmi_instance_t vmi = {0};
    
    void* input = (void*)&domid;
    void* config = (void*)kernel_json;  

    /* Initializes the libvmi library */
    if (VMI_FAILURE == vmi_init_complete(
                           &vmi, input, VMI_INIT_DOMAINID, NULL,
                           VMI_CONFIG_JSON_PATH, config, NULL))
    {
        printf("Failed to init LibVMI library.\n");
        clean_up(vmi);
        return VMI_FAILURE;
    }

    /* Checks, that VM is house a Windows OS */
    os_t os = vmi_get_ostype(vmi);

    if (VMI_OS_WINDOWS != os)
    {
        fprintf(stderr, "Only Windows is supported!");
        clean_up(vmi);
        return VMI_FAILURE;
    }

    /* Pauses the vm for consistent memory access */
    if (vmi_pause_vm(vmi) != VMI_SUCCESS)
    {
        printf("Failed to pause VM\n");
        clean_up(vmi);
        return VMI_FAILURE;
    }

    /* Retrieves name of the VM */
    char* vm_name = vmi_get_name(vmi);
    printf("Reconstruction of GUI of VM %s\n", vm_name);
    free(vm_name);

    /* Retrieves offsets to relevent fields */
    if (VMI_FAILURE == find_offsets(vmi, kernel_json, win32k_json))
    {
        clean_up(vmi);
        return VMI_FAILURE;
    }

    size_t len = 0;
    struct winsta_container* winstas = NULL;

    /* Gathers windows stations with all desktops by iterating over all procs */
    if (VMI_FAILURE == retrieve_winstas_from_procs(vmi, &winstas, &len))
    {
        clean_up(vmi);
        return VMI_FAILURE;
    }

    printf("\nAddr     \tInteractive?\tSession\n");
    printf("-------------------------------------\n");
    for (size_t i = 0; i < len; i++)
    {
        printf("%" PRIx64 "\t", winstas[i].addr);
        if (winstas[i].is_interactive)
            printf("Interactive\t");
        else
            printf("Not interactive\t");

        printf("# %" PRId32 "\n", winstas[i].session_id);
    }
    printf("-------------------------------------\n\n");

    for (size_t i = 0; i < len; i++)
    {
        printf("[*] WinSta # %" PRId32 " at %" PRIx64 "\n", winstas[i].session_id, winstas[i].addr);

#ifdef DEBUG
        GHashTable* atom_table = build_atom_table(vmi, winstas[i].atom_table);
        print_atom_table(atom_table);
        g_hash_table_destroy(atom_table);
#endif
        for (size_t j = 0; j < winstas[i].len_desktops; j++)
        {

            printf("Retrieving windows for desktop %" PRIx64 "\n", winstas[i].desktops[j]);
            GArray* windows = retrieve_windows_from_desktop(vmi, winstas[i].desktops[j], winstas[i].providing_pid);
            draw_windows(vmi, 1024, 768, windows, winstas[i].providing_pid);
            g_array_free(windows, true);
        }
        printf("-------------------------------------\n\n");
    }

    // https://resources.infosecinstitute.com/topic/windows-gui-forensics-session-objects-window-stations-and-desktop/
    clean_up(vmi);
    return VMI_SUCCESS;
}

int main(int argc, char** argv)
{
    uint64_t domid = 0;
    const char* kernel_json = NULL;
    const char* win32k_json = NULL;

    if (argc < 2)
    {
        printf("Usage: %s\n", argv[0]);
        printf("\t -d/--domid <domain id>\n");
        printf("\t -j/--json <path to kernel's json profile>\n");
        exit(EXIT_FAILURE);
    }

    if (argc > 2)
    {
        const struct option long_opts[] =
        {
            {"domid", required_argument, NULL, 'd'},
            {"kernel", required_argument, NULL, 'k'},
            {"win32k", required_argument, NULL, 'w'},
            {NULL, 0, NULL, 0}
        };
        const char* opts = "n:d:k:w:";
        int c;
        int long_index = 0;

        while ((c = getopt_long(argc, argv, opts, long_opts, &long_index)) != -1)
            switch (c)
            {
                case 'd':
                    domid = strtoull(optarg, NULL, 0);
                    break;
                case 'k':
                    kernel_json = optarg;
                    break;
                case 'w':
                    win32k_json = optarg;
                    break;
                default:
                    printf("Unknown option\n");
                    exit(EXIT_FAILURE);
            }
    }

#ifdef DEBUG
    printf("CLI-Parameters\n");
    printf("\tDom ID: %ld\n", domid);
    printf("\tKernel-JSON: %s\n",kernel_json);
    printf("\tWin32k-JSON: %s\n",win32k_json);
#endif 

    status_t ret = vmi_reconstruct_gui(domid, kernel_json, win32k_json);

    if (ret == VMI_SUCCESS)
        exit(EXIT_SUCCESS);
    else
        exit(EXIT_FAILURE);
}
