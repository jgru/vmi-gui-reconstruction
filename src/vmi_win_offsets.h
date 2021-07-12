#ifndef VMI_WIN_OFFSETS_H
#define VMI_WIN_OFFSETS_H

#define LIBVMI_EXTRA_JSON
#include <libvmi/libvmi.h>
#include <libvmi/libvmi_extra.h>

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

status_t find_offsets_from_ntoskrnl_json(vmi_instance_t vmi, const char* kernel_json)
{
    /*
     * Parse IST-file containing debugging information to retrieve offsets
     * Might have just used `vmi_get_kernel_json(vmi);`, but using
     * the supplied IST-file is more explicit
     */
    json_object* profile =  json_object_from_file(kernel_json);

    if (!profile)
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
    json_object* w32k_json = json_object_from_file(win32k_json);

    if (!w32k_json)
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

    if (VMI_FAILURE == find_offsets_from_ntoskrnl_json(vmi, kernel_json))
        return VMI_FAILURE;

    if (VMI_FAILURE == find_offsets_from_win32k_json(vmi, win32k_json))
        return VMI_FAILURE;

    return VMI_SUCCESS;
}
#endif