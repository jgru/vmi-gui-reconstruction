
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

#include <glib.h>       /* Hash table */
#include "gfx.h"        /* Graphics rendering */

/* Offset to pDeskInfo member of Win32Thread-struct */
//#define W32T__pDeskInfo_OFFSET 0x40
//https://www.geoffchappell.com/studies/windows/km/win32k/structs/threadinfo/index.htm?tx=188

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

struct Offsets {
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
    addr_t winsta_session_id_offset; // 0
    addr_t p_global_atom_table_offset; //64;
    addr_t rpdesk_list_offset; 
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
    addr_t desk_pdeskinfo_off;// = 4;
    addr_t desk_rpdesk_next_off;// = 12; 
    addr_t desk_pwinsta_parent;// = 16; 
    addr_t desk_desktopid_off; //24
    // tagDESKTOPINFO 
    addr_t spwnd_offset; 
    
    // tagWND 
    // https://www.geoffchappell.com/studies/windows/win32/user32/structs/wnd/index.htm?tx=56
    // https://github.com/volatilityfoundation/volatility/blob/a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/gui/constants.py#L43
    // https://github.com/volatilityfoundation/volatility/blob/a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/gui/win32k_core.py#L503
    addr_t rc_wnd_offset; 
    addr_t rc_client_offset;
    addr_t spwnd_next; 
    addr_t spwnd_child; 
    addr_t wnd_style; // 32
    addr_t wnd_exstyle; // 28
    addr_t pcls_offset; // CLS* pcls

    // tagRECT 
    addr_t rect_left_offset;
    addr_t rect_top_offset;
    addr_t rect_right_offset;
    addr_t rect_bottom_offset; 

    // tagCLS
    // https://www.geoffchappell.com/studies/windows/win32/user32/structs/cls.htm?tx=56
    addr_t cls_atom_offset; 
} off; 

/* 
 * The following structs encapsulate only the information needed for the purpose of reconstructing the 
 * GUI to a level, where dialogs could be identified for clicking 
 */
struct winsta_container {
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

struct rect_container {
    uint32_t x0;
    uint32_t x1;
    uint32_t y0;
    uint32_t y1;
};

struct wnd_container {
    addr_t spwnd_addr; 
    bool is_visible; 
    struct rect_container r;
    const char* type; 
};

struct atom_entry{
    uint16_t atom; 
    uint16_t ref_count; 
    addr_t hashlink; 
    uint8_t name_len; 
    wchar_t* name; 
    //unicode_string_t* name;

};

status_t populate_offsets(vmi_instance_t vmi){ // const char *win32k_config,

    if (VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsActiveProcessHead", &off.ps_active_process_head))
    {
        printf("Failed to find PsActiveProcessHead\n");
        return VMI_FAILURE;
    }

    /* Parse IST-file containing debugging information to retrieve offsets */
    json_object *profile = vmi_get_kernel_json(vmi);

    /* Find offsets within _EPROCESS */
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_EPROCESS", "ActiveProcessLinks", &off.active_proc_links_offset))
    {
        printf("Error retrieving ActiveProcessLinks-offset : %ld\n", off.name_offset);
        return VMI_FAILURE;
    }
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_EPROCESS", "UniqueProcessId", &off.pid_offset))
    {
        printf("Error retrieving UniqueProcessId-offset : %ld\n", off.pid_offset);
        return VMI_FAILURE;
    }
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_EPROCESS", "ImageFileName", &off.name_offset))
    {
        printf("Error retrieving ImageFileName-offset : %ld\n", off.name_offset);
        return VMI_FAILURE;
    }
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_EPROCESS", "ThreadListHead", &off.thread_list_head_offset))
    {
        printf("Error retrieving ThreadListHead-offset : %ld\n", off.thread_list_head_offset);
        return VMI_FAILURE;
    }

    printf("Relevant _EPROCESS-offsets\n");
    printf("Offset for ActiveProcessLinks:\t%ld\n", off.active_proc_links_offset);
    printf("Offset for ImageFileName:\t%ld\n", off.name_offset);
    printf("Offset for UniqueProcessId:\t%ld\n", off.pid_offset);
    printf("Offset for ThreadListHead:\t%ld\n", off.thread_list_head_offset);

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_ETHREAD", "ThreadListEntry", &off.thread_list_entry_offset))
    {
        printf("Error retrieving ThreadListEntry-offset : %ld\n", off.thread_list_entry_offset);
        return VMI_FAILURE;
    }

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_ETHREAD", "Tcb", &off.tcb_offset))
    {
        printf("Error retrieving Tcb-offset : %ld\n", off.tcb_offset);
        return VMI_FAILURE;
    }

    printf("\nRelevant _ETHREAD-offsets\n");
    printf("Offset for Tcb:\t%ld\n", off.tcb_offset);
    printf("Offset for ThreadListEntry:\t%ld\n", off.thread_list_entry_offset);

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_ETHREAD", "Teb", &off.teb_offset))
    {
        printf("Error retrieving Teb at offset %ld\n", off.tcb_offset);
        return VMI_FAILURE;
    }

    printf("\nRelevant _KTHREAD-offsets\n");
    printf("Offset for Teb:\t%ld\n", off.teb_offset);
    
    
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_RTL_ATOM_TABLE", "Buckets", &off.atom_table_buckets_off))
    {
        printf("Error retrieving Buckets-offset of _RTL_ATOM_TABLE\n");
        return VMI_FAILURE;
    }
    off.atom_table_buckets_off = 0x10; 
    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_RTL_ATOM_TABLE", "NumberOfBuckets", &off.atom_table_num_buckets_off))
    {
        printf("Error retrieving Number of Buckets of _RTL_ATOM_TABLE\n");
        return VMI_FAILURE;
    }
    /* 
     * Kernel-PDB-file supplies *wrong* offset, its not 0x3c! buf either 0xC, 0x18 or 0x58 (on patched versions)
     * This is a preprocessor thing as stated here: 
     * https://code.google.com/archive/p/volatility/issues/131
     * https://github.com/volatilityfoundation/volatility/blob/a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/gui/win32k_core.py#L659
     */
    off.atom_table_num_buckets_off = 0xC; 

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_RTL_ATOM_TABLE_ENTRY", "HashLink", &off.atom_entry_hashlink_offset))
    {
        printf("Error retrieving offset toHashLink of _RTL_ATOM_TABLE_ENTRY\n");
        return VMI_FAILURE;
    }

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_RTL_ATOM_TABLE_ENTRY", "Name", &off.atom_entry_name_offset))
    {
        printf("Error retrieving offset to Name of _RTL_ATOM_TABLE_ENTRY\n");
        return VMI_FAILURE;
    }

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_RTL_ATOM_TABLE_ENTRY", "NameLength", &off.atom_entry_name_len_offset))
    {
        printf("Error retrieving offset to NameLength of _RTL_ATOM_TABLE_ENTRY\n");
        return VMI_FAILURE;
    }

    if (VMI_FAILURE == vmi_get_struct_member_offset_from_json(vmi, profile, "_RTL_ATOM_TABLE_ENTRY", "Atom", &off.atom_entry_atom_offset))
    {
        printf("Error retrieving offset to Atom of _RTL_ATOM_TABLE_ENTRY\n");
        return VMI_FAILURE;
    }

    printf("\nRelevant ATOM-offsets\n");
    printf("Offset for Buckets:\t%ld\n", off.atom_table_buckets_off);
    printf("Offset for NumBuckets:\t%ld\n", off.atom_table_num_buckets_off);
    printf("Offset for Atom in AtomEntry:\t%ld\n", off.atom_entry_atom_offset);
    printf("Offset for Hashlink in AtomEntry:\t%ld\n", off.atom_entry_hashlink_offset);

    /* TODO read from pdb-JSON */
    off.teb_win32threadinfo_offset = 0x40; 
    
    // THREADINFO content
    off.w32t_pwinsta_offset = 264;  // https://github.com/volatilityfoundation/volatility/blob/a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/gui/vtypes/win7_sp1_x86_vtypes_gui.py#L199
    off.w32t_deskinfo_offset = 204; 
    
    // WinSta content
    off.winsta_session_id_offset = 0; 
    off.p_global_atom_table_offset = 64; // https://github.com/volatilityfoundation/volatility/blob/a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/gui/vtypes/win7_sp1_x86_vtypes_gui.py#L1583
    off.rpdesk_list_offset = 8; 
    off.winsta_wsf_flags = 16, 

    // tagDesktop
    off.desk_pdeskinfo_off = 4;
    off.desk_rpdesk_next_off = 12; 
    off.desk_pwinsta_parent = 16; 
    off.desk_desktopid_off = 24; 

    // DESKTOPINFO content
    off.spwnd_offset = 0x8; 
    
    // tagWINDOW content
    off.rc_wnd_offset = 64; 
    off.rc_client_offset = 80; 
    off.spwnd_next = 44;
    off.spwnd_child = 56;
    // https://www.geoffchappell.com/studies/windows/win32/user32/structs/wnd/style.htm
    off.wnd_style = 32; 
    off.wnd_exstyle = 28;
    off.pcls_offset = 100;
    
    // _RECT content
    off.rect_left_offset = 0;
    off.rect_top_offset = 4;
    off.rect_right_offset = 8;
    off.rect_bottom_offset = 12; 

    // https://www.geoffchappell.com/studies/windows/win32/user32/structs/cls.htm?tx=56
    off.cls_atom_offset = 8;
    
    return VMI_SUCCESS; 
}

void print_as_hex(char* cp, size_t l){
    for (size_t i=0; i < l; i++)
    {
        printf("\\x %02x", cp[i]);
    }
    printf("\n");
}

/* 
 * Read a Windows wchar-string into a wchar_t*, since vmi_read_unicode_str_va fails to parse 
 * _RTL_ATOM_ENTRY's name-string. Expansion is performed since Windows' wchar is 2 bytes 
 * versus 4 bytes on Linux
 */
wchar_t* read_wchar_str(vmi_instance_t vmi, addr_t start, size_t len){
    wchar_t* s = malloc(sizeof(wchar_t) * len); 
    memset(s, 0, len);

    for (size_t i = 0; i < len; i++)
    {   
        uint16_t c = 0;
        if (VMI_FAILURE == vmi_read_16_va(vmi, start + i*2, 0, &c))
        {
            printf("Error reading wchar at %" PRIx64 "\n", start + i*2);
            free(s);
            return NULL;
        }
        s[i] = (wchar_t) c; 
    } 
    return s; 
}

status_t draw_single_window(vmi_instance_t vmi, addr_t win, vmi_pid_t pid){
    status_t ret = VMI_FAILURE;
    uint32_t x0 = 0;
    uint32_t x1 = 0;
    uint32_t y0 = 0;
    uint32_t y1 = 0;
    uint32_t style = 0; 
    uint32_t exstyle = 0;

    ret = vmi_read_32_va(vmi, win + off.rc_wnd_offset + off.rect_left_offset, pid, (uint32_t *)&x0);
    ret = vmi_read_32_va(vmi, win + off.rc_wnd_offset + off.rect_right_offset, pid, (uint32_t *)&x1);
    ret = vmi_read_32_va(vmi, win + off.rc_wnd_offset + off.rect_top_offset, pid, (uint32_t *)&y0);
    ret = vmi_read_32_va(vmi, win + off.rc_wnd_offset + off.rect_bottom_offset, pid, (uint32_t *)&y1);
    
    /* Determine, if windows is visible */
    ret = vmi_read_32_va(vmi, win + off.wnd_style, pid, (uint32_t *)&style);

    /* Determine extended style attributes */
    ret = vmi_read_32_va(vmi, win + off.wnd_exstyle, pid, (uint32_t *)&exstyle);

    if((style & WS_VISIBLE) && 
       !(style &WS_DISABLED) &&
       !(style & WS_MINIMIZE) && 
       !(exstyle & WS_EX_TRANSPARENT)
    ){  

        gfx_color(220, 220, 220);
        //gfx_fill_rect(x0, y0, x1-x0, y1-y0);
        
        gfx_color(0, 0, 0);
        gfx_rect(x0, y0, x1-x0, y1-y0);
 
        ret = vmi_read_32_va(vmi, win + off.rc_client_offset + off.rect_left_offset, pid, (uint32_t *)&x0);
        ret = vmi_read_32_va(vmi, win + off.rc_client_offset + off.rect_right_offset, pid, (uint32_t *)&x1);
        ret = vmi_read_32_va(vmi, win + off.rc_client_offset + off.rect_top_offset, pid, (uint32_t *)&y0);
        ret = vmi_read_32_va(vmi, win + off.rc_client_offset + off.rect_bottom_offset, pid, (uint32_t *)&y1);

        gfx_color(220, 220, 220);
        //gfx_fill_rect(x0, y0, x1-x0, y1-y0);
        gfx_color(0, 0, 0);
        gfx_rect(x0, y0, x1-x0, y1-y0);
        gfx_flush();
    }
    return ret;
}


status_t draw_windows(vmi_instance_t vmi,int width, int height, GArray* windows, vmi_pid_t pid)
{

    /* Prepare drawing */
    gfx_open(1280, 720,"GUI Reconstruction");
    gfx_clear_color(255, 255, 255);
    gfx_clear();
    gfx_color(0, 0, 0);

    addr_t wnd_addr = 0; 
    printf("Size of list: %d\n", windows->len); 
    for(size_t i=0; i<windows->len; i++)
    {   
        wnd_addr = g_array_index(windows, addr_t, i);
        printf("WND Addr %"PRIx64"\n", wnd_addr);
        draw_single_window(vmi, wnd_addr, pid);
    } 
   
    char c = 'a'; 

    while(1){
        c = gfx_wait();
        if(c =='q')
            break; 
    }

    gfx_close();
    
    return VMI_SUCCESS;
}
status_t print_window_pid(vmi_instance_t vmi, addr_t win, vmi_pid_t pid){
    status_t ret = VMI_FAILURE;
    unicode_string_t* wnd_name; 

    uint32_t x0 = 0;
    uint32_t x1 = 0;
    uint32_t y0 = 0;
    uint32_t y1 = 0;

    uint32_t style = 0; 
    uint32_t exstyle = 0;
    
    ret = vmi_read_32_va(vmi, win + off.rc_wnd_offset + off.rect_left_offset, pid, (uint32_t *)&x0);
    ret = vmi_read_32_va(vmi, win + off.rc_wnd_offset + off.rect_right_offset, pid, (uint32_t *)&x1);
    ret = vmi_read_32_va(vmi, win + off.rc_wnd_offset + off.rect_top_offset, pid, (uint32_t *)&y0);
    ret = vmi_read_32_va(vmi, win + off.rc_wnd_offset + off.rect_bottom_offset, pid, (uint32_t *)&y1);
    
    /* Determine, if windows is visible */
    ret = vmi_read_32_va(vmi, win + off.wnd_style, pid, (uint32_t *)&style);
    /* Determine extended style attributes */
    ret = vmi_read_32_va(vmi, win + off.wnd_exstyle, pid, (uint32_t *)&exstyle);

    if((style & WS_VISIBLE) && 
       !(style &WS_DISABLED) && 
       !(style & WS_MINIMIZE) && 
       !(exstyle & WS_EX_TRANSPARENT)
    ){
        printf("\t\tSize: %d x %d\n", x1 - x0, y1 - y0);
        printf("\t\t\tVisibilty: %"  PRIx32"\n", style); 
        printf("\t\t\t_WINDOW.x0: %" PRIx32 "\n", x0);
        printf("\t\t\t_WINDOW.x1: %" PRIx32 "\n", x1);
        printf("\t\t\t_WINDOW.y0: %" PRIx32 "\n", y0);
        printf("\t\t\t_WINDOW.y1: %" PRIx32 "\n", y1);

        addr_t str_name_off = 0;
        uint32_t len = 0;  
        // https://github.com/volatilityfoundation/volatility/blob/a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/gui/vtypes/win7_sp1_x86_vtypes_gui.py#L981
        if(VMI_FAILURE != vmi_read_addr_va(vmi, win + 132 + 8, pid, &str_name_off)){
            printf("\t\t\tRead strNameOff\n");
            vmi_read_32_va(vmi, win + off.wnd_style, win + 132 , (uint32_t *)&len);
            printf("\t\t\tLength: %d\n", len);
            // Lenght always 0 ...Fix or delete
            // https://github.com/volatilityfoundation/volatility/blob/a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/gui/vtypes/win7_sp1_x86_vtypes_gui.py#L650
            wnd_name = vmi_read_unicode_str_va(vmi, str_name_off, pid);

            if (wnd_name)
            {
                printf("\t\t\tWindow name (length: %ld): ", wnd_name->length);
                print_as_hex((char*)wnd_name->contents, wnd_name->length); 
                free(wnd_name);
            }
            //printf("Window Name: %s\n", wnd_name->contents); 
        }
    }
    return ret; 
}

status_t traverse_windows_pid(vmi_instance_t vmi, addr_t *win,
                              vmi_pid_t pid, GHashTable *seen_windows, GArray *result_windows)
{
    addr_t* cur = malloc(sizeof(addr_t));
    *cur = *win; 

    while(*cur){
        /* Stores window as result*/
        g_array_append_val(result_windows, *cur);

        print_window_pid(vmi, *cur, pid); 
    
        if(g_hash_table_lookup(seen_windows, (gpointer) cur) != NULL){
            printf("Cycle after %d siblings\n", g_hash_table_size(seen_windows));
            break; 
        } 
        
        /* Keeps track of current window to detect cycles later */
        g_hash_table_insert(seen_windows, (gpointer)cur, (gpointer)cur);

        addr_t next = 0;
        if(VMI_FAILURE == vmi_read_addr_va(vmi, *cur + off.spwnd_next, pid, &next))
            return VMI_FAILURE;
        
        cur = (addr_t*) malloc(sizeof(addr_t));
        *cur = next; 
    }

    GHashTableIter iter;

    g_hash_table_iter_init(&iter, seen_windows);
    addr_t *val;
    addr_t *key_;

    while (g_hash_table_iter_next (&iter, (gpointer) &key_, (gpointer) &val)){
        uint32_t style = 0;

        /* Determine, if windows is visible; important since invisible windows might have visible children */
        if(VMI_FAILURE == vmi_read_32_va(vmi, *val + off.wnd_style, pid, (uint32_t *)&style))
            return VMI_FAILURE;
        
        if(! (style & WS_VISIBLE))
            continue; 
        
        printf("\t\tWindow at %" PRIx64 "\n", *val);
        
        addr_t *child = malloc(sizeof(uint64_t)); 
        
        if(VMI_FAILURE == vmi_read_addr_va(vmi, *val + off.spwnd_child, pid, child))
            return VMI_FAILURE; 

        GHashTable* children = g_hash_table_new(g_int64_hash, g_int64_equal); 
        traverse_windows_pid(vmi, child, pid, children, result_windows);
        g_hash_table_destroy(children); 
        
    }   

    return VMI_SUCCESS;
}

status_t retrieve_windows_from_desktop_pid(vmi_instance_t vmi, addr_t desktop, vmi_pid_t pid, GArray *result_windows)
{
    uint32_t desk_id = 0; 

    addr_t addr = desktop + off.desk_desktopid_off;
    // Desktop ID
    if (VMI_FAILURE == vmi_read_32_va(vmi, addr, pid, &desk_id))
    {
        printf("\t\tFailed to read desktop ID at %" PRIx64 "\n", desktop + off.desk_desktopid_off);
        return VMI_FAILURE;
    }
    printf("\tRetrieveing Windows for desktop #%"PRIx32"\n", desk_id); 
    
    addr_t desktop_info; 
    addr = desktop + off.desk_pdeskinfo_off;
    // Retrieves pointer desktop info struct
    if (VMI_FAILURE == vmi_read_addr_va(vmi, addr, pid, &desktop_info))
    {
        printf("\t\tFailed to read pointer to _DESKTOPINFO at %" PRIx64 "\n", desktop + off.desk_pdeskinfo_off);
        return VMI_FAILURE;
    }

    printf("\t\t_DESKTOPINFO at: %" PRIx64 "\n", desktop_info);

    addr_t spwnd = 0;

    addr = desktop_info + off.spwnd_offset;
    /* Retrieves pointer to struct pointer window */
    if (VMI_FAILURE == vmi_read_addr_va(vmi, addr, pid, &spwnd))
    {
        printf("\t\t\tFailed to read pointer to _WINDOW at %" PRIx64 "\n",  desktop_info + off.spwnd_offset);
        return VMI_FAILURE;
    }

    if (!spwnd){
        printf("\t\t\tNo valid windows for _DESKTOPINFO %" PRIx64 "\n", desktop_info);
             return VMI_SUCCESS;
    }

    printf("\t\t\t_WINDOW at: %" PRIx64 "\n", spwnd);

    /* Iterates over all windows */
    printf("\tStarting to traverse windows, starting at %" PRIx64 "\n", spwnd);
    
    addr_t *root = malloc(sizeof(uint64_t));
    *root = spwnd; 

    GHashTable* seen_windows = g_hash_table_new(g_int64_hash, g_int64_equal); 

    traverse_windows_pid(vmi, root, pid, seen_windows, result_windows);  
    g_hash_table_destroy(seen_windows); 

    return VMI_SUCCESS;
}

/* Traverses this singly-linked list of desktops belonging to one WinSta */
status_t traverse_desktops(vmi_instance_t vmi, addr_t *desktops, 
                            size_t *max_len, addr_t list_head)
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
        
        printf("\tDesktop at %"PRIx64"\n", cur); 
        
        if (next == list_head)
            break;
        cur = next; 
    }
    *max_len = i; 

    return VMI_SUCCESS;
}

/* Reads relevant data from tagWINDOWSTATION-structs and the child tagDESKTOPs */
status_t populate_winsta(vmi_instance_t vmi, struct winsta_container *winsta, addr_t addr, vmi_pid_t providing_pid)
{
    winsta->addr = addr;

    /* 
     * Do it like volatility: Find a process with matching sessionID and take is VA as _MM_SESSION_SPACE
     * https://github.com/volatilityfoundation/volatility/blob/a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/gui/sessions.py#L49
     */
    winsta->providing_pid = providing_pid;

    /* Reads pointer to global atom table */
    if (VMI_FAILURE == vmi_read_addr_va(vmi, addr + off.p_global_atom_table_offset, 0, &winsta->atom_table))
    {
        printf("Failed to read pointer to atom table at %" PRIx64 "\n", addr + off.p_global_atom_table_offset);
        return VMI_FAILURE;
    }
    printf("\tAtom table at %"PRIx64"\n", winsta->atom_table);
    
    if (VMI_FAILURE == vmi_read_32_va(vmi, addr + off.winsta_session_id_offset, 0, &winsta->session_id))
    {
        printf("Failed to read session ID at %" PRIx64 "\n", addr + off.winsta_session_id_offset);
        return VMI_FAILURE;
    }
    printf("\tSession ID %"PRId32"\n", winsta->session_id);

    uint32_t wsf_flags = 0; 
    
    if (VMI_FAILURE == vmi_read_32_va(vmi, addr + off.winsta_wsf_flags, 0, &wsf_flags))
    {
        printf("Failed to read wsfFlags at %" PRIx64 "\n", addr + off.winsta_wsf_flags);
        return VMI_FAILURE;
    }

    /* See https://github.com/volatilityfoundation/volatility/blob/a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/gui/win32k_core.py#L350 */
    winsta->is_interactive = ! (wsf_flags & 4);

    addr_t desk = 0; 
    
    if (VMI_FAILURE == vmi_read_addr_va(vmi, addr + off.rpdesk_list_offset, 0, &desk))
    {
        printf("Failed to read pointer to rpdesklist at %" PRIx64 "\n", addr + off.rpdesk_list_offset);
        return VMI_FAILURE;
    }

    size_t len = 0x10; 
    winsta->desktops = (addr_t *) malloc(len*sizeof(addr_t)); 
    memset(winsta->desktops, 0 , sizeof(addr_t)*len); 

    if(VMI_FAILURE == traverse_desktops(vmi, winsta->desktops, &len, desk))
    {
        printf("Failed to traverse desktops of winsta at %" PRIx64 "\n", winsta->addr);
        winsta->len_desktops = len;
        return VMI_FAILURE;
    }       
    winsta->len_desktops = len;

    printf("\tFound %ld desktops\n", winsta->len_desktops);
    
    return VMI_SUCCESS;
}

/* Iterates over process list an retrieves all tagWINDOWSTATIONS-structs */
status_t retrieve_winstas_from_procs(vmi_instance_t vmi, struct winsta_container** winsta_ptr, size_t* len){
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
    char* procname; 
    vmi_pid_t pid; 
    size_t winsta_count = 0; 

    /* Walks the process list */
    while (1)
    {
        /* Calculate offset to the start of _EPROCESS-struct */
        current_process = cur_list_entry - off.active_proc_links_offset;

        /* NOTE: _EPROCESS.UniqueProcessId is a really VOID*, but is never > 32 bits,
         * so this is safe enough for x64 Windows for example purposes */
        vmi_read_32_va(vmi, current_process + off.pid_offset, 0, (uint32_t *)&pid);

        procname = vmi_read_str_va(vmi, current_process + off.name_offset, 0);

        if (!procname)
        {
            printf("Failed to find procname\n");
            return VMI_FAILURE;
        }

        /* Print out the process name */
        printf("[%5d] %s (struct addr:%" PRIx64 ")\n", pid, procname, current_process);
        if (procname)
        {
            free(procname);
            procname = NULL;
        }

        addr_t thrd_list_head = 0;

        /* Retrieves pointer of ThreadListHead-member == associated thread */
        if (VMI_FAILURE == vmi_read_addr_va(vmi, current_process + off.thread_list_head_offset, 0, &thrd_list_head))
        {
            printf("Failed to read ThreadListHead-pointer at %" PRIx64 "\n", current_process + off.thread_list_head_offset);
            return VMI_FAILURE;
        }
        printf("\tThreadListHead at: %" PRIx64 "\n", thrd_list_head);

        /* Calculates offset to the start of the _ETHREAD-struct */
        addr_t cur_thrd_list_entry = thrd_list_head;
        addr_t cur_ethread = 0;
        addr_t next_thread_entry = 0;

        /* Walks the list of threads belonging to one process */
        while (1)
        {
            cur_ethread = cur_thrd_list_entry - off.thread_list_entry_offset;
            printf("\t\tThread at %" PRIx64 "\n", cur_ethread);
            /* _ETHREAD contains a  _KTHREAD structure (of size 0x200 for Win7) in the beginning */
            addr_t cur_kthread = cur_ethread;
            addr_t teb = 0;

            /* Retrieves pointer to Win32Thread  */
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
                printf("\t\tTEB at %" PRIx64 "\n", teb);
                printf("\t\tFailed to read pointer to w32thrd_info at %" PRIx64 "\n", teb + 64);
                goto next_thrd;
            }
            addr_t desktop_info = 0;

            /* Not every thread has a THREADINFO-struct */
            if (!w32thrd_info)
            {
                goto next_thrd;
            }

            printf("\t\tWin32Thread at: %" PRIx64 "\n", w32thrd_info);

            // Retrieves pointer desktop info struct
            if (VMI_FAILURE == vmi_read_addr_va(vmi, w32thrd_info + off.w32t_deskinfo_offset, pid, &desktop_info))
            {
                printf("\t\tFailed to read pointer to _DESKTOPINFO at %" PRIx64 "\n", w32thrd_info + off.w32t_deskinfo_offset);
                goto next_thrd;
            }

            printf("\t\t\t_DESKTOPINFO at: %" PRIx64 "\n", desktop_info);

            addr_t cur_pwinsta = 0; 
            // Retrieves pointer to winsta struct
            if (VMI_FAILURE == vmi_read_addr_va(vmi, w32thrd_info + off.w32t_pwinsta_offset, pid, &cur_pwinsta))
            {
                printf("\t\tFailed to read pointer to tagWINDOWSTATION at %" PRIx64 "\n", w32thrd_info + off.w32t_pwinsta_offset);
                goto next_thrd;
            }

            if (cur_pwinsta && cur_pwinsta > 0x1000){
                bool is_known = false; 
                size_t i = 0; 

                for(; i<max_len; i++){
                    if (winstas[i].addr == 0)
                        break;    
                    if (winstas[i].addr == cur_pwinsta)
                        is_known = true;  
                }
                if (!is_known && i < max_len){
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

            /* All reads processed */
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
         * In Windows, the next pointer points to the head of list, this pointer is actually the
         * address of PsActiveProcessHead symbol, not the address of an ActiveProcessLink in
         * EPROCESS struct.
         * It means in Windows, we should stop the loop at the last element in the list
         */
        if (next_list_entry == off.ps_active_process_head)
        {
            break;
        }
    };

    *winsta_ptr = (struct winsta_container*) malloc(winsta_count * sizeof(struct winsta_container)); 
    memcpy(*winsta_ptr, winstas, winsta_count * sizeof(struct winsta_container));
    *len = winsta_count;

    return VMI_SUCCESS;
}

struct atom_entry * populate_atom_entry(vmi_instance_t vmi, addr_t atom_addr)
{
    struct atom_entry *entry = malloc( sizeof(struct atom_entry));
    memset(entry, 0, sizeof(struct atom_entry)); 

    if (VMI_FAILURE == vmi_read_addr_va(vmi, atom_addr + off.atom_entry_hashlink_offset, 0, &entry->hashlink))
    {
        printf("Error reading HashLink at %" PRIx64 "\n", atom_addr + off.atom_entry_hashlink_offset);
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_16_va(vmi, atom_addr + off.atom_entry_atom_offset, 0, (uint16_t *)&entry->atom))
    {
        printf("Error reading Atom at %" PRIx64 "\n", atom_addr + off.atom_entry_atom_offset);
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_16_va(vmi, atom_addr + off.atom_entry_ref_count_offset, 0, (uint16_t *)&entry->ref_count))
    {
        printf("Error reading ReferenceCount at %" PRIx64 "\n", atom_addr + off.atom_entry_ref_count_offset);
        return NULL;
    }

    if (VMI_FAILURE == vmi_read_8_va(vmi, atom_addr + off.atom_entry_name_len_offset, 0, (uint8_t *)&entry->name_len))
    {
        printf("Error reading NameLength at %" PRIx64 "\n", atom_addr + off.atom_entry_name_len_offset);
        return NULL;
    }
    printf("Name length %d\n", entry->name_len);
    entry->name = read_wchar_str(vmi, atom_addr + off.atom_entry_name_offset, (size_t) entry->name_len);

    //entry->name = vmi_read_unicode_str_va(vmi, atom_addr + off.atom_entry_name_offset, 0);
    //entry->name = vmi_read_str_va(vmi, ae + off.atom_entry_name_offset, 0);

    if (!entry->name) 
    {
        printf("Error reading wchar-string Name at %" PRIx64 "\n", atom_addr + off.atom_entry_name_offset);
    }else
        printf("%ls\n", entry->name);

    return entry;
}

/* https://bsodtutorials.wordpress.com/2015/11/11/understanding-atom-tables/ */
GHashTable* populate_atom_table(vmi_instance_t vmi, addr_t table_addr)
{
    uint32_t num_buckets = 0;  

    if (VMI_FAILURE == vmi_read_32_va(vmi, table_addr + off.atom_table_num_buckets_off, 0, (uint32_t*) &num_buckets))
    {
        printf("Failed to read num buckets-value of _RTL_ATOM_TABLE at %" PRIx64 "\n", table_addr + off.atom_table_num_buckets_off);
        return NULL;
    }
    printf("Num buckets in _RTL_ATOM_TABLE: %"PRId32"\n", num_buckets); 

    GHashTable* ht = g_hash_table_new(g_int_hash, g_int_equal);

    size_t i = 0;
    addr_t cur = 0; 
    struct atom_entry* a = NULL;

    /* Iterate the array of pointers to _RTL_ATOM_TABLE_ENTRY-structs at buckets */
    while (i < num_buckets)
    {
        if (VMI_FAILURE == vmi_read_addr_va(vmi, table_addr + off.atom_table_buckets_off + i * 4, 0, &cur))
        {
            printf("Failed to read pointer to buckets entry of _RTL_ATOM_TABLE at %" PRIx64 "\n", table_addr + off.atom_table_buckets_off  + i * 4);
            return NULL;
        }
        i++;

        if (!cur)
            continue;

        a = populate_atom_entry(vmi, cur);
        
        if (a){
            g_hash_table_insert(ht,  &a->atom, (gpointer) a); 
            printf("Atom at: %" PRIx64 " - Value: %" PRIx16 " - %" PRId32 "\n", cur, a->atom, a->ref_count);
            //print_as_hex((char*)a->name->contents, a->name->length); 
        }
        /* Traverses the linked list of each top level _RTL_ATOM_TABLE_ENTRY */
        while (a && a->hashlink)
        {   
            cur = a->hashlink;
            a = populate_atom_entry(vmi, cur);

            if (a)
            {
                g_hash_table_insert(ht,  &a->atom, (gpointer)a);
                printf("Atom at: %" PRIx64 " - Value: %" PRIx16 " - %" PRId32 "\n", cur, a->atom, a->ref_count);
            }
        }
    }

    return ht;
}

void clean_up(vmi_instance_t vmi ){
    /* Resumes the vm */
    vmi_resume_vm(vmi);

    /* Cleanup any memory associated with the LibVMI instance */
    vmi_destroy(vmi);
}

int main (int argc, char **argv)
{
    vmi_instance_t vmi = {0};
    uint64_t domid = 0;
    uint8_t init = VMI_INIT_DOMAINID;
    uint8_t config_type = VMI_CONFIG_GLOBAL_FILE_ENTRY;
    void *input = NULL, *config = NULL;

    if ( argc < 2 ) {
        printf("Usage: %s\n", argv[0]);
        printf("\t -d/--domid <domain id>\n");
        printf("\t -j/--json <path to kernel's json profile>\n");
        exit(EXIT_FAILURE);
    }

    if (argc == 2 )
        input = argv[1];

    if ( argc > 2 ) {
        const struct option long_opts[] = {
            {"domid", required_argument, NULL, 'd'},
            {"json", required_argument, NULL, 'j'},
            {NULL, 0, NULL, 0}
        };
        const char* opts = "n:d:j:s:";
        int c;
        int long_index = 0;

        while ((c = getopt_long(argc, argv, opts, long_opts, &long_index)) != -1)
            switch (c)
            {
            case 'd':
                domid = strtoull(optarg, NULL, 0);
                input = (void *)&domid;
                break;
            case 'j':
                config_type = VMI_CONFIG_JSON_PATH;
                config = (void *)optarg;
                break;
            default:
                printf("Unknown option\n");
                exit(EXIT_FAILURE); 
            }
    }
    
    /* Initializes the libvmi library */
    if (VMI_FAILURE == vmi_init_complete(&vmi, input, init, NULL, config_type, config, NULL)) {
        printf("Failed to init LibVMI library.\n");
        clean_up(vmi);
        exit(EXIT_FAILURE);
    }
    
    /* Checks, that VM is house a Windows OS */
    os_t os = vmi_get_ostype(vmi);
    if (VMI_OS_WINDOWS != os){
        fprintf(stderr, "Only Windows is supported!"); 
        clean_up(vmi);
        exit(EXIT_FAILURE);
    }
    
    /* Pauses the vm for consistent memory access */
    if (vmi_pause_vm(vmi) != VMI_SUCCESS) {
        printf("Failed to pause VM\n");
        clean_up(vmi);
        exit(EXIT_FAILURE);
    } 

    /* Retrieves name of the VM */
    char *vm_name = vmi_get_name(vmi);
    printf("Reconstruction if windows for VM %s\n", vm_name); 
    free(vm_name);
   
    /* Retrieves offsets to relevent fields */
    if(VMI_FAILURE == populate_offsets(vmi)){
        clean_up(vmi);
        exit(EXIT_FAILURE);
    }

    size_t len = 0; 
    struct winsta_container* winstas = NULL; 
    
    /* Gathers windows stations with all desktops by iterating over all processes */
    if(VMI_FAILURE == retrieve_winstas_from_procs(vmi, &winstas, &len))
        clean_up(vmi);

    printf("\n\nAddr     \tInteractive?\tSession\n"); 
    printf("-------------------------------------\n");
     for (size_t i = 0; i < len; i++)
    {
        printf("%" PRIx64 "\t", winstas[i].addr);
        if(winstas[i].is_interactive)
            printf("Interactive\t");
        else 
            printf("Not interactive\t");

        printf("# %" PRId32 "\n", winstas[i].session_id);
        //    continue;
/*
        GHashTable* atom_table = g_hash_table_new(g_int_hash, g_int_equal);  
        populate_atom_table(vmi, winstas[i].addr, winstas[i].providing_pid, atom_table);
        g_hash_table_destroy(atom_table); 
 
        for (size_t j = 0; j < winstas[i].len_desktops; j++)
        {
            GArray * windows = g_array_new(true, true, sizeof(addr_t));
            printf("Retrieving windows for desktop %" PRIx64 "\n", winstas[i].desktops[j]);
            retrieve_windows_from_desktop_pid(vmi, winstas[i].desktops[j], winstas[i].providing_pid, windows);
            draw_windows(vmi, 1280, 720, windows, winstas[i].providing_pid);
            g_array_free(windows, true);        
        }   */     
        
    }
    for (size_t i = 0; i < len; i++)
    {
        GHashTable *atom_table = populate_atom_table(vmi, winstas[i].atom_table);
        g_hash_table_destroy(atom_table);
    }

    // https://resources.infosecinstitute.com/topic/windows-gui-forensics-session-objects-window-stations-and-desktop/
    clean_up(vmi);
    exit(EXIT_SUCCESS);
}
