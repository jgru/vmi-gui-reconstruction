/* vmi-reconstruct-gui - a tool to reconstruct the GUI of a running VM.
 *
 * Copyright (C) 2021 Jan Gruber <j4n6ru@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <wchar.h>
#include <getopt.h>

#define LIBVMI_EXTRA_JSON
#include <libvmi/libvmi.h>
#include <libvmi/libvmi_extra.h>

#include <json-c/json.h>
#include <json-c/json_util.h>

/* Datastructures */
#include <glib.h>

/* Offset retrieval */
#include "vmi_win_offsets.h"

/* Atom table specific structs and functions */
#include "vmi_win_atom_table.h"

/* Graphics rendering */
#include "gfx.h"

//#define DEBUG

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

#define TEXT_OFFSET 5

/* Holds struct-offsets, needed to access relevant fields */
extern struct Offsets off;

/*
 * The following structs encapsulate only the information needed for the purpose
 * of reconstructing the GUI to a level, where dialogs could be identified for
 * clicking
 */
struct winsta_container
{
    addr_t addr;
    /*
     * For each GUI thread, win32k maps, the associated desktop heap into the user-­‐mode
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
    const char* name;
};

struct rect_container
{
    int16_t x0;
    int16_t x1;
    int16_t y0;
    int16_t y1;

    /* For convenience */
    uint16_t w;
    uint16_t h;
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

int sort_wnd_container(gconstpointer a, gconstpointer b)
{
    int res = 0;
    res = ((struct wnd_container*)b)->level - ((struct wnd_container*)a)->level;
    return res;
}

void draw_single_wnd_container(struct wnd_container* w)
{

    if ((w->style & WS_VISIBLE) &&
        !(w->style & WS_DISABLED) &&
        !(w->style & WS_MINIMIZE) &&
        !(w->exstyle & WS_EX_TRANSPARENT))
    {

        gfx_color(80 * w->level, 80 * w->level, 80 * w->level);
        gfx_fill_rect(w->r.x0, w->r.y0, w->r.w, w->r.h);

        gfx_color(0, 0, 0);
        gfx_rect(w->r.x0, w->r.y0, w->r.w, w->r.h);

        gfx_color(85 * w->level, 85 * w->level, 85 * w->level);
        gfx_fill_rect(w->rclient.x0, w->rclient.y0, w->rclient.w, w->rclient.h);

        gfx_color(0, 0, 0);
        gfx_rect(w->rclient.x0, w->rclient.y0, w->rclient.w, w->rclient.h);

        if (w->text)
        {
            if (w->r.w > 0)
                gfx_draw_str_multiline(w->r.x0 + TEXT_OFFSET, w->r.y0, w->text, strlen(w->text), w->r.w);
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

struct rect_container* get_visible_rect_from_bitmask(uint8_t* map, size_t n, struct rect_container* r)
{   
    struct rect_container* result = NULL;

    int byte, bit_idx;
    unsigned int bit; 
    int x0 = -1, x1 = -1, y0 = -1, y1 = -1; 
   // int lx0 = -1; 
    int lx1 = -1;

    for(int y = r->y0; y < r->y1; y++)
    {
        for(int x = r->x0; x < r->x1; x++)
        {   

            byte = x / 8 * y; 

            /* Parts of a wnd can be outside of the desktop's frame */
            if(byte < n)
            {
                bit_idx = x % 8;
                bit = 0x80 >> bit_idx; 
                
                if(!(map[byte] & bit))
                {   
                    if(x0 == -1 && y0 == -1)
                    {
                        x0 = x;
                        y0 = y; 
                        //ly1 = y1; 
                    }
                
                    if(x <= lx1 || lx1 == -1)
                        x1 = x; 

                    y1 = y;
                }
            }
        }
            lx1 = x1;
    }
    printf("%d\n", lx1);
    if (x0 != -1 && x0 != -1)
    {
        result = (struct rect_container*) malloc(sizeof(struct rect_container));
        result->x0 = x0; 
        result->x1 = x1;
        result->y0 = y0; 
        result->y1 = y1; 
        result->w = x1 -x0;
        result->h = y1 - y0;
    }

    return result;    
}
/* 
 * Naive assumption, that buttons will be 8 times smaller than the respective
 * desktop dimension 
 */
#define BTN_RATIO 4

void update_visibility_bitmask(uint8_t* map, size_t n, struct rect_container* r)
{   
    int byte, bit_idx;
    unsigned int bit; 

    for(int x = r->x0; x < r->x1; x++)
    {
        for(int y = r->y0; y < r->y1; y++)
        {   
            //if(x < 0 || y < 0)

            byte = x / 8 * y; 

            /* Parts of a wnd can be outside of the desktop's frame */
            if(byte < n)
            {
                bit_idx = x % 8;
                bit = 0x80 >> bit_idx; 
                map[byte] |= bit;
            }
        }
    }
}

struct rect_container* get_visible_rect(uint8_t* map, size_t n, int scanline, struct rect_container* r)
{   
    struct rect_container* result = NULL;

    int byte;
    int x0 = -1, x1 = -1, y0 = -1, y1 = -1; 
    //int ly1 = -1; 
    int lx1 = -1;
    bool is_y_hole = false;
    for(int y = r->y0; y < r->y1; y++)
    {
        for(int x = r->x0; x < r->x1; x++)
        {    
            byte = y * scanline + x;
            /* Parts of a wnd can be outside of the desktop's frame */
            if(byte < n)
            {
                if(map[byte] != 255)
                {   
                    if(x0 == -1 && y0 == -1)
                    {
                        x0 = x;
                        y0 = y; 
                        //ly1 = y1;
                    }

                    if (x <= lx1 || lx1 == -1)
                        x1 = x;
                        
                    if(!is_y_hole)
                        y1 = y; 
                    
                }
                else
                    if(x == x0)
                        is_y_hole = true;
            }
            //ly1 = y1;
        }
        lx1 = x1;
    }

    if (x0 != -1 && x0 != -1)
    {
        result = (struct rect_container*) malloc(sizeof(struct rect_container));
        result->x0 = x0; 
        result->x1 = x1;
        result->y0 = y0; 
        result->y1 = y1; 
        result->w = x1 -x0;
        result->h = y1 - y0;
    }

    return result;    
}

void update_visibility_mask(uint8_t* map, size_t n, int scanline, struct rect_container* r)
{   
    int byte;   
    
    for(int x = r->x0; x < r->x1; x++)
    {
        for(int y = r->y0; y < r->y1; y++)
        {   
            //if(x < 0 || y < 0)

            byte = y * scanline + x; 

            /* Parts of a wnd can be outside of the desktop's frame */
            if(byte < n)
            {
                //bit_idx = x % 8;
                //bit = 0x80 >> bit_idx; 
                map[byte] = 255;
            }
        }
    }
    printf("%d - %d\n", r->x0, r->y0);
    printf("%d - %d\n", r->x1-r->x0, r->y1-r->y0);
}

struct wnd_container* find_button_to_click(GArray* windows, char *t[], size_t tlen)
{      
    uint16_t mw, mh; 
    /* Current window */
    struct wnd_container* wnd = NULL; 
    /* Candidate window */
    struct wnd_container* cand = NULL;
    /* Visibile part of candidate */
    struct rect_container* r = NULL; 

    /* Resulting button with updated rect */
    struct wnd_container* btn = NULL; 

    if (!windows)
        return NULL;

    /* 
     * Naive assumption, that buttons will be 8 times smaller than the respective
     * desktop dimension 
     */
    wnd = g_array_index(windows, struct wnd_container*, 0);
    
    mw = wnd->r.x1 / BTN_RATIO;
    mh = wnd->r.y1 / BTN_RATIO;
    
    /* Frame of desktop */
    uint16_t w = wnd->r.x1;
    uint16_t h =wnd->r.y1;

    /* Keeping track of occupied screen locations with a bitmap */
    /*
    size_t n = ((w + w % 8) / 8) * h;
    uint8_t map[n];
    memset(map, 0, sizeof(uint8_t) * n);
    */
    size_t n = w  * h;
    uint8_t map[n];
    memset(map, 0, sizeof(uint8_t) * n);

    size_t l = windows->len;
    
    for (size_t i = 0; i < l; i++)
    {   
        wnd = g_array_index(windows, struct wnd_container*, l - (i+1));
        
        /* Performs filtering based on size */
        if(wnd->r.w > mw || wnd->r.h > mh)
        {   
            printf("Updating visibility mask: %s \n", wnd->text);
            //update_visibility_bitmask(map, n, &wnd->r); 
            update_visibility_mask(map, n, w, &wnd->r); 
            continue; 
        }

        /* TODO: Performs filtering based on Class eventually */ 

        /* Checks, if a target text is in the window's text is */
        for(size_t j = 0; j < tlen; j++)
        {
            if (wnd->text && strstr(wnd->text, t[j]) != NULL)
            {   
                printf("Found matching button text - %s\n", wnd->text);
                cand = wnd; 
                break;  
            }
        }
        
        if(!cand)
        {
            /* Update visibility */
            //update_visibility_bitmask(map, n, &wnd->r); 
            printf("Updating visibility mask: %s \n", wnd->text);
            update_visibility_mask(map, n, w, &wnd->r); 
            continue; 
        }

        /* Checks visibility of candidate btn */
        r = get_visible_rect(map, n, w, &cand->r);
        
        if(r)
            break; 
        else
            /* Not visible at all, reset candidate */
            cand = NULL; 
    }

    if (cand)
    {
        btn = (struct wnd_container *)malloc(sizeof(struct wnd_container));
        memcpy(btn, cand, sizeof(struct wnd_container));
        btn->r = *r; 
    }
    return btn; 
}

int draw_windows(vmi_instance_t vmi, GArray* windows)
{
    struct wnd_container* wnd;
    int w, h;

    if (!windows)
        return -1;

    wnd = g_array_index(windows, struct wnd_container*, 0);

    if (!wnd)
        return -1;

    w = wnd->r.x1;
    h = wnd->r.y1;

    /* Prepare drawing */
    gfx_open(w, h, "GUI Reconstruction");
    gfx_clear_color(255, 255, 255);
    gfx_clear();
    gfx_color(0, 0, 0);

    for (size_t i = 0; i < windows->len; i++)
    {
        wnd = g_array_index(windows, struct wnd_container*, i);
        draw_single_wnd_container(wnd);
    }

    // TODO retrieve buttons to click here
    char *btn_texts[2] = {"Agree\0", "OK\0"}; 

    struct wnd_container* btn = find_button_to_click(windows, btn_texts, ARRAY_SIZE(btn_texts));

    if(btn)
    {
        printf("Found clickable button \"%s\" at (%d, %d)", btn->text, btn->r.x0, btn->r.y0);

        gfx_color(255, 0, 0);
        gfx_rect(btn->r.x0, btn->r.y0, btn->r.w, btn->r.h);
    }

    char c = '\0';
    while (1)
    {
        c = gfx_wait();
        if (c != '\0')
            break;
    }

    gfx_close();

    return 0;
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
    wc->r.w = x1 - x0; 
    wc->r.h = y1 - y0; 

    wc->rclient.x0 = rx0;
    wc->rclient.x1 = rx1;
    wc->rclient.y0 = ry0;
    wc->rclient.y1 = ry1;
    wc->rclient.w = rx1 - rx0; 
    wc->rclient.h = ry1 - ry0; 

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
    /* Retrieves pointer desktop info struct */
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

    winsta->name = retrieve_objhdr_name(vmi, addr);
#ifdef DEBUG
    printf("\tSession ID %" PRId32 "\n", winsta->session_id);

    if (winsta->name)
        printf("\tName: %s\n", winsta->name);
    printf("\tAtom table at %" PRIx64 "\n", winsta->atom_table);
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

        /* Print out the process name */
        printf("[%5d] %s (struct addr:%" PRIx64 ")\n", pid, procname, current_process);

        if (procname)
        {
            free(procname);
            procname = NULL;
        }

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
                    struct winsta_container wc = {0};
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



void clean_up(vmi_instance_t vmi)
{
    /* Resumes the vm */
    vmi_resume_vm(vmi);

    /* Cleanup any memory associated with the LibVMI instance */
    vmi_destroy(vmi);
}

GArray* find_first_active_desktop(vmi_instance_t vmi)
{
    size_t len = 0;
    struct winsta_container* winstas = NULL;
    const char* desk_name = NULL;

    /* Gathers windows stations with all desktops by iterating over all procs */
    if (VMI_FAILURE == retrieve_winstas_from_procs(vmi, &winstas, &len))
    {
        return NULL;
    }

    for (size_t i = 0; i < len; i++)
    {
        /* Ignore session 0 */
        if (winstas[i].session_id == 0)
            continue;

        /* Discard with a name different than WinSta0 and non-interactive window stations */
        if (!winstas[i].is_interactive)
            continue;

        /* Only take WinSta0 into account */
        if (winstas[i].name && strcmp(winstas[i].name, "WinSta0") != 0)
            continue;

        for (size_t j = 0; j < winstas[i].len_desktops; j++)
        {
            desk_name = retrieve_objhdr_name(vmi, winstas[i].desktops[j]);

            if (desk_name && strncmp(desk_name, "Default\0", 8) != 0)
                continue;

            return retrieve_windows_from_desktop(
                    vmi, winstas[i].desktops[j], winstas[i].providing_pid);
        }
    }

    return NULL;
}

status_t vmi_reconstruct_gui(uint64_t domid, const char *kernel_json,
                             const char *win32k_json, bool is_show_all)
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

    if (is_show_all)
    {
        size_t len = 0;
        struct winsta_container* winstas = NULL;

        /* Gathers windows stations with all desktops by iterating over all procs */
        if (VMI_FAILURE == retrieve_winstas_from_procs(vmi, &winstas, &len))
        {
            clean_up(vmi);
            return VMI_FAILURE;
        }

        printf("\nAddr     \tInteractive?\tSession\tName\n");
        printf("-------------------------------------\n");
        for (size_t i = 0; i < len; i++)
        {
            printf("%" PRIx64 "\t", winstas[i].addr);
            if (winstas[i].is_interactive)
                printf("Interactive\t");
            else
                printf("Not interactive\t");

            printf("# %" PRId32 "\t", winstas[i].session_id);
            printf("%s\n", winstas[i].name);
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
                if (windows)
                    draw_windows(vmi, windows);
                g_array_free(windows, true);
            }
            printf("-------------------------------------\n\n");
        }
    }
    else
    {
        GArray* windows = find_first_active_desktop(vmi);
        draw_windows(vmi, windows);
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
    int show_all_flag = 0;

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
            {"all", no_argument, NULL, 'a'},
            {NULL, 0, NULL, 0}
        };
        const char* opts = ":d:k:w:a";
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
                case 'a':
                    show_all_flag = 1;
                    break;
                default:
                    printf("Unknown option\n");
                    exit(EXIT_FAILURE);
            }
    }

#ifdef DEBUG
    printf("CLI-Parameters\n");
    printf("\tDom ID: %ld\n", domid);
    printf("\tKernel-JSON: %s\n", kernel_json);
    printf("\tWin32k-JSON: %s\n", win32k_json);
#endif

    status_t ret = vmi_reconstruct_gui(domid, kernel_json, win32k_json, show_all_flag);

    if (ret == VMI_SUCCESS)
        exit(EXIT_SUCCESS);
    else
        exit(EXIT_FAILURE);
}
