#ifndef VMI_GUI_UTILS_H
#define VMI_GUI_UTILS_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <wchar.h>
#include <getopt.h>

#include <libvmi/libvmi.h>

#include "vmi_win_offsets.h"


#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
/*
 * Checks, wether the _OBJECT_HEADER, which precedes every executive object,
 * is preceded by an optional header of type _OBJECT_HEADER_NAME_INFO.
 * If this is the case, the name of the executive object is read and returned.
 */
const char* retrieve_objhdr_name(vmi_instance_t vmi, addr_t addr)
{
    addr_t obj_hdr = 0;
    addr_t obj_hdr_nameinfo_addr= 0;
    //addr_t name_addr = 0;
    uint8_t im = 0;
    const char* name = NULL;
    unicode_string_t* us = NULL;
    unicode_string_t out = { .contents = NULL };

    obj_hdr = addr - off.objhdr_body_offset;
    obj_hdr_nameinfo_addr = obj_hdr;

    if (VMI_FAILURE == vmi_read_8_va(vmi, obj_hdr + off.objhdr_infomask_offset,
            0, &im))
    {
        fprintf(stderr, "Error reading InfoMask from _OBJECT_HEADER at: %" PRIx64 "\n", obj_hdr);
        return NULL;
    }

    /* Checks, if there is a _OBJECT_HEADER_CREATOR_INFO after *NAME_INFO */
    if (im & OBJ_HDR_INFOMASK_CREATOR_INFO)
        obj_hdr_nameinfo_addr -= off.objhdr_creator_info_length;

    /* Returns, if there is no _OBJECT_HEADER_NAME_INFO */
    if (!(im & OBJ_HDR_INFOMASK_NAME))
        return NULL;

    obj_hdr_nameinfo_addr -= off.objhdr_name_info_length;

    us = vmi_read_unicode_str_va(vmi, obj_hdr_nameinfo_addr + off.objhdr_name_info_name_offset, 0);

    if (us && VMI_SUCCESS == vmi_convert_str_encoding(us, &out, "UTF-8"))
    {
        name = strndup((char*) out.contents, out.length);
        free(out.contents);
    }

    if (us)
        vmi_free_unicode_str(us);

    return name;
}

/*
 * Read a Windows wchar-string into a wchar_t*, since vmi_read_unicode_str_va
 * fails to parse _RTL_ATOM_ENTRY's name-string or _LARGE_UNICODE_STRINGs.
 * Expansion is performed since Windows' wchar is 2 bytes versus 4 bytes on
 * 64bit-Linux
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

        if (s[i] == L'\0')
            break;
    }
    return s;
}

wchar_t* read_wchar_str(vmi_instance_t vmi, addr_t start, size_t len)
{
    return read_wchar_str_pid(vmi, start, len, 0);
}


#endif