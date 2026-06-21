
#ifndef _URLMON_PRECOMP_H
#define _URLMON_PRECOMP_H

#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H

#ifndef PROXY_CLSID_IS
#define PROXY_CLSID_IS {0x79EAC9F1,0xBAF9,0x11CE,{0x8C,0x82,0x00,0xAA,0x00,0x4B,0xA9,0x0B}}
#endif

#define NONAMELESSUNION
#define NONAMELESSSTRUCT
#define OEMRESOURCE

#include "urlmon_main.h"

#include <winreg.h>
#include <advpub.h>
#define NO_SHLWAPI_REG
#include <shlwapi.h>

#include <wine/debug.h>

#endif /* !_URLMON_PRECOMP_H */
