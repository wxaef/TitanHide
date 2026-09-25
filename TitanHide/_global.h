#ifndef _GLOBAL_H
#define _GLOBAL_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

/*
 * PatchGuard-compatible mode
 *
 * On x64 this is enabled by default. The driver must not patch the SSDT,
 * ntoskrnl code, or other PatchGuard-protected kernel structures.
 *
 * The legacy hook implementation remains in the source tree for reference,
 * but it is not activated by the driver entry path while this mode is enabled.
 */
#ifdef _WIN64
#define TITANHIDE_PATCHGUARD_COMPAT 1
#else
#define TITANHIDE_PATCHGUARD_COMPAT 0
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#include <ntifs.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>
#include <ntstrsafe.h>
#include <ntimage.h>

#ifdef __cplusplus
}
#endif

ULONG GetPoolTag();
void* RtlAllocateMemory(bool InZeroMemory, SIZE_T InSize);
void RtlFreeMemory(void* InPointer);
NTSTATUS RtlSuperCopyMemory(IN VOID UNALIGNED* Destination, IN CONST VOID UNALIGNED* Source, IN ULONG Length);

#endif