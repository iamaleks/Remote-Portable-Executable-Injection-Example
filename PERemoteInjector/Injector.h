#pragma once

#include <Windows.h>
#include <tlhelp32.h>

typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;