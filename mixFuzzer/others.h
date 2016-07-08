#pragma once
#include <stdint.h>

#define SOFT_LOGO TEXT(\
	"===============================================================================\n"\
	"|                        Wellcome to " SOFT_NAME " " SOFT_VER "                           |\n"\
	"===============================================================================\n\n")

#define CDB_X86 TEXT("cdb_x86.exe")
#define CDB_X64 TEXT("cdb_x64.exe")
#define GFLAGS_X86 TEXT("tools\\gflags_x86.exe")
#define GFLAGS_X64 TEXT("tools\\gflags_x64.exe")

const static size_t MAX_SENDBUFF_SIZE = 204800;

#pragma pack(push,1)
typedef struct _file_pack
{
	uint32_t time;
	uint32_t dirLen;
	uint8_t type;
	char data[0];
}FILEPACK, *PFILEPACK;

typedef struct _tmplnode
{
	uint32_t offset;
	char *data;
	uint32_t type;
	struct _tmplnode *next;
}TMPL_NODE, *PTMPL_NODE;
#pragma pack(pop)
