#include "PacketType.h"
#include "HookEngine/HookEngine.h"
#define __DBG_ACTIVATED__ TRUE
#include "dbg/dbg.h"
#include "FunctionOffset.h"
#include <windows.h>
#include <stdint.h>

// Globals
char *loggerPath = NULL;
FILE *defaultOutput = NULL;
FILE *handlersOutput = NULL;
bool enablePacketEncryption = true;
char sessionDateDir[1000];

//=========================================================================
typedef char (__thiscall *_SendPacket) (int self, unsigned char *buffer, size_t size);
typedef char (__thiscall *_RecvPacket) (int self, unsigned char *buffer, int *size, int a4);

//=========================================================================

_RecvPacket TrueRecvPacket = (_RecvPacket) OFFSET_RecvPacket;
_SendPacket TrueSendPacket = (_SendPacket) OFFSET_SendPacket;

void writePacketToFile(
	char *packetType,
	unsigned char *packet,
	size_t packetSize
) {
	static char filename[10000];
	sprintf(filename, "%s/%s.txt", sessionDateDir, packetType);
	FILE *packetFile = fopen(filename, "a+");

	dbg_set_output(packetFile);
	buffer_print(packet, packetSize, NULL);
	fclose(packetFile);

	dbg_set_output(defaultOutput);
}

#pragma pack(push, 1)
typedef struct {
    uint16_t type;
    uint32_t reserved;
    uint32_t unk1;
    uint32_t pcId;
    uint8_t unk2;
} CZ_REQ_FRIENDLY_FIGHTPkt;

typedef struct {
    uint16_t type;
    uint32_t reserved;
    uint32_t pcId;
    float height;
    uint32_t unk1;
    uint8_t unk2;
} ZC_JUMPPkt;

#pragma pack(pop)

/*
GIVE FUNCTION NAME
sub_DDBED0(&v24, v4, (int)"CNetUsr::RecvContentsNet()", 1);
*/
uint32_t targetId = 0;
int selfSend = 0;
uint32_t me = 0;

//=========================================================================
char __fastcall HookRecvPacket(int self, void *edx, unsigned char *buffer, int *size, int a4)
{
	char result;

	if ((result = TrueRecvPacket(self, buffer, size, a4))) {
		uint32_t packetType = 0;
		memcpy(&packetType, buffer, 2);
		if (packetType == ZC_JUMP) {
            ZC_JUMPPkt *jmpPkt = (void *) buffer;
            targetId = jmpPkt->pcId;

            if (targetId != 0 && me != targetId) {
                    if (me == 0) {
                        me = targetId;
                    }
                    CZ_REQ_FRIENDLY_FIGHTPkt letsfight = {
                        .type = CZ_REQ_FRIENDLY_FIGHT,
                        .reserved = 0,
                        .unk1 = 0,
                        .pcId = targetId,
                        .unk2 = 0
                    };
                    dbg ("Provoked %x ! ", targetId);
                    targetId = 0;
                return TrueSendPacket(selfSend, (unsigned char*) &letsfight, sizeof(letsfight));
            }

		}
		char *packetTypeStr = PacketType_to_string((PacketType) packetType);
		if (packetTypeStr != NULL) {
			dbg("RECV PacketType = %s", packetTypeStr);
		}
		buffer_print(buffer, *size, "> ");
		dbg("============================");
		writePacketToFile(packetTypeStr, buffer, *size);
	}

	return result;
}

//=========================================================================
char __fastcall HookSendPacket(int self, void *edx, unsigned char *buffer, size_t size)
{
    selfSend = self;
	uint32_t packetType = 0;
	memcpy(&packetType, buffer, 2);
	char *packetTypeStr = PacketType_to_string((PacketType) packetType);
	if (packetTypeStr != NULL) {
		dbg("SEND PacketType = %s", packetTypeStr);
	}
	buffer_print(buffer, size, "> ");
	dbg("============================");
	writePacketToFile(packetTypeStr, buffer, size);

    return TrueSendPacket(self, buffer, size);
}

//=========================================================================
// Utils
char *get_module_path(char *module)
{
	// Get current module path
	char path[MAX_PATH] = { 0 };
	GetModuleFileNameA(GetModuleHandleA(module), path, sizeof(path));

	char * lastSlash = strrchr(path, '\\');
	char * dllName = (lastSlash != NULL) ? &lastSlash[0] : path;
	dllName[0] = '\0';

	if (!strlen(path)) {
		return NULL;
	}

	return strdup(path);
}


//=========================================================================
int startInjection() {

	// Init path & dbg
	loggerPath = get_module_path("ProvokeEverybody.dll");
	HookEngine *engine = HookEngine_new("ProvokeEverybody.dll", "HookEngine.dll");
	if (!engine) {
        MessageBoxA(NULL, "Cannot create new hookengine.", "Error", 0);
        return 0;
	}

	// Init output path
	SYSTEMTIME time;
	GetSystemTime(&time);

	sprintf(sessionDateDir, "%s/packets/%.02d_%.02d_%d-%.02dh%.02d", loggerPath, time.wDay, time.wMonth, time.wYear, time.wHour, time.wMinute);
	CreateDirectoryA(sessionDateDir, NULL);

	char captureFile[1000];
	sprintf(captureFile, "%s/capture.txt", sessionDateDir);

	if (!(defaultOutput = fopen(captureFile, "w+"))) {
		MessageBoxA(NULL, "Cannot create capture file.", captureFile, 0);
		return 0;
	}

	dbg_set_output(defaultOutput);

	// initialize packets strings
	packetTypeInit();

	// Set the hooks
	if (!HookEngine_hook((PVOID*) &TrueSendPacket, HookSendPacket)) {
		MessageBoxA(NULL, "Cannot hook Tos_Client!SendPacket", "Error", 0);
		return 0;
	}
	if (!HookEngine_hook((PVOID*) &TrueRecvPacket, HookRecvPacket)) {
		MessageBoxA(NULL, "Cannot hook Tos_Client!RecvPacket", "Error", 0);
		return 0;
	}

	return 0;
}

void endInjection(void) {
	HookEngine_unhook_all();
}

bool WINAPI DllMain(HMODULE dll, DWORD reason, LPVOID reserved) {

	switch (reason)
	{
		case DLL_PROCESS_ATTACH:
			CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)startInjection, NULL, 0, NULL);
			break;

		case DLL_PROCESS_DETACH:
			endInjection();
			break;
	}

	return true;
}
