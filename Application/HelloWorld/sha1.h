#ifndef sha1_h
#define sha1_h

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>

#define memcmp CompareMem
#define memcpy CopyMem

#define uint8_t UINT8
#define uint16_t UINT16 
#define uint32_t UINT32 
#define uint64_t UINT64 
#define size_t UINT32

#pragma pack(push, 1)
typedef struct {
	size_t index;
	uint32_t hash[5];
	uint64_t total;
	uint8_t block[64];
} sha1_state;
#pragma pack(pop)

void sha1_start(sha1_state *s);
void sha1_process(sha1_state *s, const void *p, size_t len);
void sha1_finish(sha1_state *s, uint32_t hash[5]);

extern void sha1_compress(uint32_t state[5], const uint8_t block[64]);

#endif // sha1_h
