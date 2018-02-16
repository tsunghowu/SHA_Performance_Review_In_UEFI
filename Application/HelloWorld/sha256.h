#ifndef sha256_h
#define sha256_h

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

typedef struct {
   uint8_t data[64];
   uint32_t datalen;
   uint32_t bitlen[2];
   uint32_t state[8];
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, uint8_t data[], uint32_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[]);

extern void sha256_transform(SHA256_CTX *ctx, uint8_t data[]);


#endif // sha256_h

