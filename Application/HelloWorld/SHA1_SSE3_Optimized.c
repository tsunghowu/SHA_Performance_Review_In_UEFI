/** @file
  This sample application bases on HelloWorld PCD setting 
  to print "UEFI Hello World!" to the UEFI Console.

  Copyright (c) 2006 - 2016, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials                          
  are licensed and made available under the terms and conditions of the BSD License         
  which accompanies this distribution.  The full text of the license may be found at        
  http://opensource.org/licenses/bsd-license.php                                            

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,                     
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.             

**/

#include <Uefi.h>
#include <Library/PcdLib.h>
#include <Library/IoLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include "sha1.h"

//
// String token ID of help message text.
// Shell supports to find help message in the resource section of an application image if
// .MAN file is not found. This global variable is added to make build tool recognizes
// that the help string is consumed by user and then build tool will add the string into
// the resource section. Thus the application can use '-?' option to show help message in
// Shell.
//

#ifndef UINT32_C
  #define UINT32_C(c) c##UL
#endif
  

#define TESTCASE(a,b,c,d,e,msg) {{UINT32_C(a),UINT32_C(b),UINT32_C(c),UINT32_C(d),UINT32_C(e)}, msg}

struct testcase {
  uint32_t answer[5];
  char *msg;
};

struct testcase testCases[] = {
  TESTCASE(0xDA39A3EE,0x5E6B4B0D,0x3255BFEF,0x95601890,0xAFD80709, ""),
  TESTCASE(0x86F7E437,0xFAA5A7FC,0xE15D1DDC,0xB9EAEAEA,0x377667B8, "a"),
  TESTCASE(0xA9993E36,0x4706816A,0xBA3E2571,0x7850C26C,0x9CD0D89D, "abc"),
  TESTCASE(0xC12252CE,0xDA8BE899,0x4D5FA029,0x0A47231C,0x1D16AAE3, "message digest"),
  TESTCASE(0x32D10C7B,0x8CF96570,0xCA04CE37,0xF2A19D84,0x240D3A89, "abcdefghijklmnopqrstuvwxyz"),
  TESTCASE(0x84983E44,0x1C3BD26E,0xBAAE4AA1,0xF95129E5,0xE54670F1, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
};

#define min(a, b) ({ \
  __typeof__(a) _a = (a); \
  __typeof__(b) _b = (b); \
  _a < _b ? _a : _b; \
})

#define uint32 UINT32
#define uint8 UINT8

struct sha1_context
{
    uint32 total[2];
    uint32 state[5];
    uint8 buffer[64];
};

void slow_sha1_starts( struct sha1_context *ctx );
void slow_sha1_update( struct sha1_context *ctx, uint8 *input, uint32 length );
void slow_sha1_finish( struct sha1_context *ctx, uint8 digest[20] );


/*
 * FIPS 180-1 compliant SHA-1 implementation,
 * by Christophe Devine <devine@cr0.net>;
 * this program is licensed under the GPL.
 */

#define GET_UINT32(n,b,i)                       \
{                                               \
    (n) = ( (uint32) (b)[(i)    ] << 24 )       \
        | ( (uint32) (b)[(i) + 1] << 16 )       \
        | ( (uint32) (b)[(i) + 2] <<  8 )       \
        | ( (uint32) (b)[(i) + 3]       );      \
}

#define PUT_UINT32(n,b,i)                       \
{                                               \
    (b)[(i)    ] = (uint8) ( (n) >> 24 );       \
    (b)[(i) + 1] = (uint8) ( (n) >> 16 );       \
    (b)[(i) + 2] = (uint8) ( (n) >>  8 );       \
    (b)[(i) + 3] = (uint8) ( (n)       );       \
}

void slow_sha1_starts( struct sha1_context *ctx )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
}

void slow_sha1_process( struct sha1_context *ctx, uint8 data[64] )
{
    uint32 temp, A, B, C, D, E, W[16];

    GET_UINT32( W[0],  data,  0 );
    GET_UINT32( W[1],  data,  4 );
    GET_UINT32( W[2],  data,  8 );
    GET_UINT32( W[3],  data, 12 );
    GET_UINT32( W[4],  data, 16 );
    GET_UINT32( W[5],  data, 20 );
    GET_UINT32( W[6],  data, 24 );
    GET_UINT32( W[7],  data, 28 );
    GET_UINT32( W[8],  data, 32 );
    GET_UINT32( W[9],  data, 36 );
    GET_UINT32( W[10], data, 40 );
    GET_UINT32( W[11], data, 44 );
    GET_UINT32( W[12], data, 48 );
    GET_UINT32( W[13], data, 52 );
    GET_UINT32( W[14], data, 56 );
    GET_UINT32( W[15], data, 60 );

#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

#define R(t)                                            \
(                                                       \
    temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^     \
           W[(t - 14) & 0x0F] ^ W[ t      & 0x0F],      \
    ( W[t & 0x0F] = S(temp,1) )                         \
)

#define P(a,b,c,d,e,x)                                  \
{                                                       \
    e += S(a,5) + F(b,c,d) + K + x; b = S(b,30);        \
}

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

    P( A, B, C, D, E, W[0]  );
    P( E, A, B, C, D, W[1]  );
    P( D, E, A, B, C, W[2]  );
    P( C, D, E, A, B, W[3]  );
    P( B, C, D, E, A, W[4]  );
    P( A, B, C, D, E, W[5]  );
    P( E, A, B, C, D, W[6]  );
    P( D, E, A, B, C, W[7]  );
    P( C, D, E, A, B, W[8]  );
    P( B, C, D, E, A, W[9]  );
    P( A, B, C, D, E, W[10] );
    P( E, A, B, C, D, W[11] );
    P( D, E, A, B, C, W[12] );
    P( C, D, E, A, B, W[13] );
    P( B, C, D, E, A, W[14] );
    P( A, B, C, D, E, W[15] );
    P( E, A, B, C, D, R(16) );
    P( D, E, A, B, C, R(17) );
    P( C, D, E, A, B, R(18) );
    P( B, C, D, E, A, R(19) );

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

    P( A, B, C, D, E, R(20) );
    P( E, A, B, C, D, R(21) );
    P( D, E, A, B, C, R(22) );
    P( C, D, E, A, B, R(23) );
    P( B, C, D, E, A, R(24) );
    P( A, B, C, D, E, R(25) );
    P( E, A, B, C, D, R(26) );
    P( D, E, A, B, C, R(27) );
    P( C, D, E, A, B, R(28) );
    P( B, C, D, E, A, R(29) );
    P( A, B, C, D, E, R(30) );
    P( E, A, B, C, D, R(31) );
    P( D, E, A, B, C, R(32) );
    P( C, D, E, A, B, R(33) );
    P( B, C, D, E, A, R(34) );
    P( A, B, C, D, E, R(35) );
    P( E, A, B, C, D, R(36) );
    P( D, E, A, B, C, R(37) );
    P( C, D, E, A, B, R(38) );
    P( B, C, D, E, A, R(39) );

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

    P( A, B, C, D, E, R(40) );
    P( E, A, B, C, D, R(41) );
    P( D, E, A, B, C, R(42) );
    P( C, D, E, A, B, R(43) );
    P( B, C, D, E, A, R(44) );
    P( A, B, C, D, E, R(45) );
    P( E, A, B, C, D, R(46) );
    P( D, E, A, B, C, R(47) );
    P( C, D, E, A, B, R(48) );
    P( B, C, D, E, A, R(49) );
    P( A, B, C, D, E, R(50) );
    P( E, A, B, C, D, R(51) );
    P( D, E, A, B, C, R(52) );
    P( C, D, E, A, B, R(53) );
    P( B, C, D, E, A, R(54) );
    P( A, B, C, D, E, R(55) );
    P( E, A, B, C, D, R(56) );
    P( D, E, A, B, C, R(57) );
    P( C, D, E, A, B, R(58) );
    P( B, C, D, E, A, R(59) );

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

    P( A, B, C, D, E, R(60) );
    P( E, A, B, C, D, R(61) );
    P( D, E, A, B, C, R(62) );
    P( C, D, E, A, B, R(63) );
    P( B, C, D, E, A, R(64) );
    P( A, B, C, D, E, R(65) );
    P( E, A, B, C, D, R(66) );
    P( D, E, A, B, C, R(67) );
    P( C, D, E, A, B, R(68) );
    P( B, C, D, E, A, R(69) );
    P( A, B, C, D, E, R(70) );
    P( E, A, B, C, D, R(71) );
    P( D, E, A, B, C, R(72) );
    P( C, D, E, A, B, R(73) );
    P( B, C, D, E, A, R(74) );
    P( A, B, C, D, E, R(75) );
    P( E, A, B, C, D, R(76) );
    P( D, E, A, B, C, R(77) );
    P( C, D, E, A, B, R(78) );
    P( B, C, D, E, A, R(79) );

#undef K
#undef F

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
}

void slow_sha1_update( struct sha1_context *ctx, uint8 *input, uint32 length )
{
    uint32 left, fill;

    if( ! length ) return;

    left = ( ctx->total[0] >> 3 ) & 0x3F;
    fill = 64 - left;

    ctx->total[0] += length <<  3;
    ctx->total[1] += length >> 29;

    ctx->total[0] &= 0xFFFFFFFF;
    ctx->total[1] += ctx->total[0] < ( length << 3 );

    if( left && length >= fill )
    {
        memcpy( (void *) (ctx->buffer + left), (void *) input, fill );
        slow_sha1_process( ctx, ctx->buffer );
        length -= fill;
        input  += fill;
        left = 0;
    }

    while( length >= 64 )
    {
        slow_sha1_process( ctx, input );
        length -= 64;
        input  += 64;
    }

    if( length )
    {
        memcpy( (void *) (ctx->buffer + left), (void *) input, length );
    }
}

static uint8 sha1_padding[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void slow_sha1_finish( struct sha1_context *ctx, uint8 digest[20] )
{
    uint32 last, padn;
    uint8 msglen[8];

    PUT_UINT32( ctx->total[1], msglen, 0 );
    PUT_UINT32( ctx->total[0], msglen, 4 );

    last = ( ctx->total[0] >> 3 ) & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    slow_sha1_update( ctx, sha1_padding, padn );
    slow_sha1_update( ctx, msglen, 8 );

    PUT_UINT32( ctx->state[0], digest,  0 );
    PUT_UINT32( ctx->state[1], digest,  4 );
    PUT_UINT32( ctx->state[2], digest,  8 );
    PUT_UINT32( ctx->state[3], digest, 12 );
    PUT_UINT32( ctx->state[4], digest, 16 );
}


UINT32 self_test(void)
{
  int res = 0;
  unsigned int i;
  for (i = 0; i < sizeof(testCases) / sizeof(testCases[i]); ++i) {
#if 1
    UINT8 hash[20];
    struct testcase *tc = &testCases[i];
    sha1_state s;
    sha1_start(&s);
    {
        const size_t len = AsciiStrLen(tc->msg);
        sha1_process(&s, tc->msg, len);
    }
    sha1_finish(&s, (UINT32*)hash);

    if (CompareMem(hash, tc->answer, sizeof(tc->answer)) != 0) {
        DEBUG((EFI_D_ERROR, "Test %d failed!\n", i));
        Print (L"mismatch, Test Case %d\n", i);
        res = -1;
    }
#else
    struct sha1_context ctx;
    UINT8 sha1sum[20];
    struct testcase *tc = &testCases[i];

    slow_sha1_starts( &ctx ); 
    slow_sha1_update( &ctx, tc->msg, (UINT32)AsciiStrLen(tc->msg) );
    slow_sha1_finish( &ctx, sha1sum );
     DEBUG((EFI_D_ERROR, "Partition Hash: "));
    for( j = 0; j < 20; j++ )
    {
         DEBUG((EFI_D_ERROR, "%2X", sha1sum[j]));
    }
    DEBUG((EFI_D_ERROR, "\n "));
#endif    
  }


  return res;
}

#define EDKII_FAST_SHA1_IMP_PROTOCOL_GUID \
  { 0x545f1bef, 0x604, 0x4531, { 0xae, 0x85, 0xbd, 0xf7, 0x25, 0x5c, 0xa8, 0x8 } }


/*
void sha1_start(sha1_state *s);
void sha1_process(sha1_state *s, const void *p, size_t len);
void sha1_finish(sha1_state *s, uint32_t hash[5]);
*/
typedef
VOID
(EFIAPI *EDKII_FAST_SHA1_START)(
  sha1_state *s
);

typedef
VOID
(EFIAPI *EDKII_FAST_SHA1_PROCESS)(
  sha1_state *s, const void *p, size_t len
);

typedef
VOID
(EFIAPI *EDKII_FAST_SHA1_FINISH)(
  sha1_state *s, uint32_t hash[5]
);

typedef struct _EDKII_FAST_SHA1_IMP_PROTOCOL {
  EDKII_FAST_SHA1_START Fast_Sha1_Start;
  EDKII_FAST_SHA1_PROCESS Fast_Sha1_Process;
  EDKII_FAST_SHA1_FINISH Fast_Sha1_Finish;
} EDKII_FAST_SHA1_IMP_PROTOCOL;


VOID 
EFIAPI
SSE3_FAST_SHA1_START(
  sha1_state *s
);

VOID
EFIAPI
SSE3_FAST_SHA1_PROCESS(
  sha1_state *s, const void *p, size_t len
);

VOID
EFIAPI
SSE3_FAST_SHA1_FINISH(
  sha1_state *s, uint32_t hash[5]
);

EDKII_FAST_SHA1_IMP_PROTOCOL mFastSha1Implementation = {
  SSE3_FAST_SHA1_START,
  SSE3_FAST_SHA1_PROCESS,
  SSE3_FAST_SHA1_FINISH
};


VOID 
EFIAPI
SSE3_FAST_SHA1_START(
  sha1_state *s
){
  sha1_start(s);
}

VOID
EFIAPI
SSE3_FAST_SHA1_PROCESS(
  sha1_state *s, const void *p, size_t len
){
  sha1_process(s, p, len);
}

VOID
EFIAPI
SSE3_FAST_SHA1_FINISH(
  sha1_state *s, uint32_t hash[5]
){
  sha1_finish(s, hash);
}

VOID SpeedTest() {
  // Benchmark speed
  int i;
  UINT64  HzIn100ms, Frequency;
  uint32_t state[5] = {};
  uint32_t block[16] = {};

  const int N = 10000000*10;  //10 Millions blocks
  UINT64  timeStamp, SpeedInMB; 

  timeStamp = AsmReadTsc();
  gBS->Stall(100*1000);  
  timeStamp = AsmReadTsc() - timeStamp;
  HzIn100ms = timeStamp;
  HzIn100ms *= 10;  //revert to 1000ms = 1s.
  Frequency = HzIn100ms / 1000;
//  Print (L"Elapse time(stall 0.1s): %d \n", timeStamp/Frequency);

  timeStamp = AsmReadTsc();
  for (i = 0; i < N; i++) {
    sha1_compress(state, (uint8_t *)block);
  }
  timeStamp = AsmReadTsc() - timeStamp;

  Print (L"10 Millions operation on 64-byte block. Elapse time(ms): %d \n", timeStamp/Frequency);
  SpeedInMB = ((UINT64)N * sizeof(block) * Frequency) / timeStamp;

  Print (L"(SHA-1 with SSE3 optimized)Speed: %d.%d MB/s \n", SpeedInMB/1000, SpeedInMB%1000 );
  return;
}



/**
  The user Entry Point for Application. The user code starts with this function
  as the real entry point for the application.

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.  
  @param[in] SystemTable    A pointer to the EFI System Table.
  
  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
	EFI_HANDLE                  Handle;
  EFI_STATUS  Status;
  EFI_GUID  gFastSha1ImplementationProtocolGuid = EDKII_FAST_SHA1_IMP_PROTOCOL_GUID;

  self_test();

  Handle = NULL;
  SpeedTest();
  Status = gBS->InstallMultipleProtocolInterfaces (
                   &Handle,
                   &gFastSha1ImplementationProtocolGuid, &mFastSha1Implementation,
                   NULL
                   );

  return EFI_SUCCESS;
}
