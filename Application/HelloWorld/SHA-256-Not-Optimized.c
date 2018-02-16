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
#include "sha256.h"

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
  


struct TestCase {
	uint32_t answer[8];
  	char *msg;
};

#define TESTCASE(a,b,c,d,e,f,g,h,msg) {{UINT32_C(a),UINT32_C(b),UINT32_C(c),UINT32_C(d),UINT32_C(e),UINT32_C(f),UINT32_C(g),UINT32_C(h)}, msg}

struct TestCase testCases[] = {
		TESTCASE(0xE3B0C442,0x98FC1C14,0x9AFBF4C8,0x996FB924,0x27AE41E4,0x649B934C,0xA495991B,0x7852B855, ""),
		TESTCASE(0xCA978112,0xCA1BBDCA,0xFAC231B3,0x9A23DC4D,0xA786EFF8,0x147C4E72,0xB9807785,0xAFEE48BB, "a"),
		TESTCASE(0xBA7816BF,0x8F01CFEA,0x414140DE,0x5DAE2223,0xB00361A3,0x96177A9C,0xB410FF61,0xF20015AD, "abc"),
		TESTCASE(0xF7846F55,0xCF23E14E,0xEBEAB5B4,0xE1550CAD,0x5B509E33,0x48FBC4EF,0xA3A1413D,0x393CB650, "message digest"),
		TESTCASE(0x71C480DF,0x93D6AE2F,0x1EFAD144,0x7C66C952,0x5E316218,0xCF51FC8D,0x9ED832F2,0xDAF18B73, "abcdefghijklmnopqrstuvwxyz"),
		TESTCASE(0x248D6A61,0xD20638B8,0xE5C02693,0x0C3E6039,0xA33CE459,0x64FF2167,0xF6ECEDD4,0x19DB06C1, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
	};

void print_hash(uint8_t hash[])
{
   UINT8 idx;
  
   for (idx=0; idx < 32; idx++)
      Print(L"%02x",hash[idx]);
   Print(L"\n");
}

void reorder_hash(uint8_t hash[])
{
	int i;
	uint32_t temp;
	for(i=0;i<8;i++){
		temp = ((uint32_t)hash[i*4+0])<<24;
		temp |= ((uint32_t)hash[i*4+1])<<16;
		temp |= ((uint32_t)hash[i*4+2])<<8;
		temp |= ((uint32_t)hash[i*4+3])<<0;
		*(uint32_t*)&hash[i*4] = temp;
	}

}

UINT32 self_test(void)
{
  int res = 0;
  unsigned int i;
  for (i = 0; i < sizeof(testCases) / sizeof(testCases[i]); ++i) {
    		UINT8 hash[32];
			struct TestCase *tc = &testCases[i];

			SHA256_CTX ctx;

			sha256_init(&ctx); // Init
			
			sha256_update(&ctx, (uint8_t*)tc->msg, AsciiStrLen((const CHAR8 *)tc->msg)); // Update
   			sha256_final(&ctx, hash); // Final
   			reorder_hash(hash);
   			if (CompareMem(hash, tc->answer, sizeof(tc->answer)) != 0) {
        		DEBUG((EFI_D_ERROR, "Test %d failed!\n", i));
        		Print (L"mismatch, Test Case %d\n", i);
				res = -1;
			}
	}
	return res;
}

VOID SpeedTest() {
  // Benchmark speed
  int i;
  UINT64  HzIn100ms, Frequency;
  uint32_t block[16] = {};
  SHA256_CTX ctx;
  sha256_init(&ctx);
  
  const int N = 10000000*10;  //10 Millions blocks
  UINT64  timeStamp, SpeedInMB; 

  timeStamp = AsmReadTsc();
  gBS->Stall(100*1000);  
  timeStamp = AsmReadTsc() - timeStamp;
  HzIn100ms = timeStamp;
  HzIn100ms *= 10;  //revert to 1000ms = 1s.
  Frequency = HzIn100ms / 1000;
  Print (L"Benchmarking SHA-256(Not optimized) speed. \n");

  timeStamp = AsmReadTsc();
  for (i = 0; i < N; i++){
    sha256_transform(&ctx, (uint8_t *)block);  
  }
  timeStamp = AsmReadTsc() - timeStamp;

  Print (L"10 Millions operation on 64-byte block. Elapse time(ms): %d\n", timeStamp/Frequency);
  SpeedInMB = ((UINT64)N * sizeof(block) * Frequency) / timeStamp;

  Print (L"SHA-256: %d.%d MB/s \n", SpeedInMB/1000, SpeedInMB%1000 );
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
  self_test();
  SpeedTest();
  return EFI_SUCCESS;
}
