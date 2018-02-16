# Background of The work 

* To compare the SHA1/SHA-256 performance in different implementation, different optimization flags and with different compilers(GCC48/GCC5). See how the performance difference in UEFI(Pre-boot environment).
* Bottom-line: As a UEFI developer, while using these CPU intensive algorithms, we need to take into account the
performance between them.

# Description of the work.
* SHA-1 Performance
Experiement 1:<br>
	Gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.6) <br>
	CPU: Intel Kabylake E3-1505L v6. 2.5 GHz <br>
	Optimization flags: -Ofast <br>
	Test case: 10-million operations on 64-byte block computation.<br>
	SHA-1 in different implementations: <br>
		* Christophe Devine's version : 	436.889 MB/s<br>
		* Nayuki sha1 fast in C : 			433.221 MB/s<br>
		* Nayuki sha1 fast in Assembly :	449.777 MB/s<br>
		* With Intel SSE3 implementation :	601.800 MB/s<br>

-Experiement 2:
-	Gcc version 4.8
-	Gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.6) 
-	CPU: Intel Kabylake E3-1505L v6. 2.5 GHz
-	Optimization flags: -Ofast
-	Test case: 10-million operations on 64-byte block computation.
-	SHA-1 SSE3 in GCC 4.8 vs GCC 5.4: 
-		* GCC 4.8 :							569.889 MB/s
-		* GCC 5.2 :							597.710 MB/s

-Experiement 3:
-	Gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.6) 
-	CPU: Intel Kabylake E3-1505L v6. 2.5 GHz
-	Test case: 10-million operations on 64-byte block computation.
-	SHA-1 SSE3 with different optimization flag added to Compiler: 
-		* -Ofast :							597.733 MB/s
-		* -Os :								583.531 MB/s
-			Note: -Os is the default flag in Tiano EDK-II, used to reduce the size of object files.
-		* -O2 :								598.150 MB/s
-		* -O1 :								583.229 MB/s
-		* -O0 :								563.159 MB/s
 


* SHA-2(SHA-256) Performance
-Experiement 1:
-	Gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.6) 
-	CPU: Intel Kabylake E3-1505L v6. 2.5 GHz
-	Optimization flags: -Ofast
-	Test case: 10-million operations on 64-byte block computation.
-	SHA-256 in different implementations: 
-		* Without SSE3 instruction benefit:			158.712 MB/s
-		* With SSE3 implementation used in Linux:	260.472 MB/s

Experiement 2:
-	Gcc version 4.8
-	Gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.6) 
-	CPU: Intel Kabylake E3-1505L v6. 2.5 GHz
-	Optimization flags: -Ofast
-	Test case: 10-million operations on 64-byte block computation.
-	SHA-256 SSE3 in GCC 4.8 vs GCC 5.4: 
-		* GCC 4.8 :							260.128 MB/s
-		* GCC 5.4 :							259.254 MB/s

-Experiement 3:
-	Gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.6) 
-	CPU: Intel Kabylake E3-1505L v6. 2.5 GHz
-	Test case: 10-million operations on 64-byte block computation.
-	SHA-256 SSE3 with different optimization flag added to compiler: 
-		* -Ofast :							260.319 MB/s
-		* -Os :								260.292 MB/s
-			Note: -Os is the default flag in Tiano EDK-II, used to reduce the size of object files.
-		* -O2 :								260.250 MB/s
-		* -O1 :								259.720 MB/s
-		* -O0 :								255.295 MB/s

Reference:
Nayuki,
https://www.nayuki.io/

SHA-1, Christophe Devine's version
http://ecee.colorado.edu/~ecen5653/ecen5653/code/example-3/sha1.c

Intel SSE3 implementation,
Improving the Performance of the Secure Hash Algorithm (SHA-1)
https://software.intel.com/en-us/articles/improving-the-performance-of-the-secure-hash-algorithm-1

