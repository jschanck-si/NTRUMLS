#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <windows.h>
#include <Wincrypt.h>
#include "randombytes.h"



void randombytes(unsigned char *x, unsigned long long xlen)
{
	int i;
	srand(time(NULL) - 3);
	HCRYPTPROV hCryptProv = NULL;

	if (CryptAcquireContext(&hCryptProv,               // handle to the CSP
		NULL,                  // container name
		NULL,                      // use the default provider
		PROV_RSA_FULL,             // provider type
		0))                        // flag values
		;
	else
	{
		if (GetLastError() == NTE_BAD_KEYSET)
		{
			if (CryptAcquireContext(
				&hCryptProv,
				NULL,
				NULL,
				PROV_RSA_FULL,
				CRYPT_NEWKEYSET))
				;
			else
			{
				printf("Could not create a new key container.\n");
				exit(1);
			}
		}
		else
		{
			printf("A cryptographic service handle could not be "
				"acquired.\n");
			exit(1);
		}

	} // End of else.
	if (CryptGenRandom(hCryptProv, xlen, x))
		;
	else
	{
		printf("Error during CryptGenRandom.\n");
		exit(1);
	}
//	printf("window random string: ");
//	for (i = 0; i < xlen; i++)
//		printf("%2x ", x[i]);
//	printf("\n");
	Sleep(1);
}
