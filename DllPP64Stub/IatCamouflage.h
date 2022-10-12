/*
	since this stub is using api hashing & removing crt functions, the low number of imported functions is pretty much a ioc
	so i had to come up with a list of non-blacklisted api's that can change the modules & functions used (although not executed)

*/

#pragma once
#include <Windows.h>
#include <synchapi.h>



LPVOID FunctionToReturnSomething(int i, int* pi, int* px, int* py) {
	int x, y;
	x = y = i++;
	y += x * i;
	x = i + 100;
	i = i + i / 2;
	*pi = i;
	*px = x;
	*py = y;
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024);
}



BOOL CamouflageImports(int i) {
	int x, y;
	x = y = i++;
	y += x * i;
	x = i + 100;
	i = i + i / 2;

	LPVOID p = FunctionToReturnSomething(i, &i, &x, &y);
	

	//i : 577 || x : 485 || y : 148224
	//PRINT(L"[i] i : %d || x : %d || y : %d \n", i, x, y);

	if (i == 577) {
		x += 1;
		x -= 1;
		if (y * 2 == y + 148224) {
			if (GetLastError() == ERROR_IPSEC_IKE_SECLOADFAIL) {
				// we dont care about anything here, we just want these to be imported to our iat
				ReleaseSRWLockExclusive(NULL);
				ReleaseSRWLockShared(NULL);
				SetCriticalSectionSpinCount(NULL, NULL);
				TryAcquireSRWLockExclusive(NULL);
				WakeAllConditionVariable(NULL);
				SetUnhandledExceptionFilter(NULL);
				UnhandledExceptionFilter(NULL);
				CheckMenuItem(NULL, NULL, NULL);
				GetMenu(NULL);
				GetSystemMenu(NULL, NULL);
				GetMenuItemID(NULL, NULL);
				EnableMenuItem(NULL, NULL, NULL);
				MessageBeep(NULL);
				GetLastError();
				MessageBoxW(NULL, NULL, NULL, NULL);
				MessageBoxA(NULL, NULL, NULL, NULL);
				UpdateWindow(NULL);
				GetWindowContextHelpId(NULL);
			}
			else {
				HeapFree(GetProcessHeap(), 0, p);
			}
		}
	}


	return TRUE;

}