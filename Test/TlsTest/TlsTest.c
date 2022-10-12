#include <Windows.h>
#include <stdio.h>

// https://github.com/kevinalmansa/TLS_Examples/tree/master/TLS_Examples/TLS_Static


#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback_func")

void	tls_callback1(PVOID hModule, DWORD dwReason, PVOID pContext);
void	tls_callback2(PVOID hModule, DWORD dwReason, PVOID pContext);


#ifdef _WIN64
#pragma const_seg(".CRT$XLB")
EXTERN_C const
#else
#pragma data_seg(".CRT$XLB")
EXTERN_C
#endif

PIMAGE_TLS_CALLBACK tls_callback_func = (PIMAGE_TLS_CALLBACK)tls_callback1;

#ifdef _WIN64
#pragma const_seg()
#else
#pragma data_seg()
#endif //_WIN64



#ifdef _WIN64
#pragma const_seg(".CRT$XLC")
EXTERN_C const
#else
#pragma data_seg(".CRT$XLC")
EXTERN_C
#endif

PIMAGE_TLS_CALLBACK tls_callback_func2 = (PIMAGE_TLS_CALLBACK)tls_callback2;

#ifdef _WIN64
#pragma const_seg()
#else
#pragma code_seg()
#endif //_WIN64




/*****************************************************************************
First TLS Callback
Set above to segment CRT$XLB
******************************************************************************/
void	tls_callback1(PVOID hModule, DWORD dwReason, PVOID pContext)
{
	if (dwReason == DLL_THREAD_ATTACH) {
		// This will be loaded in each DLL thread attach
		MessageBox(0, TEXT("TLS Callback 1: Thread Attach Triggered"), TEXT("TLS"), 0);
	}

	if (dwReason == DLL_PROCESS_ATTACH) {
		MessageBox(0, TEXT("TLS Callback: Process Attach Triggered"), TEXT("TLS"), 0);
		// DEBUG - Help understand how this is being stored in memory.
		printf("TLS Callback Addresses:\n    Function Address: %p\n    CRT Callback Address: %p\n",
			tls_callback1, &tls_callback_func);
	}
}


/*****************************************************************************
Second TLS Callback
Set above to segment CRT$XLC
******************************************************************************/
void	tls_callback2(PVOID hModule, DWORD dwReason, PVOID pContext)
{
	if (dwReason == DLL_THREAD_ATTACH) {
		// This will be loaded in each DLL thread attach
		MessageBox(0, TEXT("TLS Callback 2: Thread Attach Triggered"), TEXT("TLS_Thread"), 0);
	}

	if (dwReason == DLL_PROCESS_ATTACH) {
		MessageBox(0, TEXT("TLS Callback 1: Process Attach Triggered"), TEXT("TLS_Process"), 0);
		// DEBUG - Help understand how this is being stored in memory.
		printf("TLS Callback Addresses:\n    Function Address: %p\n    CRT Callback Address: %p\n",
			tls_callback2, &tls_callback_func2);
	}
}


/*****************************************************************************
The actual main()
Code in the TLS Callbacks set above will execute BEFORE the main.
Setting a breakpoint here will not stop the callbacks from executing first.
******************************************************************************/
int main()
{
	printf("Main():\n    Hello World\n");
	system("pause");
	return 0;
}
