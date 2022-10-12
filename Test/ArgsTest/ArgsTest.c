#include <Windows.h>
#include <stdio.h>



int main(int argc, char* argv[]) {

	printf("\n\t#########################################[ARGS TEST]#########################################\n\n");

	if (argc > 1) {
		for (size_t i = 1; i < argc; i++) {
			printf("[i] argv[%d] : %s \n", i, argv[i]);
		}
	}
	else {
		printf("[-] No Arguments Where Passed In \n");
	}
	
	printf("\n\t#########################################[ARGS TEST]#########################################\n\n");

	MessageBoxA(NULL, "DONE !", "DONE !", MB_OK);

	return 0;
}
