#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

//éviter de suivre un plan initiale
// travailler par itération : ecrire un code le plus simple possible et le tester avec IDA pour trouver la technique suivante

int secret = 584875;

int checkArg(char* arg) {
    int len = strlen(arg);
    if (len > 8) {
        printf("Error: Number must be 8 digits or less.\n");
        return 0;
    }

    for (int i = 0; i < len; i++) {
        if (!isdigit(arg[i])) {
            printf("Error: Input must be a number.\n");
            return 0;
        }
    }
    return 1;
}

int checkDebuggeri(){
	char secret2[5] = {0xA5, 0x5B, 0x48, 0x54, 0x5A};
	char secret3[5] = {0x5A, 0x54, 0x48, 0x5B, 0xA5};
	for(int i=0; i<5;i++){
			secret2[i] = secret3[i]^0x48;
	}
	int r = 0;
  for (int i = 0; i < 5; i++) {
	  int decimal = (unsigned int) secret2[i] ;
	r+=decimal;
  }
  r= r*r;
  return r*r;
}

// cette methode fait appel à checkDebuggeri pour générer la clé 
_declspec(noinline) int encrypt(int *digits, int count) {
	 int x;
	 int a;
	__asm{
	mov eax, secret
	call checkDebuggeri
	mov x, eax
	}
	return x+1;
}

void compare(int key, int key1){
	if(key==key1){
	printf("Bingo Vous avez trouve la clef");
	}else{
	printf("Nope, C est pas la bonne ! %d . ",key1);
	ExitProcess(0);
	}
}

int main(int argc, char* argv[]) 
{
	BOOL isDebugged = TRUE;
	// key pour brouiller les informations principales i.e. cle + message
	// on prend n'import quoi car on va faire XOR deux fois donc il reste tjr le cle etle message: (x XOR y) XOR y = x
	char key = 22;

	//check number of arguments
    if (argc != 2) {
        printf("Error: Nombre de paramètre dépassé");
        return 1;
    }

    //check program arguments
    if (!checkArg(argv[1])) {
        return 1;
    }
	
	// encrypted with https://www.stringencrypt.com (v1.4.0) [C/C++]
	// valeur chiffree XOR key
	wchar_t message[11] = { 0x600E^key, 0x800B^key, 0x200A^key, 0xE00A^key, 0x2008^key, 0xE008^key, 0x3FFD^key, 0x8005^key,
                        0xA003^key, 0x0005^key, 0xDFF4^key };
	
	// decrypte de message
	for (unsigned int CLPyb = 0, weqEr = 0; CLPyb < 11; CLPyb++)
	{
		// ici on XOR encore une fois pour retourner la bonne valeur
		weqEr = message[CLPyb]^key;
		weqEr += CLPyb;
		weqEr = (((weqEr & 0xFFFF) >> 13) | (weqEr << 3)) & 0xFFFF;
		weqEr += CLPyb;
		message[CLPyb] = weqEr;
	}

	// Check if Debugger is detected  -- mode debug au button vert
	if (IsDebuggerPresent()) {
		printf("Debugger detected\n");
        ExitProcess(0);
    }

	// Checking for the presence of a debugger by using a software interrupt (INT 1)
	__try {
		__asm {
			pushfd
			or dword ptr[esp], 0x100 // set the Trap Flag 
			popfd                    // Load the value into EFLAGS register
			nop
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		// If an exception has been raised --> debugger is not present
		isDebugged = FALSE;
	}
	if (isDebugged)
	{
		printf("Debugger detected\n");
		ExitProcess(0);
	}

	// Check if Remote Debugger is detected 
	if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged )){ 
		if (isDebugged ){
			printf("Remote Debugger detected");
			ExitProcess(0);
		}
	}
	int entiers[5] = {54,4,7,5,12};
	//ici on génère la clé secrète !!! c'est pas un encrypt
	int variable = encrypt(entiers, strlen(argv[1]));
	compare(variable, atoi(argv[1]));
		
	//while(1);
    return 0;
}