#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

	int buffer[0x10];
	int overflowIt[0x10];

	char* e = getenv("PWD");
	if (e == NULL){
		printf("Where are you? :( \n");
		exit(1);
	}
    memset(overflowIt, '\x00', 0x40);

	strcpy((char*)buffer, e);
	if ( overflowIt[2] == 0x01020304)
		printf("Congratulations, you pwned it!\n");
	else
		printf("Please try again, you got 0x%08X\n", overflowIt[2]);
	return 0;
}