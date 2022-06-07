#include "utils.h"
#include <cstdio>
#include <stdlib.h>
#include <conio.h>

void read_input(int& length, unsigned char** password)
{

	char ch;
	int len = 0;
	fflush(stdin);
	do
	{
		ch = _getch();
		if (ch == 13 || ch == 10) //carriage return and line ffed
			break;
		printf("%c",ch);
		(*password) = (unsigned char*)realloc(*password, len + 1);

		if ((*password) == NULL)
			return ;
		(*password)[len++] = ch;


	} while (ch != 13 && ch != 10);
	length = len;

	printf("\n");
	return ;
}
