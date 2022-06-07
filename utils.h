#pragma once
#define ERR_BASE	100
#define ERR_MEM		(ERR_BASE + 1)
#define ERR_IO		(ERR_BASE + 2)

#define MESSAGE_TYPE_HANDSHAKE	0
#define MESSAGE_TYPE_CHAT		1

#define ALICE	0
#define BOB		1

void read_input(int& length, unsigned char** password);