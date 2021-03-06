-- this requires that lua can execute gcc, as and objdump (so typically in a unix envionment with dev tools)

local gas = require("moondust.gas")

print(gas.dump_asm("mov [rax + 4], eax"))

print("single line:")
print(gas.dump_asm("mov rcx, 10"))
print("multiple lines:")
print(gas.dump_asm([[
	mov eax,4
	mov ebx,1
	mov ecx,edi
	mov edx,eax
	int 0x80
	mov eax,1
	mov ebx,0
	int 0x80
]]))


print(gas.dump_asm("push 0"))

print(gas.dump_asm("call 0xdeadb"))
print(gas.dump_c([[
#include <stdio.h>

int main(void) {
	//int (*lol)(const char*) = 1;
	int test = puts("hello world");
}
]]))
