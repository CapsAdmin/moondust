package.path = package.path .. ";../src/?.lua"

-- this requires that lua can execute gcc, as and objdump (so typically in a unix envionment with dev tools)

local gas = require("gas")

print("single line:")
gas.dump_asm("mov rcx, 10")
print("multiple lines:")
gas.dump_asm([[
	mov eax,4
	mov ebx,1
	mov ecx,edi
	mov edx,eax
	int 0x80
	mov eax,1
	mov ebx,0
	int 0x80
]])