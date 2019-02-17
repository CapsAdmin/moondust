package.path = package.path .. ";../src/?.lua"

local asm = require("assembler")
local util = require("util")
local ffi = require("ffi")

local mcode = asm.compile(function(a)
	local msg = "hello world!\n"

	local STDOUT_FILENO = 1
	local WRITE = 1

	mov(r12, rdi)

	label("loop")
		mov(rax, WRITE)
		mov(rdi, STDOUT_FILENO)
		mov(rsi, util.object_to_address(msg))
		mov(rdx, #msg)
		syscall()
		inc(r12)
	cmp(r12, 10)

	jne(label.loop)

	jmp(label["no!"])
		mov(rax, 777)
	label("no!")

	-- yes!
	mov(rax, 1337)

	ret()
end)

local func = ffi.cast("uint64_t (*)(uint64_t)", mcode)

print(func(0))