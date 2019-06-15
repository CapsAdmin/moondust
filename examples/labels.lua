local ffi = require("ffi")
local asm = require("moondust.assembler")

local mcode = asm.compile(function(a)
	local msg = "hello world!\n" _G.msg_ref = msg

	local STDOUT_FILENO = 1
	local WRITE = jit.os == "Linux" and 1 or 0x2000004
	local i = r10

	mov(i, rdi)

	label("loop") do
		mov(rax, WRITE)
		mov(rdi, STDOUT_FILENO)
		mov(rsi, asm.object_to_address(msg))
		mov(rdx, #msg)
		syscall()
		inc(i)

		cmp(i, 10)
		jne("loop")
	end

	jmp("no!")
		mov(rax, 777)
	label("no!")

	-- yes!
	mov(rax, 1337)

	ret()
end)

local func = ffi.cast("uint64_t (*)(uint64_t)", mcode)

print(tonumber(func(0)))