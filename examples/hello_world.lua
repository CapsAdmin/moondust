local ffi = require("ffi")
local asm = require("moondust.assembler")
local util = require("moondust.util")

local mcode = asm.compile(function(a)
	local msg = "hello world!\n"

	local STDOUT_FILENO = 1
    local WRITE = jit.os == "Linux" and 1 or 0x2000004

	mov(rax, WRITE)
	mov(rdi, STDOUT_FILENO)
	mov(rsi, util.object_to_address(msg))
	mov(rdx, #msg)
	syscall()

	ret()
end)

local func = ffi.cast("void (*)()", mcode)

func()