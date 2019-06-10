package.path = package.path .. ";./src/?.lua"

local asm = require("assembler")
local util = require("util")
local ffi = require("ffi")

local mcode = asm.compile(function(a)
	local msg = "hello world!\n"

	local STDOUT_FILENO = 1
	local WRITE = 1

	mov(rax, WRITE)
	mov(rdi, STDOUT_FILENO)
	mov(rsi, util.object_to_address(msg))
	mov(rdx, #msg)
	syscall()
	inc(r12)

	ret()
end)

local func = ffi.cast("void (*)()", mcode)

func()