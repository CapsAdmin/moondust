package.path = package.path .. ";./src/?.lua"

local asm = require("assembler")
local util = require("util")
local ffi = require("ffi")

local r = asm.reg

local a = asm.assembler()

do
    local msg = "hello world!\n"

    local STDOUT_FILENO = 1 
    local WRITE = jit.os == "Linux" and 1 or 0x2000004

    a:mov(r.rax, WRITE)
    a:mov(r.rdi, STDOUT_FILENO)
    a:mov(r.rsi, util.object_to_address(msg))
    a:mov(r.rdx, #msg)
    a:syscall()

    a:ret()
end

local mcode = a:compile()
local func = ffi.cast("void (*)()", mcode)

func()