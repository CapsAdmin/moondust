package.path = package.path .. ";../src/?.lua"

local asm = require("assembler")
local util = require("util")
local ffi = require("ffi")

local reg = asm.reg

local a = asm.assembler()

do
    local msg = "hello world!\n"

    local STDOUT_FILENO = 1
    local WRITE = 1

    a:mov(reg.rax, WRITE)
    a:mov(reg.rdi, STDOUT_FILENO)
    a:mov(reg.rsi, util.object_to_address(msg))
    a:mov(reg.rdx, #msg)
    a:syscall()

    a:ret()
end

local mcode = a:compile()
local func = ffi.cast("void (*)()", mcode)

func()