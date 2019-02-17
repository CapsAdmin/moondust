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

    a:mov(reg.r12, reg.rdi)

    a:create_label("loop")
        a:mov(reg.rax, WRITE)
        a:mov(reg.rdi, STDOUT_FILENO)
        a:mov(reg.rsi, util.object_to_address(msg))
        a:mov(reg.rdx, #msg)
        a:syscall()
        a:inc(reg.r12)
    a:cmp(reg.r12, 10)

    a:jne(a:virtual_label("loop"))

    a:jmp(a:virtual_label("no!"))
        a:mov(reg.rax, 777)
    a:create_label("no!")

    -- yes!
    a:mov(reg.rax, 1337)

    a:ret()
end

local mcode = a:compile()
local func = ffi.cast("uint64_t (*)(uint64_t)", mcode)

print(func(0))