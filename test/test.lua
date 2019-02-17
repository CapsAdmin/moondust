package.path = package.path .. ";../src/?.lua"

-- this requires that lua can execute gcc, as and objdump (so typically in a unix envionment with dev tools)

local gas = require("gas")
local util = require("util")
local x86_64 = require("x86_64")
local asm = require("assembler")
local util = require("util")

gas.dump_asm("mov (0xdeadbeef), %eax")

do return end

print(util.string_binformat(x86_64.encode("mov", asm.reg"rcx", asm.reg"rax"()).bytes, 16, "  ", true))

print(asm.reg"rax"())
print(asm.reg"rax" + 1)
print(asm.reg"rax" + asm.reg"rcx" * 2 + 1)

--[[
{reg = "rax"}
{reg = "rax", disp = 15}

{reg = "rax", index = "rbx"}
{reg = "rax", index = "rbx", scale = 2}
{reg = "rax", index = "rbx", scale = 2, disp = 15}

{disp = 0x1234}
{disp = 0x1234, index = "rbx"}
{disp = 0x1234, index = "rbx", scale = 2}]]