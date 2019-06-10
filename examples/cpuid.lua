package.path = package.path .. ";./src/?.lua"

local asm = require("assembler")
local util = require("util")
local ffi = require("ffi")

local mcode = asm.compile(function(a)
    push(rbx)
    mov(edi, eax)
    cpuid()
    mov(eax, rsi + 0)
    mov(ebx, rsi + 4)
    mov(ecx, rsi + 8)
    mov(edx, rsi + 12)
    pop(rbx)
    ret()
 end)

local cpuid = ffi.cast("void(*)(int, void *)", mcode)

local cpuid_t = ffi.typeof[[struct {
    uint32_t eax, ebx, ecx, edx;
} __attribute__((packed))]]

local id = ffi.new(cpuid_t)
local name = ffi.new[[
   union {
     struct { uint32_t ebx, edx, ecx; } __attribute__((packed)) reg;
     char string[12];
   }
 ]]

cpuid(0x0, id)
name.reg.ebx, name.reg.ecx, name.reg.edx = id.ebx, id.ecx, id.edx
local vendor = ffi.string(name.string, 12)
cpuid(0x1, id)
local family = bit.band(bit.rshift(id.eax, 8), 0xf)
local extfamily = bit.band(bit.rshift(id.eax, 20), 0xff)
local model  = bit.band(bit.rshift(id.eax, 4), 0xf)
local extmodel = bit.band(bit.rshift(id.eax, 16), 0xf)

-- XXX This is a simplified CPU ID formatting function.
--     See Intel CPUID instruction documentation for full algorithm.
--     (Could alternatively grovel this from /proc/cpuinfo.)
cpu_model = ("%s-%X-%X%X"):format(vendor, family, extmodel, model)

print(cpu_model)