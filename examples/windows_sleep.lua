local ffi = require("ffi")
local asm = require("moondust.assembler")

local r = asm.reg

local a = asm.assembler()
local ms = 2000
do
    a:mov(r.rcx, ms)
    a:mov(r.rdx, asm.address_of("Sleep", "Kernel32.dll"))
    a:call(r.rdx)
    a:ret()
end

local mcode = a:compile()
local func = ffi.cast("uint64_t (*)()", mcode)

print("sleeping for "..(ms/1000).." seconds..")
local t = os.clock()
func()
print("slept for " .. (os.clock() - t) .. " seconds")