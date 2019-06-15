local ffi = require("ffi")
local asm = require("moondust.assembler")

local r = asm.reg

local a = asm.assembler()

local x,y,z = 10.5, 23, 123
print(math.sqrt(x*x + y*y + z*z))


local input = ffi.new("double[3]", x,y,z)
local output = ffi.new("double[1]", 0)

do
    a:movsd(r.xmm0, r(asm.object_to_address(input + 0)))
    a:movsd(r.xmm1, r(asm.object_to_address(input + 1)))
    a:movsd(r.xmm2, r(asm.object_to_address(input + 2)))

    a:mulsd(r.xmm0, r.xmm0)
    a:mulsd(r.xmm1, r.xmm1)
    a:mulsd(r.xmm2, r.xmm2)

    a:addsd(r.xmm2, r.xmm1)
    a:addsd(r.xmm1, r.xmm0)

    a:sqrtsd(r.xmm0, r.xmm0)

    a:movsd(r(asm.object_to_address(output)), r.xmm0)

    a:ret()
end

local mcode = a:compile()

local func = ffi.cast("void (*)()", mcode)

func()

print(output[0])