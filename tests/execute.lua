package.path = package.path .. ";./src/?.lua"

local ffi = require("ffi")
local gas = require("moondust.gas")
local x86_64 = require("moondust.x86_64")
local asm = require("moondust.assembler")
local r = asm.reg

local function check(res, op, target, msg)
    if op == "==" then
        if res == target then

        else
            msg = msg:gsub("TARGET", tostring(target))
            print(msg .. " got " .. tostring(res) .. " instead")
        end
    else
        error("unhanled op " .. op, 2)
    end
end

do -- 2+5 memory
    local a = asm.assembler()
    local res = ffi.new("int[1]", 2)

    do
        a:mov(r.rax, 3)
        a:add(r(asm.object_to_address(res)), r.rax)

        a:ret()
    end

    local mcode = a:compile()
    local func = ffi.cast("int (*)()", mcode)
    check(func(), "==", 3, "rax should be TARGET")
    check(res[0], "==", 5, "memory destination should be TARGET")
end

do -- 2+5 registry
    local a = asm.assembler()
    do
        a:mov(r.rax, 3)
        a:add(r.rax, 2)

        a:ret()
    end

    local mcode = a:compile()
    local func = ffi.cast("int (*)()", mcode)

    local res = func()
    check(res, "==", 5, "rax should be TARGET")
end

do -- 2+5 memory with offset
    local a = asm.assembler()
    local res = ffi.new("int[1]", 2)

    do
        a:mov(r.rdx, asm.object_to_address(res) - 1024)

        a:mov(r.rax, 3)
        a:add(r.rdx + 1024, r.rax)

        a:ret()
    end

    local mcode = a:compile()
    local func = ffi.cast("void (*)()", mcode)
    func()
    check(res[0], "==", 5, "int should be TARGET")
end


do -- 2+5 double
    local a = asm.assembler()

    local res = ffi.new("double[1]", 0)
    do
        a:movsd(r.xmm0, r(asm.object_to_address(ffi.new("double[1]", 3))))
        a:addsd(r.xmm0, r(asm.object_to_address(ffi.new("double[1]", 2))))
        a:movsd(r(asm.object_to_address(res)), r.xmm0)

        a:ret()
    end

    local mcode = a:compile()

    local func = ffi.cast("int (*)()", mcode)

    func()

    check(res[0], "==", 5, "rax should be TARGET")
end


do -- 3*2 double
    local a = asm.assembler()

    local res = ffi.new("double[1]", 0)
    do
        a:movsd(r.xmm0, r(asm.object_to_address(ffi.new("double[1]", 3))))
        a:mulsd(r.xmm0, r(asm.object_to_address(ffi.new("double[1]", 2))))
        a:movsd(r(asm.object_to_address(res)), r.xmm0)

        a:ret()
    end

    local mcode = a:compile()

    local func = ffi.cast("int (*)()", mcode)

    func()

    check(res[0], "==", 6, "rax should be TARGET")
end

do -- left shift
    local a = asm.assembler()
    do
        a:mov(r.rax, 0xa)
        a:shl(r.rax, 2)
        a:ret()
    end

    local mcode = a:compile()

    local func = ffi.cast("uint32_t (*)()", mcode)

    local res = func()
    check(res, "==", 0x28, "rax should be TARGET")
end

local function generic_output(output, assemble)
    local a = asm.assembler()
    assemble(a, output)

    local mcode = a:compile()
    local func = ffi.cast("void (*)()", mcode)
    func()
    return output[0]
end

local function generic_return(assemble)
    local a = asm.assembler()

    assemble(a)

    local mcode = a:compile()

    local func = ffi.cast("uint64_t (*)()", mcode)

    return func()
end

local x,y,z = 10.5, 23, 123
check(math.sqrt(x*x + y*y + z*z), "==", generic_output(ffi.new("double[1]"), function(a, output)
    local input = ffi.new("double[3]", x,y,z)
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
end, "sqrt(x*x + y*y + z*z) should be TARGET"))


check(1337ull, "==", generic_return(function(a)
    a:push(ffi.new("uint32_t", 1337))
    a:pop(r.rax)
    a:ret()
end), "should be TARGET")

check(1337ull, "==", generic_return(function(a)
    a:mov(r.rax, ffi.new("uint64_t", 1337))

    a:jmp("no!")
        a:mov(r.rax, 777)
        a:label("no!")
    a:ret()
end), "should be TARGET")

local function address_of(name)
    ffi.cdef("void *" .. name) return asm.object_to_address(ffi.C[name])
end
