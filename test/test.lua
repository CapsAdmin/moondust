package.path = package.path .. ";./src/?.lua"

local gas = require("gas")
local util = require("util")
local x86_64 = require("x86_64")
local ffi = require("ffi")
local asm = require("assembler")
local r = asm.reg

do
    local function compare(str, name, ...)
        local data = x86_64.encode(name, ...)

        local strtbl = {} for i,v in ipairs({...}) do strtbl[i] = tostring(v) end
        --print(name .. " " .. table.concat(strtbl, ", ") .. " | " .. table.concat(data.metadata.opcode, " "))
        local str, ok = gas.dump_asm(str, function(bytes) return util.string_binformat(bytes, 15, "  ", true) end, data.bytes)
        if not ok then
            print("======================")
            local info = debug.getinfo(2)
            print(info.source:sub(2) .. ":" .. info.currentline)
            data.metadata:dump()
            print(str)
            print("======================")
        end
    end


    compare("mov r12, rdi", 				"mov", r.r12, r.rdi)
    compare("mov r12, [0x1]", 				"mov", r.r12, r(0x1))
    compare("inc r12", 			    	    "inc", r.r12)
    compare("mov rcx, rbx", 				"mov", r.rcx, r.rbx)
    compare("mov rcx, [0x1]", 				"mov", r.rcx, r(0x1))
    compare("mov ecx, [0x1]", 				"mov", r.ecx, r(0x1))
    compare("mov ax, [0x1]", 				"mov", r.ax, r(0x1))
    compare("mov al, [0x1]", 				"mov", r.al, r(0x1))
    compare("mov rcx, [0xdead]", 			"mov", r.rcx, r(0xdead))
    compare("mov rcx, [rbx]", 				"mov", r.rcx, r(r.rbx))
    compare("mov [rcx], rbx", 				"mov", r(r.rcx), r.rbx)
    compare("mov rcx, [rbx*1]", 			"mov", r.rcx, r.rbx * 1)
    compare("mov rcx, [2*rbx]", 			"mov", r.rcx, r.rbx * 2)
    compare("mov rcx, [4*rbx]", 			"mov", r.rcx, r.rbx * 4)
    compare("mov rcx, [8*rbx]", 			"mov", r.rcx, r.rbx * 8)
    compare("mov rcx, [1*rbx+0xdead]", 		"mov", r.rcx, r.rbx * 1 + 0xdead)
    compare("mov rcx, [2*rbx+0xdead]", 		"mov", r.rcx, r.rbx * 2 + 0xdead)
    compare("mov rcx, [4*rbx+0xdead]", 		"mov", r.rcx, r.rbx * 4 + 0xdead)
    compare("mov rcx, [8*rbx+0xdead]", 		"mov", r.rcx, r.rbx * 8 + 0xdead)
    compare("mov rcx, [1*rdx+rbx+0xdead]", 	"mov", r.rcx, 1 * r.rbx + r.rdx + 0xdead)
    compare("mov rcx, [2*rdx+rbx+0xdead]", 	"mov", r.rcx, 2 * r.rbx + r.rdx + 0xdead)
    compare("mov rcx, [4*rdx+rbx+0xdead]", 	"mov", r.rcx, 4 * r.rbx + r.rdx + 0xdead)
    compare("mov rcx, [8*rdx+rbx+0xdead]", 	"mov", r.rcx, 8 * r.rbx + r.rdx + 0xdead)
    compare("mov [rbx*1], rcx", 			"mov", r.rbx * 1, r.rcx)
    compare("mov [rbx*2], rcx", 			"mov", r.rbx * 2, r.rcx)
    compare("mov [rbx*2+0xdead], rcx",		"mov", r.rbx * 2 + 0xdead, r.rcx)
    compare("mov [rbx*1+1024], rcx",        "mov", r.rbx + 1024, r.rcx)
    compare("movsd xmm1, xmm0",              "movsd", r.xmm0, r.xmm1)
end

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
        a:add(r(util.object_to_address(res)), r.rax)

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
        a:mov(r.rdx, util.object_to_address(res) - 1024)

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
        a:movsd(r.xmm0, r(util.object_to_address(ffi.new("double[1]", 3))))
        a:addsd(r.xmm0, r(util.object_to_address(ffi.new("double[1]", 2))))
        a:movsd(r(util.object_to_address(res)), r.xmm0)

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
        a:movsd(r.xmm0, r(util.object_to_address(ffi.new("double[1]", 3))))
        a:mulsd(r.xmm0, r(util.object_to_address(ffi.new("double[1]", 2))))
        a:movsd(r(util.object_to_address(res)), r.xmm0)

        a:ret()
    end

    local mcode = a:compile()

    local func = ffi.cast("int (*)()", mcode)

    func()

    check(res[0], "==", 6, "rax should be TARGET")
end

do -- fpu add 2+3
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

print("test complete")