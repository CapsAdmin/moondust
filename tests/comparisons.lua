package.path = package.path .. ";./src/?.lua"

local ffi = require("ffi")
local gas = require("moondust.gas")
local util = require("moondust.util")
local x86_64 = require("moondust.x86_64")
local asm = require("moondust.assembler")
local r = asm.reg


local function compare(str, ...)
    local name = util.string_split(str, " ")[1]
    local data = x86_64.encode(name, ...)

    local strtbl = {} for i,v in ipairs({...}) do strtbl[i] = tostring(v) end
    --print(name .. " " .. table.concat(strtbl, ", ") .. " | " .. table.concat(data.metadata.opcode, " "))
    local str, ok = gas.dump_asm(str, function(bytes) return util.string_binformat(bytes, 15, "  ", true) end, data.bytes)
    if not ok then
        print("======================")
        local info = debug.getinfo(2)
        print(info.source:sub(2) .. ":" .. info.currentline)
        print(str)
        for k,v in pairs(data.metadata) do print(k,v) end
        print("======================")
    end
end

compare("mov r12, rdi", 				r.r12, r.rdi)
compare("mov r12, [0x1]", 				r.r12, r(0x1))
compare("inc r12", 			    	    r.r12)
compare("mov rcx, rbx", 				r.rcx, r.rbx)
compare("mov rcx, [0x1]", 				r.rcx, r(0x1))
compare("mov ecx, [0x1]", 				r.ecx, r(0x1))
compare("mov ax, [0x1]", 				r.ax, r(0x1))
compare("mov al, [0x1]", 				r.al, r(0x1))
compare("mov rcx, [0xdead]", 			r.rcx, r(0xdead))
compare("mov rcx, [rbx]", 				r.rcx, r(r.rbx))
compare("mov [rcx], rbx", 				r(r.rcx), r.rbx)
compare("mov rcx, [rbx*1]", 			r.rcx, r.rbx * 1)
compare("mov rcx, [2*rbx]", 			r.rcx, r.rbx * 2)
compare("mov rcx, [4*rbx]", 			r.rcx, r.rbx * 4)
compare("mov rcx, [8*rbx]", 			r.rcx, r.rbx * 8)
compare("mov rcx, [1*rbx+0xdead]", 		r.rcx, r.rbx * 1 + 0xdead)
compare("mov rcx, [2*rbx+0xdead]", 		r.rcx, r.rbx * 2 + 0xdead)
compare("mov rcx, [4*rbx+0xdead]", 		r.rcx, r.rbx * 4 + 0xdead)
compare("mov rcx, [8*rbx+0xdead]", 		r.rcx, r.rbx * 8 + 0xdead)
compare("mov rcx, [1*rdx+rbx+0xdead]", 	r.rcx, 1 * r.rbx + r.rdx + 0xdead)
compare("mov rcx, [2*rdx+rbx+0xdead]", 	r.rcx, 2 * r.rbx + r.rdx + 0xdead)
compare("mov rcx, [4*rdx+rbx+0xdead]", 	r.rcx, 4 * r.rbx + r.rdx + 0xdead)
compare("mov rcx, [8*rdx+rbx+0xdead]", 	r.rcx, 8 * r.rbx + r.rdx + 0xdead)
compare("mov [rbx*1], rcx", 			r.rbx * 1, r.rcx)
compare("mov [rbx*2], rcx", 			r.rbx * 2, r.rcx)
compare("mov [rbx*2+0xdead], rcx",		r.rbx * 2 + 0xdead, r.rcx)
compare("mov [rbx*1+1024], rcx",        r.rbx + 1024, r.rcx)
compare("movsd xmm1, xmm0",             r.xmm0, r.xmm1)
compare("push rbp",                     r.rbp)
compare("mov rbp, rsp",                 r.rbp, r.rsp)
compare("lea rax, [1337222223]",        r.rax, r(1337222223))
compare("call rax",                     r.rax)
compare("lea rdi, [rip + 0xf * 2]",     r.rdi, r(r.rip + 0xf * 2))
compare("lea rdi, [rip + 0xf]",         r.rdi, r(r.rip + 0xf))
compare("lea rdi, [rip]",               r.rdi, r(r.rip))

compare("mov [rbp], ebx",               r(r.rbp+0), r.ebx)
compare("mov [rbp+1], ebx",             r(r.rbp+1), r.ebx)
compare("mov [rbp+123123], ebx",        r(r.rbp+123123), r.ebx)
compare("mov [rbp], ecx",               r(r.rbp), r.ecx)
compare("mov [rbp], ebx",               r(r.rbp+0), r.ebx)


-- TODO
--compare("add QWORD PTR [rbp-1], 2",      "add", r(r.rbp - 1), 2)
--compare("mov ebx, [eax+1]",               "mov", r.ebx, r(r.eax+1))
--compare("mov [eax+1], ebx",               "mov", r(r.eax+1), r.ebx)
--compare("mov [rax+123123], ebx",               "mov", r(r.rax+123123), r.ebx)