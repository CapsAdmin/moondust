package.path = package.path .. ";../src/?.lua"

local gas = require("gas")
local util = require("util")
local x86_64 = require("x86_64")
local ffi = require("ffi")
local asm = require("assembler")

local function compare(str, name, ...)
    local data = x86_64.encode(name, ...)

    local strtbl = {} for i,v in ipairs({...}) do strtbl[i] = tostring(v) end
    print(name .. " " .. table.concat(strtbl, ", ") .. " | " .. table.concat(data.metadata.opcode, " "))
	gas.dump_asm(str, function(bytes) return util.string_binformat(bytes, 15, "  ", true) end, data.bytes)
end

local r = asm.reg

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