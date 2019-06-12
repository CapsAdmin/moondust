local ffi = require("ffi")
local asm = require("moondust.assembler")
local util = require("moondust.util")

local r = asm.reg

local a = asm.assembler()

do
    local msg = "hello world!"

    a:push(r.rbp)
    a:mov(r.rbp, r.rsp)

    a:lea(r.rdi, r(util.object_to_address(msg)))
    a:mov(r.rdx, util.address_of("puts"))
    a:call(r.rdx)
    a:pop(r.rbp)

    a:ret()
end

local mcode = a:compile()
local func = ffi.cast("void (*)()", mcode)

func()