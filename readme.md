# lua-asm (WORK IN PROGRESS)

This is an x86-64 instruction encoder with a simple JIT assembler written in Lua.

I'm mainly doing this for educational purposes as I've always wanted to learn how binaries are executed. If all goes well I hope it can be used to do fun performance optimizations alongside LuaJIT and maybe even Lua 5.3

At the moment it roughly supports 32 and 64 bit general purpose registers, indirect addressing, displacement and scaling.

It looks like this at the moment using the high level wrapper. Syntax resembles intel style using the high level wrapper.

```lua
local asm = require("assembler")
local util = require("util")
local ffi = require("ffi")

local mcode = asm.compile(function()
	local msg = "hello world!\n"

	-- syntax resembles intel style
	mov(rax, 1) -- WRITE
	mov(rdi, 1) -- STDOUT
	mov(rsi, util.object_to_address(msg))
	mov(rdx, #msg)

	syscall()

	jmp("no!")
		mov(rax, 777)
	label("no!")

	mov(rax, 1337)

	ret()
end)

local func = ffi.cast("uint64_t (*)(uint64_t)", mcode)

print(func(0))
```

The code above is translated roughly into something like this:

```lua
-- the following:
mov(rbx + rcx * 4 - 0x20, rax)

-- is the same as:
local x86_64 = require("x86_64")
bytes = x86_64.encode("mov", {
	reg = "rbx",
	index = "rcx",
	scale = 4,
	disp = -0x20,
},
{
	reg = "rax",
})
-- where the bytes are simply placed into a buffer
```

Instructions are sourced from https://github.com/asmjit/asmdb

TODO
* more refactoring and better code separation
* shorter way of encoding modrm+sib and rex prefix, the code feels stupid at the moment
* suppport instructions like simd, vex, xop, etc
* build lua file with all the instructions to get rid of x86data.js and json.lua dependency
* windows support
