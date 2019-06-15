# moondust (WORK IN PROGRESS)

This is an x86-64 instruction encoder with a simple JIT assembler written in LuaJIT with FFI.

I'm mainly doing this for educational purposes as I've always wanted to learn how binaries are executed. If all goes well I hope it can be used to do fun performance optimizations alongside LuaJIT and maybe even Lua 5.3

At the moment it roughly supports 32 and 64 bit general purpose registers, indirect addressing, displacement and scaling.

It looks like this at the moment using the high level wrapper. Syntax resembles intel style.

```lua
local ffi = require("ffi")
local asm = require("moondust.assembler")

local mcode = asm.compile(function()
	local msg = "hello world!\n"

	-- syntax resembles intel style
	mov(rax, 1) -- WRITE
	mov(rdi, 1) -- STDOUT
	mov(rsi, asm.object_to_address(msg))
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

Each instruction in the above example are roughly translated like this:

```lua
mov(rbx + rcx * 4 - 0x20, rax)
-- >>>
local x86_64 = require("moondust.x86_64")
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

x86_64 instructions are sourced from https://github.com/asmjit/asmdb

To run tests: `./run test`

To build x86_64_data.lua from x86_64.json: `./run build`

To require module `require('moondust')`

TODO
* more refactoring and better code separation
* shorter way of encoding modrm+sib and rex prefix, the code feels stupid at the moment
* suppport instructions like simd, vex, xop, etc
* windows support
