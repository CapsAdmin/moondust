local ffi = require("ffi")
local memory = require("moondust.memory")
local Assembler = {}
Assembler.__index = Assembler
setmetatable(Assembler, {
	__call = function()
		return Assembler.new()
	end,
})

function Assembler.new()
	local self = setmetatable({
		code = {},
		pos = 1,
		labels = {},
		labelsi = {},
	}, Assembler)
	return self
end

function Assembler:emit(...)
	for i, b in ipairs({...}) do
		self.code[self.pos] = string.char(b)
		self.pos = self.pos + 1
	end
end

function Assembler:size()
	return self.pos
end

function Assembler:emit_string(str)
	for i = 1, #str do
		local char = str:sub(i, i)
		self.code[self.pos] = char
		self.pos = self.pos + 1
	end
end

function Assembler:compile()
	return self:resolve_labels(table.concat(self.code))
end

function Assembler:build(cdef)
	local code = self:compile()
	local ptr = assert(memory.make_executable(code))

	if cdef then return ffi.cast(cdef, ptr) end

	return ptr
end

function Assembler:debug_disassemble()
	local dissassemble = require("moondust.disassemble")
	return dissassemble(table.concat(self.code))
end

function Assembler:debug_hex()
	local hex = {}

	for i = 1, self.pos - 1 do
		table.insert(hex, string.format("%02X", self.code[i]:byte()))
	end

	return table.concat(hex, " ")
end

do -- constants
	Assembler.emit_u8 = emit

	function Assembler:emit_u16(n)
		local bytes = ffi.new("union { uint16_t n; uint8_t b[2]; }", n)

		for i = 0, 1 do
			self:emit(bytes.b[i])
		end
	end

	function Assembler:emit_u32(n)
		local bytes = ffi.new("union { uint32_t n; uint8_t b[4]; }", n)

		for i = 0, 3 do
			self:emit(bytes.b[i])
		end
	end

	function Assembler:emit_u64(n)
		local bytes = ffi.new("union { uint64_t n; uint8_t b[8]; }", n)

		for i = 0, 7 do
			self:emit(bytes.b[i])
		end
	end

	function Assembler:emit_i8(n)
		local bytes = ffi.new("union { int8_t n; uint8_t b; }", n)
		self:emit(bytes.b)
	end

	function Assembler:emit_i16(n)
		local bytes = ffi.new("union { int16_t n; uint8_t b[2]; }", n)

		for i = 0, 1 do
			self:emit(bytes.b[i])
		end
	end

	function Assembler:emit_i32(n)
		local bytes = ffi.new("union { int32_t n; uint8_t b[4]; }", n)

		for i = 0, 3 do
			self:emit(bytes.b[i])
		end
	end

	function Assembler:emit_i64(n)
		local bytes = ffi.new("union { int64_t n; uint8_t b[8]; }", n)

		for i = 0, 7 do
			self:emit(bytes.b[i])
		end
	end

	function Assembler:emit_f32(f)
		local bytes = ffi.new("union { float f; uint8_t b[4]; }", f)

		for i = 0, 3 do
			self:emit(bytes.b[i])
		end
	end

	function Assembler:emit_f64(f)
		local bytes = ffi.new("union { double f; uint8_t b[8]; }", f)

		for i = 0, 7 do
			self:emit(bytes.b[i])
		end
	end
end

require("moondust.x86_64")(Assembler)
return Assembler
