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

	local function check_range(num, min, max, bits)
		assert(
			num >= min and num <= max,
			bits .. "-bit number must be between " .. min .. " and " .. max .. " but it is " .. tostring(num)
		)
	end

	function Assembler:emit_number(num, bit_size, signed)
		if bit_size == 8 then
			if signed then
				check_range(num, -128, 127, bit_size)
				self:emit_i8(num)
			else
				check_range(num, 0, 255, bit_size)
				self:emit_u8(num)
			end
		elseif bit_size == 16 then
			if signed then
				check_range(num, -32768, 32767, bit_size)
				self:emit_i16(num)
			else
				check_range(num, 0, 65535, bit_size)
				self:emit_u16(num)
			end
		elseif bit_size == 32 then
			if signed then
				check_range(num, -2147483648, 2147483647, bit_size)
				self:emit_i32(num)
			else
				check_range(num, 0, 4294967295, bit_size)
				self:emit_u32(num)
			end
		elseif bit_size == 64 then
			if signed then
				assert(type(num) == "cdata")
				self:emit_i64(num)
			else
				assert(type(num) == "cdata")
				self:emit_u64(num)
			end
		end
	end
end

require("moondust.x86_64")(Assembler)
return Assembler
