local ffi = require("ffi")
local x86_64 = require("x86_64")

local asm = {}

do
	local meta = {}
	meta.__index = meta

	function meta:__tostring()
		if self.disp or self.index or self.scale then
			return string.format("%s(%s, %s, %s)", self.disp or "", self.reg, self.index or "", self.scale or "")
		end
		return self.reg
	end

	function meta.__add(l, r)
		if getmetatable(r) == meta then
			return asm.reg(l.reg, r.reg, r.disp, r.scale)
		end

		if type(r) == "number" then
			l.disp = r
		end

		return l
	end

	function meta.__sub(l, r)
		if type(r) == "number" then
			l.disp = -r
		end

		return l
	end

	function meta.__mul(l, r)
		if type(r) == "number" then
			l.scale = r
		end

		return l
	end

	function asm.reg(reg, index, disp, scale)
		return setmetatable({
			reg = reg,
			index = index,
			disp = disp,
			scale = scale,
		}, meta)
	end
end

if jit.os ~= "Windows" then
	ffi.cdef[[
		char *mmap(void *addr, size_t length, int prot, int flags, int fd, long int offset);
		int munmap(void *addr, size_t length);
	]]

	local PROT_READ = 0x1 -- Page can be read.
	local PROT_WRITE = 0x2 -- Page can be written.
	local PROT_EXEC = 0x4 -- Page can be executed.
	local PROT_NONE = 0x0 -- Page can not be accessed.
	local PROT_GROWSDOWN = 0x01000000 -- Extend change to start of growsdown vma (mprotect only).
	local PROT_GROWSUP = 0x02000000 -- Extend change to start of growsup vma (mprotect only).
	local MAP_SHARED = 0x01 -- Share changes.
	local MAP_PRIVATE = 0x02
	local MAP_ANONYMOUS = 0x20

	function asm.executable_memory(str)
		local mem = ffi.C.mmap(nil, #str, bit.bor(PROT_READ, PROT_WRITE, PROT_EXEC), bit.bor(MAP_PRIVATE, MAP_ANONYMOUS), -1, 0)
		ffi.copy(mem, str)
		return mem
	end
else
	function asm.executable_memory(str)
		error("NYI", 2)
	end
end

local function check_gas(data)
	local util = require("util")
	local gas = require("gas")

	local str = data.name .. " "
	local types = util.string_split(data.arg_types, ",")
	for i = #data.args, 1, -1 do
		local arg, type = data.args[i], types[i]

		if type:sub(1,1) == "i" then
			if _G.type(arg) == "string" then
				arg = tostring(asm.ObjectToAddress(arg)):sub(0,-3)
			elseif _G.type(arg) == "cdata" then
				arg = tonumber(arg)
			end

			if data.real_operands[i]:sub(1,1) == "i" then
				str = str .. "$"
			end
			str = str .. tostring(arg)
		end
		if type:sub(1,1) == "r" or type:sub(1,1) == "m" then
			str = str .. "%" .. tostring(arg)
		end
		if i ~= 1 then
			str = str .. ","
		end
	end

	gas.dump_asm(str, format_func, data.bytes, false)

	if false then
		print(str)
		print(format_func(data.bytes))
		data.bytes = nil
		print(data.lua) data.lua = nil
		table.print(data)
	end
end

local type_translate = {
	i8 = "int8_t",
	i16 = "int16_t",
	i32 = "int32_t",
	i64 = "int64_t",

	u8 = "uint8_t",
	u16 = "uint16_t",
	u32 = "uint32_t",
	u64 = "uint64_t",
}

local compile_env = {}

for k,v in pairs(type_translate) do
	compile_env[k] = function(num) return ffi.new(k, num) end
end

function asm.compile(func, validate)
	local str = {}
	local size = 0

	local get_pos = function() return size end

	setfenv(func, setmetatable({}, {__index = function(s, key)
		if compile_env[key] then
			return compile_env[key]
		end

		if x86_64.map[key] then
			return function(...)
				local data = x86_64.encode(key, ...)
				table.insert(str, data.bytes)
				size = size + #data.bytes
				if validate then
					check_gas(data)
				end
			end
		end

		if x86_64.RegLookup[key] then
			return asm.reg(key)
		end

		if key == "pos" then
			return get_pos
		end

		return _G[key]
	end}))()

	if #str == 0 then
		return nil, "nothing to assemble"
	end

	str = table.concat(str)

	local mem = asm.executable_memory(str)

	if mem == nil then
		return nil, "failed to map memory"
	end

	return mem, #str
end

return asm