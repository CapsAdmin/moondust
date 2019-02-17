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

	function meta:__call()
		return asm.reg(self.reg, self.index, self.disp or 0 , self.scale or 1)
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

	local function create_reg(reg, index, scale, disp)
		return setmetatable({
			reg = reg,
			index = index,
			disp = disp,
			scale = scale,
		}, meta)
	end

	do
		local meta = {}
		meta.__index = meta
		function meta:__call(reg, index, scale, disp)
			return create_reg(reg, index, scale, disp)
		end

		asm.reg = {}

		for reg in pairs(x86_64.RegLookup) do
			asm.reg[reg] = create_reg(reg)
		end

		asm.reg = setmetatable(asm.reg, meta)
	end
end

function asm.addr(num)
	return ffi.cast("void *", num)
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

			if data.metadata.real_operands[i]:sub(1,1) == "i" then
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
end

do
	local meta = {}

	function meta:__index(key)
		if meta[key] then
			return meta[key]
		end

		if x86_64.map[key] then
			return function(_, ...)
				return self:encode(key, ...)
			end
		end
	end

	function meta:get_size()
		return self.size
	end

	function meta:write(str)
		table.insert(self.buffer, str)
		self.size = self.size + #str
	end

	function meta:encode(name, ...)
		local data = x86_64.encode(name, ...)
		if type(data) == "table" and type(data.bytes) == "string" then
			self:write(data.bytes)
		end
		return data
	end

	function meta:create_label(name)
		local label = {name = name, start_pos = self:get_size()}
		table.insert(self.labelsi, label)
		self.labels[name] = label
	end

	function meta:get_label(name)
		return self.labels[name]
	end

	function meta:virtual_label(name)
		return {label_name = name}
	end

	function meta:compile()
		if #self.buffer == 0 then
			return nil, "nothing to assemble"
		end

		local str = table.concat(self.buffer)

		local found = {}
		for _, stop in ipairs(self.labelsi) do
			if stop.stop_pos then
				for _, start in ipairs(self.labelsi) do
					if start.name == stop.name and start.start_pos then
						table.insert(found, {
							name = start.name,
							start = start.start_pos,
							stop = stop.stop_pos,
							mnemonic = stop.mnemonic
						})
					end
				end
			end
		end

		table.sort(found, function(a, b) return a.stop < b.stop end)
		local offset = 0

		for i, label in ipairs(found) do
			local start = label.start
			local stop = label.stop

			local rel = start - stop

			if rel < 0 then
				rel = rel - #x86_64.encode(label.mnemonic, rel).bytes  -- FIX ME
			end

			local bytes = x86_64.encode(label.mnemonic, rel).bytes

			str = str:sub(1, stop + offset) .. bytes .. str:sub(stop + 1 + offset, #str)
			offset = offset + #bytes
		end

		local mem = asm.executable_memory(str)

		if mem == nil then
			return nil, "failed to map memory"
		end

		return mem, #str
	end

	function asm.assembler()
		local self = setmetatable({}, meta)

		self.buffer = {}
		self.size = 0
		self.labels = {}
		self.labelsi = {}

		function x86_64.pre_encode(name, argstr, a,b,c,d,e)
			local info = x86_64.map[name][argstr]
			if info.has_relative and type(a) == "table" then
				table.insert(self.labelsi, {name = a.label_name, stop_pos = self:get_size(), mnemonic = name})
				return false
			end
		end

		return self
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

for k,v in pairs(type_translate) do
	asm[k] = function(num) return ffi.new(k, num) end
end

function asm.compile(func, validate)
	local a = asm.assembler()

	local env = {}

	for k,v in pairs(type_translate) do
		env[k] = function(num) return ffi.new(k, num) end
	end

	env.pos = function() return a:get_size() end
	env.label = setmetatable({}, {__call = function(_, name) return a:create_label(name) end, __index = function(_, key) return a:virtual_label(key) end})

	setfenv(func, setmetatable({}, {__index = function(s, key)
		if env[key] then
			return env[key]
		end

		if x86_64.map[key] then
			return function(...)
				local data = a:encode(key, ...)

				if validate then
					check_gas(data)
				end
			end
		end

		if x86_64.RegLookup[key] then
			return asm.reg(key)
		end

		return _G[key]
	end}))(a)

	return a:compile()
end

return asm