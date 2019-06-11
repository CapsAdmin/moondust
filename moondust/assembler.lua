local ffi = require("ffi")
local x86_64 = require("moondust.x86_64")

local asm = {}

do
	local meta = {}
	meta.__index = meta

	function meta:__tostring()
		local str = ""

		if self.indirect then
			str = str .. "["
		end

		if self.reg then
			str = str .. self.reg
		end

		if self.index then
			str = str .. "+" .. self.index
		end

		if self.scale then
			str = str .. "*" .. self.scale
		end

		if self.disp then
			if self.reg or self.index then
				str = str .. (self.disp > 0 and "+" or "-") .. tostring(self.disp)
			else
				str = str .. tostring(self.disp)
			end
		end

		if self.indirect then
			str = str .. "]"
		end

		return str
	end

	function meta:copy()
		return setmetatable({
			reg = self.reg,
			base = self.base,
			index = self.index,
			scale = self.scale,
			disp = self.disp,
		}, meta)
	end


	function meta:__call()
		local new = asm.reg(self.reg, self.index, self.scale, self.disp, true)
		return new
	end

	function meta.__add(l, r)
		if type(l) == "number" then
			r,l = l,r
		end

		if getmetatable(r) == meta then
			l = l:copy()
			l.index = r.reg or l.index
			l.disp = r.disp or l.disp
			l.scale = r.scale or l.scale
			l.indirect = true
		end

		if type(r) == "number" then
			l = l:copy()
			l.disp = r
			l.scale = l.scale or 1
			l.indirect = true
		end

		return l
	end

	function meta.__sub(l, r)
		if type(l) == "number" then
			r,l = l,r
		end
		if type(r) == "number" then
			l = l:copy()
			l.disp = -r
			l.indirect = true
		end

		return l
	end

	function meta.__mul(l, r)
		if type(l) == "number" then
			r,l = l,r
		end

		if type(r) == "number" then
			l = l:copy()
			l.scale = r
			l.indirect = true
		end

		return l
	end

	local function create_reg(reg, index, scale, disp, indirect)
		return setmetatable({
			reg = reg,
			index = index,
			disp = disp,
			scale = scale,
			indirect = indirect,
		}, meta)
	end

	do
		local lib_meta = {}
		lib_meta.__index = lib_meta
		function lib_meta:__call(reg, index, scale, disp, indirect)
			if getmetatable(reg) == meta then
				local new = reg:copy()
				new.indirect = true
				return new
			elseif type(reg) ~= "string" then
				disp = reg
				reg = nil
				indirect = true
			end
			return create_reg(reg, index, scale, disp, indirect)
		end

		asm.reg = {}

		for reg in pairs(x86_64.reginfo) do
			asm.reg[reg] = create_reg(reg)
		end

		asm.reg = setmetatable(asm.reg, lib_meta)
	end
end

function asm.addr(num)
	return ffi.cast("void *", num)
end

do
	ffi.cdef("char *strerror(int errnum);")
	local function last_error(num)
		num = num or ffi.errno()
		local err = ffi.string(ffi.C.strerror(num))
		return err == "" and tostring(num) or err
	end

	if jit.os ~= "Windows" then
		ffi.cdef[[
			char *mmap(void *addr, size_t length, int prot, int flags, int fd, long int offset);
			int munmap(void *addr, size_t length);
		]]

		local PROT_READ = 0x1
		local PROT_WRITE = 0x2
		local PROT_EXEC = 0x4

		local MAP_PRIVATE
		local MAP_ANONYMOUS

		if jit.os == "OSX" then
			MAP_PRIVATE = 0x0002
			MAP_ANONYMOUS = 0x1000
		else
			MAP_PRIVATE = 0x02
			MAP_ANONYMOUS = 0x20
		end

		local MAP_FAILED = ffi.cast("char *", -1)

		function asm.executable_memory(str)
			local mem = ffi.C.mmap(nil, #str, bit.bor(PROT_READ, PROT_WRITE, PROT_EXEC), bit.bor(MAP_PRIVATE, MAP_ANONYMOUS), -1, 0)
			if mem == MAP_FAILED then
				return nil, last_error()
			end
			ffi.copy(mem, str)
			return mem
		end
	else
		function asm.executable_memory(str)
			return nil, "NYI"
		end
	end
end

local function check_gas(data)
	local util = require("util")
	local gas = require("gas")

	local str = data.name .. " "
	local types = util.string_split(data.arg_types, ",")
	for i = 1, #data.args do
		local arg, type = data.args[i], types[i]

		if type:sub(1,1) == "i" or type:sub(1,1) == "u" then
			if _G.type(arg) == "string" then
				arg = tostring(asm.ObjectToAddress(arg)):sub(0,-3)
			elseif _G.type(arg) == "cdata" then
				arg = tonumber(arg)
			end

			str = str .. tostring(arg)
		end
		if type:sub(1,1) == "r" or type:sub(1,1) == "m" then
			str = str .. tostring(arg)
		end
		if i ~= #data.args then
			str = str .. ","
		end
	end

	print(gas.dump_asm(str, function(bytes) return util.string_binformat(bytes, 15, "  ", true) end, data.bytes, false))
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

	function meta:label(name)
		local label = {name = name, start_pos = self:get_size()}
		table.insert(self.labelsi, label)
		self.labels[name] = label
	end

	function meta:get_label(name)
		return self.labels[name]
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

		local mem = assert(asm.executable_memory(str))

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
			if info.has_relative and type(a) == "string" then
				table.insert(self.labelsi, {name = a, stop_pos = self:get_size(), mnemonic = name})
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
	env.label = function(name) return a:label(name) end

	setfenv(func, setmetatable({}, {__index = function(s, key)
		if env[key] then
			return env[key]
		end

		if x86_64.map[key] then
			return function(...)
				local data, err = a:encode(key, ...)
				if validate and data then
					check_gas(data)
				end
			end
		end

		if x86_64.reginfo[key] then
			return asm.reg(key)
		end

		return _G[key]
	end}))(a)

	return a:compile()
end

return asm