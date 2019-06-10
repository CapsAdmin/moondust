local ffi = require("ffi")
local json = require("json")
local util = require("util")

local x86_64 = {}

do
	x86_64.reginfo = {}

	do -- integers
		local base = {
			"ax", "cx", "dx", "bx",
			"sp", "bp", "si", "di",
		}

		for _, bit in ipairs({64, 32, 16, 8}) do
			local tbl = {}

			if bit == 64 then
				for i, v in ipairs(base) do tbl[i] = "r" .. v; tbl[i + 7 + 1] = "r" .. (i+7) end
			elseif bit == 32 then
				for i, v in ipairs(base) do tbl[i] = "e" .. v; tbl[i + 7 + 1] = "r" .. (i+7) .. "d" end
			elseif bit == 16 then
				for i, v in ipairs(base) do tbl[i] = v; tbl[i + 7 + 1] = "r" .. (i+7) .. "w" end
			else
				tbl = {
					"al", "cl", "dl","bl",
					"ah", "ch", "dh", "bh",
					"spl", "bpl", "sil", "dil",
					"r8b", "r9b", "r10b", "r11b",
					"r12b", "r13b", "r14b", "r15b",
				}
			end

			for i, reg in ipairs(tbl) do
				x86_64.reginfo[reg] = {
					bits = bit,
					extra = i > 8,
					index = (i - 1)%8,
				}
			end
		end
	end

	do -- xmm
		for i = 0, 15 do
			x86_64.reginfo["xmm" .. i] = {
				bits = "xmm",
				extra = i > 8,
				index = i%8,
			}
		end
	end
end


local REX_FIXED_BIT = 0b01000000
local REX = {
	W = 0b00001000, -- 64bit mode
	R = 0b00000100, -- r8-r15
	X = 0b00000010, -- r8-r15
	B = 0b00000001, -- r8-r15
}

local VEX_2_BYTES_PREFIX = 0xC5
local VEX_3_BYTES_PREFIX = 0xC4
local XOP_PREFIX = 0x8F

function x86_64.encode_rex(W, flip, B, R, X)
	if flip then
		B,R,X = X,B,R
	end

	local rex = REX_FIXED_BIT -- Fixed base bit pattern

	if W then
		rex = bit.bor(rex, REX.W)
	end

	if R then
		rex = bit.bor(rex, REX.R)
	end

	if X then
		rex = bit.bor(rex, REX.X)
	end

	if B then
		rex = bit.bor(rex, REX.B)
	end

	return string.char(rex)
end

function x86_64.encode_modrm_sib(op1, op2)
	local reg1 = op1.reg and x86_64.reginfo[op1.reg].index
	local reg2
	local index
	local base
	local scale
	local disp
	local disp_type

	local modrm
	local sib

	if type(op2) == "number" then
		reg2 = op2
	else
		index = x86_64.reginfo[op2.index] and x86_64.reginfo[op2.index].index
		reg2 = x86_64.reginfo[op2.reg] and x86_64.reginfo[op2.reg].index

		if op2.indirect then
			base = reg2
			reg2 = nil

		end

		disp = op2.disp
		disp_type = "uint32_t"
		scale = op2.scale
	end

	-- mov rcx, rbx
	if reg1 and reg2 then
		modrm = 0b11000000
		modrm = bit.bor(modrm, reg1)
		modrm = bit.bor(modrm, bit.lshift(reg2, 3))
	end

	--mov rcx, [0xdead]
	if reg1 and disp and not reg2 and not base and not index and not scale then
		modrm = 0b00000100
		modrm = bit.bor(modrm, bit.lshift(reg1, 3))
		sib = 0b00100101
		disp_type = "uint32_t"
	elseif reg1 and base and not reg2 and not index and not scale  then
		modrm = bit.bor(bit.lshift(reg1, 3), base)
	elseif reg1 and base and scale then
		if index then
			modrm = 0b10000100
		else
			modrm = 0b00000100
		end

		modrm = bit.bor(modrm, bit.lshift(reg1, 3))

		sib = 0

		if index then
			sib = bit.bor(sib, base)
			sib = bit.bor(sib, bit.lshift(index, 3))
		else
			sib = bit.bor(sib, 0b101)
			sib = bit.bor(sib, bit.lshift(base, 3))
		end

		if scale then
			sib = sib or 0
			local pattern = 0b00

			if scale == 1 then
				pattern = 0b00
			elseif scale == 2 then
				pattern = 0b01
			elseif scale == 4 then
				pattern = 0b10
			elseif scale == 8 then
				pattern = 0b11
			else
				error("invalid sib scale: " .. tostring(sib.scale))
			end

			sib = bit.bor(sib, bit.lshift(pattern, 6))
		end

		disp_type = "uint32_t"
		disp = disp or 0
	end

	local str = ""

	if modrm then
		str = str .. string.char(modrm)
	end

	if sib then
		str = str .. string.char(sib)
	end

	if disp then
		str = str ..x86_64.encode_int(disp_type, disp)
	end

	return str
end

function x86_64.encode_int(t, int)
	if type(int) == "cdata" then
		int = ffi.cast(t, int)
	elseif type(int) == "number" then
		int = ffi.new(t, int)
	end

	return ffi.string(ffi.new(t.."[1]", int), ffi.sizeof(t))
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

local type_translate2 = {
	ib = "i8",
	iw = "i16",
	id = "i32",
	iq = "i64",

	ub = "u8",
	uw = "u16",
	ud = "u32",
	uq = "u64",

	rel8 = "i8",
	rel16 = "i16",
	rel32 = "i32",
}

x86_64.map = {}

local function dump(self)
	for k,v in pairs(self) do
		if k == "real_operands" then
		   v = table.concat(v, ", ")
		end

		print(k .. " = " .. tostring(v))
	end
end

local function parse_db(db)
	local function parse_instruction(name, operands, encoding, opcode, metadata, operands2)
		local real_operands = {}
		local arg_line = {}
		for i, v in ipairs(operands) do
			real_operands[i] = v
			v = type_translate2[v] or v
			operands[i] = v
			arg_line[i] =  "op" .. i
		end

		local key = table.concat(operands, ",")

		if x86_64.map[name] and x86_64.map[name][key] and x86_64.map[name][key].encoding == "MR" then
			return
		end

		arg_line = table.concat(arg_line, ", ")


		local lua = "local x86_64 = ... return function("..arg_line..")"

		local instr_length = 0

		local instr = {}

		if opcode[1] == "REX.W" then
			local op2 = ")"

			if operands[2] and (util.string_startswith(operands[2], "r") or util.string_startswith(operands[2], "m")) then
				op2 = ", op2.reg and x86_64.reginfo[op2.reg].extra, op2.index and x86_64.reginfo[op2.index].extra)"
			end

			table.insert(instr, "x86_64.encode_rex(true, "..tostring(encoding == "RM")..", op1.reg and x86_64.reginfo[op1.reg].extra" .. op2)
		end

		for _, byte in ipairs(opcode) do
			if byte == "/r" then
				if encoding == "MR" and operands[1]:sub(1,1) == "m" and (operands[2]:sub(1,1) == "r" or operands[2]:sub(1,1) == "x") then
					table.insert(instr, "x86_64.encode_modrm_sib(op2, op1)")
				else
					table.insert(instr, "x86_64.encode_modrm_sib(op1, op2)")
				end
			elseif util.string_startswith(byte, "c") then
				local s = byte:sub(2,2)
				if s == "b" then
					table.insert(instr, "x86_64.encode_int('int8_t', op"..#operands..")")
				elseif s == "w" then
					table.insert(instr, "x86_64.encode_int('int16_t', op"..#operands..")")
				elseif s == "d" then
					table.insert(instr, "x86_64.encode_int('int32_t', op"..#operands..")")
				end
			elseif util.string_startswith(byte, "/") and tonumber(byte:sub(2,2)) then
				table.insert(instr, "x86_64.encode_modrm_sib(op1, "..byte:sub(2,2)..")")
			elseif util.string_endswith(byte, "+r") then
				table.insert(instr, "string.char(0x"..byte:sub(1, 2).." + x86_64.reginfo[op1.reg].index)")
			elseif type_translate[type_translate2[byte]] then
				table.insert(instr, "x86_64.encode_int(\""..type_translate[type_translate2[byte]].."\", op"..#operands..")")
			elseif tonumber(byte, 16) then
				table.insert(instr, "\"\\x"..byte.."\"")
				instr_length = instr_length + 1
			end
		end

		local has_relative = false
		local alt_key

		for i, v in ipairs(real_operands) do
			if util.string_startswith(v, "rel") then
				instr_length = instr_length + tonumber(v:sub(4)) / 8
				--lua = lua .. "\nop" .. i .. " = op" .. i .. " - " .. instr_length .. "\n"
				has_relative = true
				operands[i] = "string"
			end
		end

		if has_relative then
			alt_key = table.concat(operands)
		end

		lua = lua .. " return " .. table.concat(instr, "..")
		lua = lua:gsub("\"%s*%.%.%s*\"", "")
		lua = lua .." end"

		x86_64.map[name] = x86_64.map[name] or {}
		x86_64.map[name][key] = {
			func = loadstring(lua)(x86_64),
			lua = lua,
			name = name,
			operands = operands,
			encoding = encoding,
			opcode = opcode,
			metadata = metadata,
			operands2 = operands2,
			real_operands = real_operands,
			has_relative = has_relative,
			dump = dump,
		}

		if alt_key then
			x86_64.map[name][alt_key] = x86_64.map[name][key]
		end
	end

	for i, v in ipairs(db.instructions) do
		local name, operands, encoding, opcode, metadata = unpack(v)

		local args = {}

		local tbl = util.string_split(operands, ",")
		--for i = #tbl, 1, -1 do local arg = tbl[i]
		for i, arg in ipairs(tbl) do
			arg = util.string_trim(arg)

			local mode
			if arg:sub(2,2) == ":" then
				mode = arg:sub(1, 1)
				arg = arg:sub(3)
			end

			if util.string_startswith(arg, "~") then
				arg = arg:sub(2) -- also swap args?
			end


			if arg == "m64fp" then arg = "m64" end
			if arg == "m32fp" then arg = "m32" end

			if not util.string_startswith(arg, "<") then
				table.insert(args, util.string_trim(arg))
			end
		end

		if #args == 0 then
			for _, name in ipairs(util.string_split(name, "/")) do
				parse_instruction(name, args, encoding, util.string_split(opcode, " "), metadata, operands)
			end
		else
			local temp = {}
			local max = 0

			for i, arg in ipairs(args) do
				temp[i] = temp[i] or {}
				for z, var in ipairs(util.string_split(arg, "/")) do
					temp[i][z] = var
				end
				max = math.max(max, #temp[i])
			end

			for z = 1, max do
				local args2 = {}
				for i = 1, #args do
					table.insert(args2, temp[i][math.min(z, #temp[i])])
				end

				for _, name in ipairs(util.string_split(name, "/")) do
					parse_instruction(name, args2, encoding, util.string_split(opcode, " "), metadata, operands)
				end
			end
		end
	end
end

local js = assert(io.open("x86data.js", "rb") or io.open("./src/x86data.js", "rb")):read("*all")

local data = js:match("// %$%{JSON:BEGIN%}(.+)// ${JSON:END}")
data = data:gsub("%/%*.-%*/", "")

parse_db(json.decode(data))

local function helper_error(tbl, str)
	local candidates = {}

	for key in pairs(tbl) do
		table.insert(candidates, {key = key, score = util.string_levenshtein(key, str)})
	end

	table.sort(candidates, function(a, b) return a.score < b.score end)

	local found = ""
	for i = 1, 5 do
		if candidates[i] then
			found = found  .. "\t" .. candidates[i].key .. "\n"
		end
	end

	return found
end

function x86_64.get_typestring(mnemonic, ...)
	local str = {}
	local max = select("#", ...)
	local lua_number = false
	local lua_address = false

	for i = 1, max do
		local arg = select(i, ...)

		local found = false

		if type(arg) == "table" and (arg.reg or arg.disp or arg.base) then
			if not arg.reg and not arg.base then
				if type(arg.disp) == "cdata" then
					local size = ffi.sizeof(arg.disp) * 8
					str[i] = "m" .. size
				else
					str[i] = "m?"
					lua_number = true
				end
			elseif arg.indirect then
				str[i] = "m" .. x86_64.reginfo[arg.reg].bits
			else
				if x86_64.reginfo[arg.reg].bits == "xmm" then
					str[i] = "xmm[7:0]"
				else
					str[i] = "r" .. x86_64.reginfo[arg.reg].bits
				end
			end
		elseif type(arg) == "number" then
			str[i] = "i?"
			lua_number = true
		else
			local found = false
			if type(arg) == "cdata" then
				for k,v in pairs(type_translate) do
					if ffi.istype(v, arg) then
						str[i] = k
						found = true
						break
					end
				end
			end
			if not found then
				str[i] = type(arg)
			end
		end
	end

	if not x86_64.map[mnemonic] then
		return nil, "no such function " .. mnemonic .. "\ndid you mean one of these?\n" .. helper_error(x86_64.map, mnemonic)
	end

	if lua_number then
		for i, arg in ipairs(str) do
			if util.string_endswith(arg, "?") then
				local num = select(i, ...)
				if type(num) == "table" and num.disp then
					num = num.disp
				end

				for _, bits in ipairs({"8", "16", "32", "64"}) do
					str[i] = arg:sub(0, 1) .. bits
					local test = table.concat(str, ",")

					if bits == "8" and num > -128 and num < 128 and x86_64.map[mnemonic][test] then
						break
					elseif bits == "16" and num > -13824 and num < 13824 and x86_64.map[mnemonic][test] then
						break
					elseif bits == "32" and num > -2147483648 and num < 2147483648 and x86_64.map[mnemonic][test] then
						break
					elseif x86_64.map[mnemonic][test] then
						break
					end
				end
			end
		end
	end

	str = table.concat(str, ",")

	if not x86_64.map[mnemonic][str] then
		return nil, mnemonic .. " does not take arguments " .. str .. "\ndid you mean one of these?\n" .. helper_error(x86_64.map[mnemonic], str)
	end

	return str
end

function x86_64.encode(mnemonic, ...)
	local typestr, err = x86_64.get_typestring(mnemonic, ...)

	if not typestr then
		error(err, 2)
	end

	if x86_64.pre_encode then
		local res = x86_64.pre_encode(mnemonic, typestr, ...)
		if res ~= nil then
			return res
		end
	end

	local data = x86_64.map[mnemonic][typestr]
	local ok, bytes = pcall(data.func, ...)

	if not ok then
		print(data.lua)
		print(...)

		local a,b = ...
		print("op1:")
		for k,v in pairs(a or {}) do
			print(k,v)
		end

		print("op2:")
		for k,v in pairs(b or {}) do
			print(k,v)
		end
		error(bytes, 2)
	end

	return {
		name = mnemonic,
		bytes = bytes,
		arg_types = typestr,
		args = {...},
		metadata = data,
	}
end

return x86_64