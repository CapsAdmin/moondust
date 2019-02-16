local ffi = require("ffi")
local json = require("json")
local util = require("util")

local x86_64 = {}

local base = {
	"ax", "cx", "dx", "bx",
	"sp", "bp", "si", "di",
}

x86_64.Reg64 = {} for i, v in ipairs(base) do x86_64.Reg64[i] = "r" .. v x86_64.Reg64[i + 7 + 1] = "r" .. (i+7) end
x86_64.Reg32 = {} for i, v in ipairs(base) do x86_64.Reg32[i] = "e" .. v x86_64.Reg32[i + 7 + 1] = "r" .. (i+7) .. "d" end
x86_64.Reg16 = {} for i, v in ipairs(base) do x86_64.Reg16[i] = v x86_64.Reg16[i + 7 + 1] = "r" .. (i+7) .. "w" end

x86_64.Reg8 = {
	"al", "cl", "dl","bl",
	"ah", "ch", "dh", "bh",
	"spl", "bpl", "sil", "dil",
	"r8b", "r9b", "r10b", "r11b",
	"r12b", "r13b", "r14b", "r15b",
}

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

x86_64.KnownBits = {64, 32, 16, 8}

x86_64.RegLookup = {}

for _, bit in ipairs(x86_64.KnownBits) do
	for i, reg in ipairs(x86_64["Reg" .. bit]) do
		local info = {}

		info.bits = bit

		if i > 8 then
			info.extra = true
		end

		info.index = (i - 1)%8

		x86_64.RegLookup[reg] = info
	end
end

function x86_64.REX(W, B, R, X)
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

function x86_64.MODRM(op1, op2)
	local reg = x86_64.RegLookup[op1.reg].index
	local index
	local base
	local scale
	local disp

	reg = x86_64.RegLookup[op1.reg].index

	if type(op2) == "number" then
		base = op2
	else
		index = x86_64.RegLookup[op2.index] and x86_64.RegLookup[op2.index].index
		base = x86_64.RegLookup[op2.reg] and x86_64.RegLookup[op2.reg].index

		disp = op2.disp
		scale = op2.scale
	end

	-- build modrm byte
	if reg and base then
		-- 00 000 000
		modrm = 0

		-- 00 src 000 - place
		modrm = bit.bor(modrm, bit.lshift(base, 3))

		if disp then
			if disp >= -127 and disp <= 127 == 1 then
				-- 10 src 000
				modrm = bit.bor(modrm, 0b01000000)
			else
				modrm = bit.bor(modrm, 0b10000000)
			end
		else
			-- 11 src 000
			modrm = bit.bor(modrm, 0b11000000)
		end

		if index then
			-- 10 src idx
			modrm = bit.bor(modrm, 0b100)
		else
			-- 10 src dst
			modrm = bit.bor(modrm, reg)
		end
	elseif base then
		modrm = 0b11000000
		modrm = bit.bor(modrm, base)
	elseif reg then
		modrm = 0b11111000
		modrm = bit.bor(modrm, reg)
	end

	-- build sib byte
	if base and index then
		sib = sib or 0

		sib = bit.bor(sib, base)
		sib = bit.bor(sib, bit.lshift(index, 3))

		if tbl.scale then
			local pattern = 0b00

			if tbl.scale == 1 then
				pattern = 0b00
			elseif tbl.scale == 2 then
				pattern = 0b01
			elseif tbl.scale == 4 then
				pattern = 0b10
			elseif tbl.scale == 8 then
				pattern = 0b11
			else
				error("invalid sib scale: " .. tostring(tbl.sib.scale))
			end

			sib = bit.bor(sib, bit.lshift(pattern, 6))
		end
	end

	local str = ""

	if modrm then
		str = str .. string.char(modrm)
	end

	if sib then
		str = str .. string.char(sib)
	end

	return str
end

function x86_64.INT2BYTES(t, int)
	if type(int) == "cdata" then
		int = ffi.cast(t, int)
	elseif type(int) == "number" then
		int = ffi.new(t, int)
	end

	return ffi.string(ffi.new(t.."[1]", int), ffi.sizeof(t))
end


for _, bit in ipairs(x86_64.KnownBits) do
	for i, reg in ipairs(x86_64["Reg" .. bit]) do
		local info = {}

		info.bits = bit

		if i > 8 then
			info.extra = true
		end

		info.index = (i - 1)%8

		x86_64.RegLookup[reg] = info
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

local function parse_db(db)
-- /r = modrm + sib and displacement
	-- /0 = modrm only

	-- +r = preceeding byte + 0-7


	local function parse_instruction(name, operands, encoding, opcode, metadata, operands2)
		--print(" ")
		--print(name, table.concat(operands, ", "), operands2, encoding, table.concat(opcode, " "), metadata)

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
				op2 = ", op2.reg and x86_64.RegLookup[op2.reg].extra, op2.index and x86_64.RegLookup[op2.index].extra)"
			end

			table.insert(instr, "x86_64.REX(true, x86_64.RegLookup[op1.reg].extra" .. op2)
		end

		for _, byte in ipairs(opcode) do
			if byte == "/r" then
				table.insert(instr, "x86_64.MODRM(op1, op2)")
			elseif util.string_startswith(byte, "c") then
				local s = byte:sub(2,2)
				if s == "b" then
					table.insert(instr, "x86_64.INT2BYTES('int8_t', op"..#operands..")")
				elseif s == "w" then
					table.insert(instr, "x86_64.INT2BYTES('int16_t', op"..#operands..")")
				elseif s == "d" then
					table.insert(instr, "x86_64.INT2BYTES('int32_t', op"..#operands..")")
				end
			elseif util.string_startswith(byte, "/") and tonumber(byte:sub(2,2)) then
				table.insert(instr, "x86_64.MODRM(op1, "..byte:sub(2,2)..")")
			elseif util.string_endswith(byte, "+r") then
				table.insert(instr, "string.char(0x"..byte:sub(1, 2).." + x86_64.RegLookup[op1.reg].index)")
			elseif type_translate[type_translate2[byte]] then
				table.insert(instr, "x86_64.INT2BYTES(\""..type_translate[type_translate2[byte]].."\", op"..#operands..")")
			elseif tonumber(byte, 16) then
				table.insert(instr, "\"\\x"..byte.."\"")
				instr_length = instr_length + 1
			end
		end

		for i, v in ipairs(real_operands) do
			if util.string_startswith(v, "rel") then
				instr_length = instr_length + tonumber(v:sub(4)) / 8
				lua = lua .. "\nop" .. i .. " = op" .. i .. " - " .. instr_length .. "\n"
			end
		end

		lua = lua .. " return " .. table.concat(instr, "..")
		lua = lua:gsub("\"%s*%.%.%s*\"", "")
		lua = lua .." end"

		x86_64.map[name] = x86_64.map[name] or {}
		x86_64.map[name][key] = {
      func = loadstring(lua)(x86_64),
      lua = lua,
      real_operands = real_operands,
      info = table.concat({"--", name, table.concat(operands, ","), operands2, encoding, table.concat(opcode, " "), metadata}, " | "),
    }
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

			if not util.string_startswith(arg, "<") then
				table.insert(args, util.string_trim(arg))
			end
		end

		do
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

local js = assert(io.open("x86data.js", "rb") or io.open("../src/x86data.js", "rb")):read("*all")

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


function x86_64.encode(func, ...)
	local str = {}
	local max = select("#", ...)
	local lua_number = false
	local lua_address = false

	for i = 1, max do
		local arg = select(i, ...)

		if type(arg) == "table" then
			if arg.disp or arg.scale then
				str[i] = "rm" .. x86_64.RegLookup[arg.reg].bits
			else
				str[i] = "r" .. x86_64.RegLookup[arg.reg].bits
			end
		elseif type(arg) == "number" then
			str[i] = "i?"
			lua_number = true
		elseif type(arg) == "cdata" then
			for k,v in pairs(type_translate) do
				if ffi.istype(v, arg) then
					str[i] = k
					break
				end
			end
		elseif type(arg) == "string" then
			str[i] = "i64"
		else
			str[i] = type(arg)
		end
	end

	if not x86_64.map[func] then
    error("no such function " .. func .. "\ndid you mean one of these?\n" .. helper_error(x86_64.map, func), 2)
	end

	if lua_number then
		for i, arg in ipairs(str) do
			if util.string_endswith(arg, "?") then
				local num = select(i, ...)

				for _, bits in ipairs({"8", "16", "32"}) do
					str[i] = arg:sub(0, 1) .. bits
					local test = table.concat(str, ",")

					if bits == "8" and num > -128 and num < 128 and x86_64.map[func][test] then
						break
					elseif bits == "16" and num > -13824 and num < 13824 and x86_64.map[func][test] then
						break
					elseif bits == "32" and num > -2147483648 and num < 2147483648 and x86_64.map[func][test] then
						break
					end
				end
			end
		end
	end

	str = table.concat(str, ",")

	if not x86_64.map[func][str] then
    error(func .. " does not take arguments " .. str .. "\ndid you mean one of these?\n" .. helper_error(x86_64.map[func], str), 2)
	end

	local data = x86_64.map[func][str]

	return {
		name = func,
		bytes = data.func(...),
		arg_types = str,
		args = {...},
		lua = data.lua,
		real_operands = data.real_operands,
	}
end

return x86_64