local ffi = require("ffi")
local util = require("moondust.util")


local x86_64 = {}

_G.x86_64 = x86_64
x86_64.map = require("moondust.x86_64_data")
_G.x86_64 = nil

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

		x86_64.reginfo["rip"] = {
			bits = 64,
			rip = true,
		}
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

	local rip

	if type(op2) == "number" then
		reg2 = op2
	else
		index = x86_64.reginfo[op2.index] and x86_64.reginfo[op2.index].index
		reg2 = x86_64.reginfo[op2.reg] and x86_64.reginfo[op2.reg].index

		if op2.indirect then
			base = reg2
			reg2 = nil
		end

		if x86_64.reginfo[op2.reg] and x86_64.reginfo[op2.reg].rip then
			rip = true
		end

		disp = op2.disp
		disp_type = "uint32_t"
		scale = op2.scale
	end

	if rip then
		modrm = 0b00111101
		disp = disp or 0
	end

	-- mov rcx, rbx
	if reg1 and reg2 then
		modrm = 0b11000000
		modrm = bit.bor(modrm, reg1)
		modrm = bit.bor(modrm, bit.lshift(reg2, 3))
	end

	--mov rcx, [0xdead]
	if reg1 and disp and not reg2 and not base and not index and not scale and not rip then
		modrm = 0b00000100
		modrm = bit.bor(modrm, bit.lshift(reg1, 3))
		sib = 0b00100101
		disp_type = "uint32_t"
	elseif reg1 and base and not reg2 and not index and not scale then
		modrm = bit.bor(bit.lshift(reg1, 3), base)
	elseif reg1 and base and scale then
		if index then
			modrm = 0b10000100
		elseif rip then
			modrm = 0b00000101
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

function x86_64.get_typestring(mnemonic, ...)
	if not x86_64.map[mnemonic] then
		return nil, "no such function " .. mnemonic .. "\ndid you mean one of these?\n" .. helper_error(x86_64.map, mnemonic)
	end

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