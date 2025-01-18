-- moondust x64 assembler
local NO_BASE = 5
local RIP_RELATIVE = 5
local scale_bits = {[1] = 0x00, [2] = 0x40, [4] = 0x80, [8] = 0xC0}
return function(Assembler)
	do -- registers
		local reginfo = {}

		for i, name in ipairs({"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"}) do
			local reg_index = i - 1
			reginfo["r" .. name] = {
				bits = 64,
				is_extended = false,
				i = reg_index,
			}
			reginfo["r" .. (reg_index + 8)] = {
				bits = 64,
				is_extended = true,
				i = reg_index,
			}
			reginfo["k" .. i] = {
				bits = 64,
				is_extended = false,
				i = reg_index,
				class = "mask",
			}
			reginfo["e" .. name] = {
				bits = 32,
				is_extended = false,
				i = reg_index,
			}
			reginfo["r" .. (reg_index + 8) .. "d"] = {
				bits = 32,
				is_extended = true,
				i = reg_index,
			}
		end

		local function create_register_family(prefix, bits, count, options)
			for i = 0, count - 1 do
				local name = prefix .. i
				reginfo[name] = {
					bits = bits,
					is_extended = i > 7,
					i = i % 8,
					class = options.class,
					width = options.width,
				}
			end
		end

		-- Define register families
		create_register_family("xmm", 128, 16, {class = "simd", width = 128})
		create_register_family("ymm", 256, 16, {class = "simd", width = 256})
		create_register_family("zmm", 512, 32, {class = "simd", width = 512})
		reginfo.rip = {bits = 64, rip = true, class = "ip", i = 5}

		local function validate_register_name(reg_name)
			if not reginfo[reg_name] then
				error(reg_name .. " is not a valid register", 2)
			end
		end

		local Register = {}
		Register.__index = Register

		function Register:pure_displacement()
			return self.indirect and
				self.disp and
				not self.reg and
				not self.base and
				not self.index
		end

		function Register:is_indirect()
			return self.indirect or self.index or self.scale or self.base or self.rip
		end

		function Register:__tostring()
			if self.reg then
				if self.indirect then
					if self.disp then
						return "[" .. self.reg .. " " .. (
								self.disp >= 0 and
								"+" or
								"-"
							) .. " " .. math.abs(self.disp) .. "]"
					end

					return "[" .. self.reg .. "]"
				end

				return self.reg
			end

			local str = "["

			if self.base then str = str .. self.base end

			if self.index then
				if self.base then str = str .. " + " end

				str = str .. self.index
			end

			if self.scale then str = str .. "*" .. self.scale end

			if self.disp then
				str = str .. " " .. (
						self.disp >= 0 and
						"+" or
						"-"
					) .. " " .. (
						type(self.disp) == "cdata" and
						(
							"%p"
						):format(self.disp) or
						math.abs(self.disp)
					)
			end

			str = str .. "]"
			return str
		end

		local function copy(self)
			local new = {}

			for k, v in pairs(self) do
				new[k] = v
			end

			return new
		end

		function Register:__mul(scale)
			local new = copy(self)
			new.indirect = true
			new.reg = nil
			new.index = self.reg or self.index
			new.scale = scale
			return Register.new(new)
		end

		function Register:__add(other)
			local new = copy(self)
			new.indirect = true
			new.reg = nil

			if type(other) == "number" then
				if self.rip then
					local new = copy(self)
					new.disp = other
					return Register.new(new)
				elseif self.index then
					-- We already have an index operation, just add displacement
					new.disp = other
				else
					-- Simple base + displacement
					new.reg = self.reg
					new.disp = other
					new.base = self.reg or self.base
				end
			else
				-- Handle register addition
				if self.index then
					-- If we already have an index, preserve it and add base
					new.base = other.reg
				else
					if other.scale then
						-- If other has scale, it's an index operation
						new.base = self.reg
						new.index = other.index
						new.scale = other.scale
					else
						-- Simple base + index
						new.base = self.reg
						new.index = other.reg
					end
				end
			end

			return Register.new(new)
		end

		function Register:__sub(other)
			return self:__add(-other)
		end

		function Register:memory_address()
			local new = copy(self)
			new.indirect = true
			return Register.new(new)
		end

		function Register.new(val)
			if tonumber(val) then
				return setmetatable({disp = val, indirect = true}, Register)
			elseif type(val) == "string" then
				validate_register_name(val)
				local new = {reg = val}

				for k, v in pairs(reginfo[val]) do
					new[k] = v
				end

				assert(type(new.i) == "number", "Register index must be a number")
				return setmetatable(new, Register)
			elseif type(val) == "table" then
				local new = {}

				if val.indirect and val.disp and not (val.reg or val.base or val.index) then
					new.i = 0

					for k, v in pairs(val) do
						new[k] = v
					end

					return setmetatable(new, Register)
				end

				for _, key in ipairs({"reg", "index", "base"}) do
					if val[key] then
						validate_register_name(val[key])
						new[key] = val[key]

						for k, v in pairs(reginfo[val[key]]) do
							if not new[k] then new[k] = v end
						end
					end
				end

				for k, v in pairs(val) do
					if k ~= "reg" and k ~= "index" and k ~= "base" then new[k] = v end
				end

				for _, key in ipairs({"reg", "index", "base"}) do
					if new[key] then
						assert(type(new.i) == "number", "Register index must be a number")
						return setmetatable(new, Register)
					end
				end

				error("Table must contain at least one valid register reference", 2)
			end

			error("Invalid register specification: " .. tostring(val), 2)
		end

		Assembler.Register = Register
		Assembler.Registers = {}

		for name, info in pairs(reginfo) do
			Assembler.Registers[name] = Register.new(name)
		end

		setmetatable(
			Assembler.Registers,
			{
				__index = function(_, key)
					error("Invalid register: " .. tostring(key), 2)
				end,
				__call = function(_, val)
					return Register.new(val)
				end,
			}
		)
	end

	local R = Assembler.Registers

	do
		local ctx
		local Instruction = {}
		Instruction.__index = Instruction

		function Instruction:prefix(what)
			self.ctx.prefix = self.ctx.prefix or {}

			for i, v in ipairs(self.ctx.prefix) do
				if v == what then return end
			end

			table.insert(self.ctx.prefix, what)
			return self
		end

		function Instruction:wide_mode()
			return self:prefix("rex_w")
		end

		function Instruction:extend_modrm_reg()
			return self:prefix("rex_r")
		end

		function Instruction:extend_sib_index()
			return self:prefix("rex_x")
		end

		function Instruction:extend_modrm_rm()
			return self:prefix("rex_b")
		end

		function Instruction:opcode(...)
			self.ctx.opcode = {...}
			return self
		end

		function Instruction:modrm_mode(v)
			self.ctx.modrm = self.ctx.modrm or {}
			self.ctx.modrm.mode = v
			return self
		end

		function Instruction:modrm_reg(v)
			self.ctx.modrm = self.ctx.modrm or {}
			self.ctx.modrm.reg = v
			return self
		end

		function Instruction:modrm_rm(v)
			self.ctx.modrm = self.ctx.modrm or {}
			self.ctx.modrm.rm = v
			return self
		end

		Instruction.extend_sib_base = Instruction.extend_modrm_rm
		Instruction.extend_opcode_reg = Instruction.extend_modrm_rm

		function Instruction:modrm_use_sib()
			self.ctx.modrm = self.ctx.modrm or {}
			self.ctx.modrm.rm = 4
			return self
		end

		function Instruction:sib_scale(v)
			self.ctx.sib = self.ctx.sib or {}
			self.ctx.sib.scale = v
			return self
		end

		function Instruction:sib_reg(v)
			self.ctx.sib = self.ctx.sib or {}
			self.ctx.sib.index = v
			return self
		end

		function Instruction:sib_base(v)
			self.ctx.sib = self.ctx.sib or {}
			self.ctx.sib.base = v
			return self
		end

		function Instruction:displace(num)
			self.ctx.disp = num
			return self
		end

		function Instruction:rex_reg(reg2, reg1, index_reg)
			if (reg1 and reg1.bits == 64) or (reg2 and reg2.bits == 64) then
				self:wide_mode()
			end

			if reg1 and reg1.is_extended then self:extend_modrm_reg() end

			if index_reg and index_reg.is_extended then self:extend_sib_index() end

			if reg2 and reg2.is_extended then self:extend_modrm_rm() end

			return self
		end

		function Instruction:reg_reg(reg1, reg2)
			if reg2.indirect and reg2.disp and not reg2.reg and not reg2.base and not reg2.index then
				self:modrm_mode("indirect") -- 0 = indirect
				self:modrm_reg(reg1.i)
				self:modrm_use_sib()
				self:sib_scale(1)
				self:sib_base(NO_BASE) -- 5 = no base
				self:displace(reg2.disp)
				return self
			elseif reg1.indirect and reg1.disp and not reg1.reg and not reg1.base and not reg1.index then
				self:modrm_mode("indirect")
				self:modrm_reg(reg2.i)
				self:modrm_use_sib()
				self:sib_scale(1)
				self:sib_base(NO_BASE)
				self:displace(reg1.disp)
				return self
			end

			if not reg2.indirect and not reg2.index and not reg2.scale and not reg2.rip then
				self:modrm_mode("direct")
				self:modrm_reg(reg1.i)
				self:modrm_rm(reg2.i)
				return self
			end

			-- Special case: r12/rsp used as base requires SIB byte
			if reg2.indirect and (reg2.reg == "r12" or reg2.reg == "rsp") then
				self:modrm_mode("indirect")
				self:modrm_reg(reg1.i)
				self:modrm_use_sib()
				self:sib_scale(1)
				self:sib_base(reg2.i)
				return self
			end

			if reg2.rip then
				self:modrm_mode("indirect")
				self:modrm_reg(reg1.i)
				self:modrm_rm(RIP_RELATIVE)
				self:displace(reg2.disp or 0)
				return self
			end

			if reg2.index and reg2.scale and not reg2.base then
				self:modrm_mode("indirect")
				self:modrm_reg(reg1.i)
				self:modrm_use_sib()
				self:sib_scale(reg2.scale)
				self:sib_reg(R[reg2.index].i)
				self:sib_base(NO_BASE)
				self:displace(reg2.disp or 0)
				return self
			end

			local mod = "indirect"
			local effective_disp = nil
			local disp = reg2.disp
			local is_bp = reg2.reg and (reg2.reg == "ebp" or reg2.reg == "rbp")

			if not disp and reg2.reg and (is_bp or reg2.reg == "r13") then
				mod = "indirect8"
				effective_disp = 0
			elseif not disp or (disp == 0 and not is_bp) then
				mod = "indirect"
			elseif disp >= -128 and disp <= 127 then
				mod = "indirect8"
				effective_disp = disp
			else
				mod = "indirect32"
				effective_disp = disp
			end

			if reg2.index or reg2.scale or reg2.reg == "rsp" or reg2.reg == "esp" then
				self:modrm_mode(mod)
				self:modrm_reg(reg1.i)
				self:modrm_use_sib()
				local index_reg = reg2.index and R[reg2.index] or nil
				local base_reg = reg2.base and R[reg2.base] or reg2
				self:sib_scale(reg2.scale)
				self:sib_reg(index_reg and index_reg.i)
				self:sib_base(base_reg and base_reg.i)
			else
				self:modrm_mode(mod)
				self:modrm_reg(reg1.i)
				self:modrm_rm(reg2.i)
			end

			self:displace(effective_disp)
			return self
		end

		function Instruction:encode()
			return self.asm:emit_instruction(self.ctx)
		end

		function Assembler:ins()
			return setmetatable({ctx = {}, asm = self}, Instruction)
		end

		function Assembler:opcode(...)
			self:ins():opcode(...):encode()
		end
	end

	do
		local function has_key(tbl, key)
			for i, v in ipairs(tbl) do
				if v == key then return true end
			end

			return false
		end

		local function emit_exclusive_key(out, prefixes, group)
			local done

			for _, prefix in ipairs(prefixes) do
				local byte = group[prefix]

				if byte then
					table.insert(out, byte)
					done = prefix

					break
				end
			end

			if done then
				for _, prefix in ipairs(prefixes) do
					if prefix ~= done then
						local byte = group[prefix]

						if byte then
							local other_keys = {}

							for key in pairs(group) do
								if key ~= done then table.insert(other_keys, key) end
							end

							error(done .. " cannot coexist with " .. table.concat(other_keys, ", "))
						end
					end
				end
			end
		end

		local legacy_prefixes = {
			group_1 = {
				lock = 0xf0,
				repne = 0xf2,
				repe = 0xf3,
			},
			group_2 = {
				cs_segment_override = 0x2E,
				ss_segment_override = 0x36,
				ds_segment_override = 0x3E,
				es_segment_override = 0x26,
				fs_segment_override = 0x64,
				gs_segment_override = 0x65,
				branch_not_taken = 0x2E,
				branch_taken = 0x3E,
			},
			group_3 = {
				operand_size_override = 0x66,
			},
			group_4 = {
				address_size_override = 0x67,
			},
		}

		local function emit_group_prefix(self, group, prefixes)
			for key, byte in pairs(group) do
				if has_key(prefixes, key) then
					emit_exclusive_key(self, prefixes, group)

					break
				end
			end
		end

		local scale_bits = {[1] = 0b00000000, [2] = 0b01000000, [4] = 0b10000000, [8] = 0b11000000}

		local function prefix(p)
			local out = {}
			emit_group_prefix(out, legacy_prefixes.group_1, p)
			emit_group_prefix(out, legacy_prefixes.group_2, p)
			emit_group_prefix(out, legacy_prefixes.group_3, p)
			emit_group_prefix(out, legacy_prefixes.group_4, p)

			if
				has_key(p, "rex_w") or
				has_key(p, "rex_r") or
				has_key(p, "rex_x") or
				has_key(p, "rex_b")
			then
				local byte = 0b01000000

				if has_key(p, "rex_w") then byte = bit.bor(byte, 0b00001000) end -- Operand size override (0 = default, 1 = 64-bit)
				if has_key(p, "rex_r") then byte = bit.bor(byte, 0b00000100) end -- Extension of ModR/M reg field
				if has_key(p, "rex_x") then byte = bit.bor(byte, 0b00000010) end -- Extension of SIB index field
				if has_key(p, "rex_b") then byte = bit.bor(byte, 0b00000001) end -- Extension of ModR/M r/m field, SIB base field, or opcode reg field
				if byte ~= 0b01000000 then table.insert(out, byte) end
			elseif p.vex_pp and p.vex_l and p.vex_r then
				error("2-byte VEX prefix not implemented")
			elseif
				p.vex_mmmm and
				p.vex_pp and
				p.vex_l and
				p.vex_w and
				(
					p.vex_r or
					p.vex_x or
					p.vex_b
				)
			then
				error("3-byte VEX prefix not implemented")
			elseif
				p.vex_mm and
				p.vex_pp and
				p.vex_l and
				p.vex_w and
				(
					p.vex_r or
					p.vex_x or
					p.vex_b
				)
				and
				p.vex_z and
				p.vex_b
			then
				error("EVEX prefix not implemented")
			end

			return unpack(out)
		end

		local function opcode(...)
			local len = select("#", ...)
			assert(len >= 1 and len <= 3, "opcode must be 1-3 bytes")
			return ...
		end

		local map = {
			indirect = 0b00000000,
			indirect8 = 0b01000000,
			indirect32 = 0b10000000,
			direct = 0b11000000,
		}
		local valid_scales = {[1] = true, [2] = true, [4] = true, [8] = true}

		local function validate_scale(scale)
			if not scale then return end

			if not valid_scales[scale] then
				error("Invalid scale value: " .. tostring(scale) .. ". Must be 1, 2, 4, or 8", 2)
			end
		end

		local function modrm(mode, reg, rm)
			assert(reg >= 0 and reg <= 7, "reg must be between 0 and 7")
			assert(rm >= 0 and rm <= 7, "rm must be between 0 and 7")
			assert(map[mode], "invalid ModR/M mode: ", mode)
			local byte = map[mode] -- mod bits 0b**000000
			byte = bit.bor(byte, bit.lshift(reg, 3)) -- reg bits 0b00***000
			byte = bit.bor(byte, rm) -- R/M bits 0b00000***
			return byte
		end

		local function sib(scale, index, base)
			validate_scale(scale)
			assert(index ~= 4, "sib index cannot be 4, however it can be nil")
			assert(index == nil or index >= 0 and index <= 7, "index register must be between 0 - 7")
			assert(base >= 0 and base <= 7, "base register must be between 0 - 7")
			local byte = scale_bits[scale] or 0 -- scale bits 0b**000000
			byte = bit.bor(byte, bit.lshift(index or 4, 3)) -- index bits 0b00***000
			byte = bit.bor(byte, base) -- base bits 0b00000***
			return byte
		end

		local SIB_INDICATOR = 4
		local RIP_RELATIVE = 5

		local function validate_displacement(disp)
			if disp == nil then return end

			if type(disp) == "number" then return end

			if type(disp) == "cdata" and tonumber(disp) then return end

			error("Displacement must be a number, got: " .. type(disp), 2)
		end

		function Assembler:emit_instruction(info)
			if info.prefix then self:emit(prefix(info.prefix)) end

			if info.opcode then self:emit(opcode(unpack(info.opcode))) end

			local mode

			if info.modrm then
				mode = info.modrm.mode

				if mode ~= "direct" and not info.sib and info.modrm.rm == SIB_INDICATOR then
					error("SIB required", 2)
				end

				if not info.disp then
					if mode == "indirect8" then
						error("8-bit displacement required", 2)
					elseif mode == "indirect32" then
						error("32-bit displacement required", 2)
					end

					if mode == "indirect" then
						if info.modrm.rm == RIP_RELATIVE then
							error("32-bit displacement required for displacement-only addressing", 2)
						end
					end

					if mode == "direct" or mode == "indirect" then
						if info.sib and info.sib.base == RIP_RELATIVE then
							error("32-bit displacement required for rip-relative addressing", 2)
						end
					end
				end

				self:emit(modrm(info.modrm.mode, info.modrm.reg, info.modrm.rm))
			end

			if info.sib then
				if info.prefix and has_key(info.prefix, "rex_x") and info.sib.index == 4 then
					error("Cannot use RSP/R12 as SIB index register")
				end

				self:emit(sib(info.sib.scale, info.sib.index, info.sib.base))
			end

			if info.disp then
				local num = info.disp
				validate_displacement(num)
				local signed = true
				local bits = 8

				if
					mode == "indirect32" or
					(
						mode == "indirect" and
						(
							info.modrm.rm == 5 or
							(
								info.sib and
								info.sib.base == 5
							)
						)
					)
				then
					bits = 32
				end

				if type(num) == "cdata" then bits = 64 end

				self:emit_number(num, bits, signed)
			end
		end
	end

	do -- mov
		local function imm_to_reg(self, dst, imm, signed)
			local ins = self:ins()
			ins:rex_reg(dst)
			ins:opcode(0xB8 + dst.i)
			ins:encode()

			if dst.bits == 64 then
				if signed then self:emit_i64(imm) else self:emit_u64(imm) end
			else
				if signed then self:emit_i32(imm) else self:emit_u32(imm) end
			end
		end

		local function reg_to_reg(self, dst, src)
			local ins = self:ins()
			ins:rex_reg(dst, src)
			ins:opcode(0x89)
			ins:reg_reg(src, dst)
			ins:encode()
		end

		local function mem_to_reg(self, dst, src)
			local ins = self:ins()
			ins:rex_reg(dst, src)
			ins:opcode(0x8B)
			ins:reg_reg(dst, src)
			ins:encode()
		end

		local function reg_to_mem(self, dst, src)
			local ins = self:ins()
			ins:rex_reg(src, dst)
			ins:opcode(0x89)
			ins:reg_reg(src, dst)
			ins:encode()
		end

		local function reg_to_moff(self, dst, src)
			if type(dst.disp) == "cdata" then
				if src.reg == "rax" then
					local ins = self:ins()
					ins:rex_reg(src)
					ins:opcode(0xA3)
					ins:encode()
					self:emit_u64(dst.disp)
					return
				end

				self:push(R.r11)
				self:mov(R.r11, dst.disp)

				do
					local ins = self:ins()
					ins:rex_reg(R.r11:memory_address(), src)
					ins:opcode(0x89)
					ins:reg_reg(src, R.r11:memory_address())
					ins:encode()
				end

				self:pop(R.r11)
			else
				local ins = self:ins()
				ins:rex_reg(dst, src)
				ins:opcode(0x89)
				ins:reg_reg(src, dst)
				ins:encode()
			end
		end

		local function moff_to_reg(self, dst, src)
			if type(src.disp) == "cdata" then
				if dst.reg == "rax" then
					local ins = self:ins()
					ins:rex_reg(dst)
					ins:opcode(0xA1)
					ins:encode()
					self:emit_u64(src.disp)
					return
				end

				self:mov(dst, src.disp)
				local ins = self:ins()
				ins:rex_reg(dst, dst)
				ins:opcode(0x8B)
				ins:reg_reg(dst, dst:memory_address())
				ins:encode()
			else
				local ins = self:ins()
				ins:rex_reg(src, dst)
				ins:opcode(0x8B)
				ins:reg_reg(dst, src)
				ins:encode()
			end
		end

		function Assembler:mov(dst, src, signed)
			if tonumber(src) then
				imm_to_reg(self, dst, src, signed)
			elseif src:pure_displacement() then
				moff_to_reg(self, dst, src)
			elseif dst:pure_displacement() then
				reg_to_moff(self, dst, src)
			elseif src:is_indirect() then
				mem_to_reg(self, dst, src)
			elseif dst:is_indirect() then
				reg_to_mem(self, dst, src)
			elseif dst.reg and src.reg then
				reg_to_reg(self, dst, src)
			else
				error(
					"mov " .. tostring(dst) .. ", " .. tostring(src) .. " is not a valid combination",
					2
				)
			end
		end
	end

	do -- jump labels
		-- Common jump function template to avoid code duplication
		local function jump_function(...)
			local opcodes = {...}
			return function(self, label)
				local jump_pos = self.pos

				if self.labels[label] and self.labels[label].defined then
					-- Label already defined, calculate relative offset for backward jump
					local target_pos = self.labels[label].pos
					local rel32 = target_pos - (jump_pos + 4 + #opcodes) -- 6 bytes: 2 for opcode, 4 for offset
					self:opcode(unpack(opcodes))
					self:emit_i32(rel32)
				else
					-- Forward jump to undefined label
					if not self.labels[label] then
						self.labels[label] = {references = {}, defined = false}
					end

					table.insert(
						self.labels[label].references,
						{
							pos = jump_pos,
							type = #opcodes == 1 and "near" or "long_conditional",
							size = 4 + #opcodes, -- 2 bytes opcode + 4 bytes offset
						}
					)
					self:opcode(unpack(opcodes))
					self:emit(0, 0, 0, 0) -- Placeholder for the 32-bit offset
				end
			end
		end

		Assembler.je = jump_function(0x0F, 0x84)
		Assembler.jne = jump_function(0x0F, 0x85)
		Assembler.jl = jump_function(0x0F, 0x8C)
		Assembler.jle = jump_function(0x0F, 0x8E)
		Assembler.jg = jump_function(0x0F, 0x8F)
		Assembler.jge = jump_function(0x0F, 0x8D)
		Assembler.jmp = jump_function(0xE9)
		local map = {
			["=="] = Assembler.je,
			["~="] = Assembler.jne,
			["<"] = Assembler.jl,
			["<="] = Assembler.jle,
			[">"] = Assembler.jg,
			[">="] = Assembler.jge,
		}

		function Assembler:jump(label, cond)
			if not cond then self:jmp(label) else map[cond](self, label) end
		end

		-- Label definition remains the same
		function Assembler:label(name)
			if self.labels[name] and self.labels[name].defined then
				error(string.format("Label '%s' already defined", name))
			end

			if not self.labels[name] then
				self.labels[name] = {references = {}, defined = false}
			end

			self.labels[name].pos = self.pos
			self.labels[name].defined = true
		end

		function Assembler:resolve_labels(code)
			local bytes = {string.byte(code, 1, #code)}

			for name, label in pairs(self.labels or {}) do
				if not label.defined then error("Undefined label: " .. name) end

				for _, ref in ipairs(label.references) do
					local next_instruction_pos = ref.pos + ref.size
					local offset = label.pos - next_instruction_pos
					local offset_pos = ref.pos + (ref.type == "near" and 1 or 2)
					bytes[offset_pos] = bit.band(offset, 0xFF)
					bytes[offset_pos + 1] = bit.band(bit.rshift(offset, 8), 0xFF)
					bytes[offset_pos + 2] = bit.band(bit.rshift(offset, 16), 0xFF)
					bytes[offset_pos + 3] = bit.band(bit.rshift(offset, 24), 0xFF)
				end
			end

			return string.char(unpack(bytes))
		end
	end

	do -- basic functions
		function Assembler:ret()
			self:opcode(0xC3)
		end

		function Assembler:push(reg)
			local ins = self:ins()

			if reg.is_extended then ins:extend_opcode_reg() end

			ins:opcode(0x50 + reg.i)
			ins:encode()
		end

		function Assembler:pop(reg)
			local ins = self:ins()

			if reg.is_extended then ins:extend_opcode_reg() end

			ins:opcode(0x58 + reg.i)
			ins:encode()
		end

		function Assembler:syscall()
			self:opcode(0x0F, 0x05):encode()
		end

		local function handle_immediate_operation(self, reg, imm, extension)
			local ins = self:ins()
			ins:rex_reg(reg)

			if imm >= -128 and imm <= 127 then
				ins:opcode(0x83)
				ins:modrm_mode("direct")
				ins:modrm_reg(extension)
				ins:modrm_rm(reg.i)
				ins:encode()
				self:emit_i8(imm)
			else
				ins:opcode(0x81)
				ins:modrm_mode("direct")
				ins:modrm_reg(extension)
				ins:modrm_rm(reg.i)
				ins:encode()
				self:emit_i32(imm)
			end
		end

		do
			function Assembler:add(reg1, op2)
				if type(op2) == "number" then
					local ins = self:ins()
					ins:rex_reg(reg1)

					if op2 >= -128 and op2 <= 127 then
						ins:opcode(0x83)
						ins:modrm_mode("direct")
						ins:modrm_reg(0) -- extension for ADD
						ins:modrm_rm(reg1.i)
						ins:encode()
						self:emit_i8(op2)
					else
						ins:opcode(0x81)
						ins:modrm_mode("direct")
						ins:modrm_reg(0) -- extension for ADD
						ins:modrm_rm(reg1.i)
						ins:encode()
						self:emit_i32(op2)
					end
				else
					local reg2 = op2
					local ins = self:ins()
					ins:rex_reg(reg1, reg2)
					ins:opcode(0x03)
					ins:reg_reg(reg1, reg2)
					ins:encode()
				end
			end

			function Assembler:sub(reg1, op2)
				if type(op2) == "number" then
					local ins = self:ins()
					ins:rex_reg(reg1)

					if op2 >= -128 and op2 <= 127 then
						ins:opcode(0x83)
						ins:modrm_mode("direct")
						ins:modrm_reg(5) -- extension for SUB
						ins:modrm_rm(reg1.i)
						ins:encode()
						self:emit_i8(op2)
					else
						ins:opcode(0x81)
						ins:modrm_mode("direct")
						ins:modrm_reg(5) -- extension for SUB
						ins:modrm_rm(reg1.i)
						ins:encode()
						self:emit_i32(op2)
					end
				else
					local reg2 = op2
					local ins = self:ins()
					ins:rex_reg(reg1, reg2)
					ins:opcode(0x2B)
					ins:reg_reg(reg1, reg2)
					ins:encode()
				end
			end

			function Assembler:cmp(reg1, op2)
				assert(reg1.bits == 64, "only supports 64-bit registers")

				if type(op2) == "number" then
					local ins = self:ins()
					ins:rex_reg(reg1)

					if op2 >= -128 and op2 <= 127 then
						ins:opcode(0x83)
						ins:modrm_mode("direct")
						ins:modrm_reg(7) -- extension for CMP
						ins:modrm_rm(reg1.i)
						ins:encode()
						self:emit_i8(op2)
					else
						ins:opcode(0x81)
						ins:modrm_mode("direct")
						ins:modrm_reg(7) -- extension for CMP
						ins:modrm_rm(reg1.i)
						ins:encode()
						self:emit_i32(op2)
					end
				else
					local reg2 = op2
					local ins = self:ins()
					ins:rex_reg(reg1, reg2)
					ins:opcode(0x3B)
					ins:reg_reg(reg1, reg2)
					ins:encode()
				end
			end
		end

		function Assembler:inc(reg)
			local ins = self:ins()
			ins:rex_reg(reg)
			ins:opcode(0xFF)
			ins:modrm_mode("direct")
			ins:modrm_reg(0)
			ins:modrm_rm(reg.i)
			ins:encode()
		end

		function Assembler:dec(reg)
			local ins = self:ins()
			ins:rex_reg(reg)
			ins:opcode(0xFF)
			ins:modrm_mode("direct")
			ins:modrm_reg(1)
			ins:modrm_rm(reg.i)
			ins:encode()
		end

		function Assembler:mul(reg)
			local ins = self:ins()
			ins:rex_reg(reg)
			ins:opcode(0xF7)
			ins:modrm_mode("direct")
			ins:modrm_reg(4)
			ins:modrm_rm(reg.i)
			ins:encode()
		end

		do
			do -- xor
				local function reg_to_reg(self, dst, src)
					local ins = self:ins()
					ins:rex_reg(dst, src)
					ins:opcode(0x33)
					ins:reg_reg(dst, src)
					ins:encode()
				end

				local function mem_to_reg(self, dst, src)
					local ins = self:ins()
					ins:rex_reg(dst, src)
					ins:opcode(0x33) -- XOR r64, r/m64
					ins:reg_reg(dst, src)
					ins:encode()
				end

				local function reg_to_mem(self, dst, src)
					local ins = self:ins()
					ins:rex_reg(src, dst)
					ins:opcode(0x31) -- XOR r/m64, r64
					ins:reg_reg(src, dst)
					ins:encode()
				end

				local function imm_to_reg(self, dst, imm)
					handle_immediate_operation(self, dst, imm, 6) -- 6 is XOR in ModR/M
				end

				local function imm_to_mem(self, dst, imm)
					local ins = self:ins()
					ins:rex_reg(dst)

					if imm >= -128 and imm <= 127 then
						ins:opcode(0x83) -- XOR r/m64, imm8
					else
						ins:opcode(0x81) -- XOR r/m64, imm32
					end

					-- Set up ModR/M byte
					ins:modrm_mode("indirect") -- 00 in ModR/M
					ins:modrm_reg(6) -- 110 in ModR/M (6 is XOR operation)
					ins:modrm_use_sib() -- Use SIB byte (rm = 4)
					-- Set up SIB byte
					ins:sib_scale(1)
					ins:sib_base(NO_BASE) -- No base register, use displacement only
					-- Add displacement
					ins:displace(dst.disp)
					-- Emit the instruction
					ins:encode()

					-- Emit the immediate value
					if imm >= -128 and imm <= 127 then
						self:emit_i8(imm)
					else
						self:emit_i32(imm)
					end
				end

				function Assembler:xor(dst, src)
					if tonumber(src) then
						-- Immediate operand
						if dst:is_indirect() then
							imm_to_mem(self, dst, src)
						else
							imm_to_reg(self, dst, src)
						end
					elseif src:is_indirect() then
						-- Memory source
						if dst:is_indirect() then
							error("Cannot XOR between two memory locations")
						end

						mem_to_reg(self, dst, src)
					elseif dst:is_indirect() then
						-- Memory destination
						reg_to_mem(self, dst, src)
					else
						-- Register to register
						reg_to_reg(self, dst, src)
					end
				end
			end
		end
	end

	do -- debug
		require("moondust.breakpoint")(Assembler)
	end

	require("moondust.wip_x64")(Assembler)
end
