-- moondust x64 assembler
local MOD_NO_DISP = 0
local MOD_DISP8 = 1
local MOD_DISP32 = 2
local MOD_REG = 3
local SIB_INDICATOR = 4
local NO_INDEX = 4
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

		local function validate_scale(scale)
			local valid_scales = {[1] = true, [2] = true, [4] = true, [8] = true}

			if scale and not valid_scales[scale] then
				error("Invalid scale value: " .. tostring(scale) .. ". Must be 1, 2, 4, or 8", 2)
			end
		end

		local function validate_displacement(disp)
			if disp == nil then return end

			if type(disp) == "number" then return end

			if type(disp) == "cdata" and tonumber(disp) then return end

			error("Displacement must be a number, got: " .. type(disp), 2)
		end

		local function validate_register_name(reg_name)
			if not reginfo[reg_name] then
				error(reg_name .. " is not a valid register", 2)
			end
		end

		local function validate_combinations(result)
			if result.rip then
				if result.index or result.scale or result.base then

				--error("RIP-relative addressing cannot use index, scale, or base", 2)
				end
			end

			if result.index == "esp" or result.index == "rsp" then
				error("ESP/RSP cannot be used as an index register", 2)
			end

			if result.scale and not result.index then
				error("Scale can only be used with an index register", 2)
			end

			if result.class == "simd" then
				if
					result.index and
					reginfo[result.index].class == "simd" and
					reginfo[result.index].width ~= result.width
				then
					error("SIMD registers must have matching widths", 2)
				end
			end

			if result.class == "mask" then
				if result.index or result.scale then
					error("Mask registers cannot be used with index or scale", 2)
				end
			end
		end

		local function REG(val)
			if tonumber(val) then
				return {disp = val, indirect = true}
			elseif type(val) == "string" then
				validate_register_name(val)
				local new = {reg = val}

				for k, v in pairs(reginfo[val]) do
					new[k] = v
				end

				validate_combinations(new)
				assert(type(new.i) == "number", "Register index must be a number")
				return new
			elseif type(val) == "table" then
				local new = {}

				if val.indirect and val.disp and not (val.reg or val.base or val.index) then
					validate_displacement(val.disp)
					new.i = 0

					for k, v in pairs(val) do
						new[k] = v
					end

					return new
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

				validate_scale(val.scale)
				validate_displacement(val.disp)

				for k, v in pairs(val) do
					if k ~= "reg" and k ~= "index" and k ~= "base" then new[k] = v end
				end

				validate_combinations(new)

				for _, key in ipairs({"reg", "index", "base"}) do
					if new[key] then
						assert(type(new.i) == "number", "Register index must be a number")
						return new
					end
				end

				error("Table must contain at least one valid register reference", 2)
			end

			error("Invalid register specification: " .. tostring(val), 2)
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
			return setmetatable(REG(val), Register)
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

		Instruction.extend_sib_base = Instruction.extend_modrm_rm
		Instruction.extend_opcode_reg = Instruction.extend_modrm_rm

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
				self:sib_base(5) -- 5 = no base
				self:displace(reg2.disp)
				return self
			elseif reg1.indirect and reg1.disp and not reg1.reg and not reg1.base and not reg1.index then
				self:modrm_mode("indirect")
				self:modrm_reg(reg2.i)
				self:modrm_use_sib()
				self:sib_scale(1)
				self:sib_base(5)
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

		function Instruction:get()
			return self.ctx
		end

		function Assembler:instruction()
			return setmetatable({ctx = {}}, Instruction)
		end
	end

	do
		local function has_key(tbl, key)
			for i, v in ipairs(tbl) do
				if v == key then return true end
			end

			return false
		end

		local function emit_exclusive_key(self, prefixes, group)
			local done

			for _, prefix in ipairs(prefixes) do
				local byte = group[prefix]

				if byte then
					self:emit(byte)
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

		function Assembler:emit_prefix(p)
			emit_group_prefix(self, legacy_prefixes.group_1, p)
			emit_group_prefix(self, legacy_prefixes.group_2, p)
			emit_group_prefix(self, legacy_prefixes.group_3, p)
			emit_group_prefix(self, legacy_prefixes.group_4, p)

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
				if byte ~= 0b01000000 then self:emit(byte) end
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
		end

		function Assembler:emit_opcode(...)
			local len = select("#", ...)
			assert(len >= 1 and len <= 3, "opcode must be 1-3 bytes")
			self:emit(...)
		end

		function Assembler:emit_modrm(mode, reg, rm)
			assert(reg >= 0 and reg <= 7, "reg must be between 0 and 7")
			assert(rm >= 0 and rm <= 7, "rm must be between 0 and 7")
			-- this ignores 16bit mode
			local byte = 0b00000000

			do -- mode bits 0b**000000 
				if mode == "indirect" then
					byte = 0b00000000
				elseif mode == "indirect8" then
					byte = 0b01000000
				elseif mode == "indirect32" then
					byte = 0b10000000
				elseif mode == "direct" then
					byte = 0b11000000
				else
					error(string.format("invalid ModR/M mode: %s", tostring(mode)))
				end
			end

			do -- reg bits 0b00***000
				byte = bit.bor(byte, bit.lshift(reg, 3))
			end

			do -- R/M bits 0b00000***
				byte = bit.bor(byte, rm)
			end

			self:emit(byte)
		end

		function Assembler:emit_sib(scale, index, base)
			assert(scale_bits[scale], "scale must be 1, 2, 4, or 8")
			assert(index ~= 4, "sib index cannot be 4, however it can be nil")
			assert(index == nil or index >= 0 and index <= 7, "index register must be between 0 - 7")
			assert(base >= 0 and base <= 7, "base register must be between 0 - 7")
			local byte = 0b00000000
			byte = bit.bor(byte, scale_bits[scale])
			byte = bit.bor(byte, bit.lshift(index or 4, 3))
			byte = bit.bor(byte, base)
			self:emit(byte)
		end

		function Assembler:emit_instruction(info)
			if info.prefix then self:emit_prefix(info.prefix) end

			if info.opcode then self:emit_opcode(unpack(info.opcode)) end

			local mode -- Moved mode declaration to outer scope
			if info.modrm then
				mode = info.modrm.mode -- Just assign here instead of declaring
				if mode == "indirect8" then
					if not info.disp then error("8-bit displacement required", 2) end
				elseif mode == "indirect32" then
					if not info.disp then error("32-bit displacement required", 2) end
				end

				if mode ~= "direct" and info.modrm.rm == 4 then
					if not info.sib then error("SIB required", 2) end
				end

				if mode == "indirect" and info.modrm.rm == 5 then
					if not info.disp then
						error("32-bit displacement required for displacement-only addressing", 2)
					end
				end

				if mode == "direct" and info.modrm.rm == 5 then
					if not info.disp then

					--error("rip-relative addressing requires displacement", 2)
					end
				end

				if info.sib and info.sib.base == 5 and mode == "indirect" then
					if not info.disp then
						error("32-bit displacement required when SIB base is 5 and mod is 0", 2)
					end
				end

				self:emit_modrm(info.modrm.mode, info.modrm.reg, info.modrm.rm)
			end

			if info.sib then
				self:emit_sib(info.sib.scale, info.sib.index, info.sib.base)
			end

			if info.disp then
				local num = info.disp
				assert(
					type(num) == "number" or type(num) == "cdata",
					"displacement must be a number"
				)
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

	do -- encoding helpers
		function Assembler:rex_reg(reg2, reg1, index_reg)
			self:emit_instruction(self:instruction():rex_reg(reg2, reg1, index_reg):get())
		end

		function Assembler:emit_modrmsib(reg1, reg2)
			self:emit_instruction(self:instruction():reg_reg(reg1, reg2):get())
		end
	end

	do -- mov
		local function imm_to_reg(self, dst, imm, signed)
			self:rex_reg(dst)
			self:emit(0xB8 + dst.i)

			if dst.bits == 64 then
				if signed then self:emit_i64(imm) else self:emit_u64(imm) end
			else
				if signed then self:emit_i32(imm) else self:emit_u32(imm) end
			end
		end

		local function reg_to_reg(self, dst, src)
			local ins = self:instruction()
			ins:rex_reg(dst, src)
			ins:opcode(0x89)
			ins:reg_reg(src, dst)
			self:emit_instruction(ins:get())
		end

		local function mem_to_reg(self, dst, src)
			local ins = self:instruction()
			ins:rex_reg(dst, src)
			ins:opcode(0x8B)
			ins:reg_reg(dst, src)
			self:emit_instruction(ins:get())
		end

		local function reg_to_mem(self, dst, src)
			local ins = self:instruction()
			ins:rex_reg(src, dst)
			ins:opcode(0x89)
			ins:reg_reg(src, dst)
			self:emit_instruction(ins:get())
		end

		local function reg_to_moff(self, dst, src)
			if type(dst.disp) == "cdata" then
				if src.reg == "rax" then
					local ins = self:instruction()
					ins:rex_reg(src)
					ins:opcode(0xA3)
					self:emit_instruction(ins:get())
					self:emit_u64(dst.disp)
					return
				end

				self:push(R.r11)
				self:mov(R.r11, dst.disp)

				do
					local ins = self:instruction()
					ins:rex_reg(R.r11:memory_address(), src)
					ins:opcode(0x89)
					ins:reg_reg(src, R.r11:memory_address())
					self:emit_instruction(ins:get())
				end

				self:pop(R.r11)
			else
				local ins = self:instruction()
				ins:rex_reg(dst, src)
				ins:opcode(0x89)
				ins:reg_reg(src, dst)
				self:emit_instruction(ins:get())
			end
		end

		local function moff_to_reg(self, dst, src)
			if type(src.disp) == "cdata" then
				if dst.reg == "rax" then
					local ins = self:instruction()
					ins:rex_reg(dst)
					ins:opcode(0xA1)
					self:emit_instruction(ins:get())
					self:emit_u64(src.disp)
					return
				end

				self:mov(dst, src.disp)
				local ins = self:instruction()
				ins:rex_reg(dst, dst)
				ins:opcode(0x8B)
				ins:reg_reg(dst, dst:memory_address())
				self:emit_instruction(ins:get())
			else
				local ins = self:instruction()
				ins:rex_reg(src, dst)
				ins:opcode(0x8B)
				ins:reg_reg(dst, src)
				self:emit_instruction(ins:get())
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
		function Assembler:get_reference_label(name, type, size)
			if not self.labels[name] then
				self.labels[name] = {references = {}, defined = false}
			end

			table.insert(self.labels[name].references, {pos = self.pos, type = type, size = size})
			return self.pos
		end

		-- je function
		function Assembler:je(label)
			local ins = self:instruction()
			ins:opcode(0x0F, 0x84)
			self:emit_instruction(ins:get())
			local ref_pos = self:get_reference_label(label, "near", 4)
			self:emit(0, 0, 0, 0)
		end

		function Assembler:jne(label)
			self:emit_opcode(0x0F, 0x85)
			local ref_pos = self:get_reference_label(label, "near", 4)
			self:emit(0, 0, 0, 0)
		end

		function Assembler:jl(label)
			self:emit_opcode(0x0F, 0x8C)
			local ref_pos = self:get_reference_label(label, "near", 4)
			self:emit(0, 0, 0, 0)
		end

		function Assembler:jle(label)
			self:emit_opcode(0x0F, 0x8E)
			local ref_pos = self:get_reference_label(label, "near", 4)
			self:emit(0, 0, 0, 0)
		end

		function Assembler:jg(label)
			local jump_pos = self.pos
			self:emit_opcode(0x0F, 0x8F)

			if not self.labels[label] then
				self.labels[label] = {references = {}, defined = false}
			end

			table.insert(
				self.labels[label].references,
				{
					pos = jump_pos,
					type = "long_conditional",
					size = 6,
				}
			)
			self:emit(0, 0, 0, 0)
		end

		function Assembler:jge(label)
			self:emit_opcode(0x0F, 0x8D)
			local ref_pos = self:get_reference_label(label, "near", 4)
			self:emit(0, 0, 0, 0)
		end

		function Assembler:jne(label)
			local jump_pos = self.pos

			if self.labels[label] and self.labels[label].defined then
				local target_pos = self.labels[label].pos
				local rel32 = target_pos - (jump_pos + 6)
				self:emit_opcode(0x0F, 0x85)
				self:emit_i32(rel32)
			else
				if not self.labels[label] then
					self.labels[label] = {defined = false, references = {}}
				end

				table.insert(
					self.labels[label].references,
					{
						pos = jump_pos,
						type = "jne",
						size = 6,
					}
				)
				self:emit(0x0F, 0x85)
				self:emit(0, 0, 0, 0)
			end
		end

		function Assembler:jmp(label)
			local jump_pos = self.pos
			self:emit_opcode(0xE9)

			if not self.labels[label] then
				self.labels[label] = {references = {}, defined = false}
			end

			table.insert(self.labels[label].references, {
				pos = jump_pos,
				type = "near",
				size = 5,
			})
			self:emit(0, 0, 0, 0)
		end

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
			self:emit_opcode(0xC3)
		end

		function Assembler:push(reg)
			local ins = self:instruction()

			if reg.is_extended then ins:extend_modrm_rm() -- replaces rex_b prefix
			end

			ins:opcode(0x50 + reg.i)
			self:emit_instruction(ins:get())
		end

		function Assembler:pop(reg)
			local ins = self:instruction()

			if reg.is_extended then ins:extend_modrm_rm() -- replaces rex_b prefix
			end

			ins:opcode(0x58 + reg.i)
			self:emit_instruction(ins:get())
		end

		function Assembler:syscall()
			local ins = self:instruction()
			ins:opcode(0x0F, 0x05)
			self:emit_instruction(ins:get())
		end

		local function handle_immediate_operation(self, reg, imm, extension)
			if imm >= -128 and imm <= 127 then
				local ins = self:instruction()
				ins:opcode(0x83)
				ins:modrm_mode("direct")
				ins:modrm_reg(extension)
				ins:modrm_rm(reg.i)
				self:emit_instruction(ins:get())
				self:emit_i8(imm)
			else
				local ins = self:instruction()
				ins:opcode(0x81)
				ins:modrm_mode("direct")
				ins:modrm_reg(extension)
				ins:modrm_rm(reg.i)
				self:emit_instruction(ins:get())
				self:emit_i32(imm)
			end
		end

		do
			function Assembler:add(reg1, op2)
				if type(op2) == "number" then
					self:rex_reg(reg1)
					handle_immediate_operation(self, reg1, op2, 0)
				else
					local reg2 = op2
					self:rex_reg(reg1, reg2)
					self:emit(0x03)
					self:emit_modrmsib(reg1, reg2)
				end
			end

			function Assembler:sub(reg1, op2)
				if type(op2) == "number" then
					self:rex_reg(reg1)
					handle_immediate_operation(self, reg1, op2, 5)
				else
					local reg2 = op2
					self:rex_reg(reg1, reg2)
					self:emit(0x2B)
					self:emit_modrmsib(reg1, reg2)
				end
			end

			function Assembler:cmp(reg1, op2)
				assert(reg1.bits == 64, "only supports 64-bit registers")

				if type(op2) == "number" then
					self:rex_reg(reg1)
					handle_immediate_operation(self, reg1, op2, 7)
				else
					local reg2 = op2
					self:rex_reg(reg1, reg2)
					self:emit(0x3B)
					self:emit_modrmsib(reg1, reg2)
				end
			end
		end

		function Assembler:inc(reg)
			local ins = self:instruction()

			if reg.bits == 64 then ins:wide_mode() end

			if reg.is_extended == 64 then ins:extend_opcode_reg() end

			ins:opcode(0xFF)
			ins:modrm_mode("direct")
			ins:modrm_reg(0)
			ins:modrm_rm(reg.i)
			self:emit_instruction(ins:get())
		end

		function Assembler:dec(reg)
			local ins = self:instruction()

			if reg.bits == 64 then ins:wide_mode() end

			if reg.is_extended == 64 then ins:extend_opcode_reg() end

			ins:opcode(0xFF)
			ins:modrm_mode("direct")
			ins:modrm_reg(1)
			ins:modrm_rm(reg.i)
			self:emit_instruction(ins:get())
		end

		function Assembler:mul(reg)
			self:rex_reg(reg)
			self:emit(0xF7)
			local ins = self:instruction()
			ins:modrm_mode("direct")
			ins:modrm_reg(4)
			ins:modrm_rm(reg.i)
			self:emit_instruction(ins:get())
		end

		do
			do -- xor
				local function reg_to_reg(self, dst, src)
					local ins = self:instruction()
					ins:rex_reg(dst, src)
					ins:opcode(0x33)
					ins:reg_reg(dst, src)
					self:emit_instruction(ins:get())
				end

				local function mem_to_reg(self, dst, src)
					local ins = self:instruction()
					ins:rex_reg(dst, src)
					ins:opcode(0x33) -- XOR r64, r/m64
					ins:reg_reg(dst, src)
					self:emit_instruction(ins:get())
				end

				local function reg_to_mem(self, dst, src)
					local ins = self:instruction()
					ins:rex_reg(src, dst)
					ins:opcode(0x31) -- XOR r/m64, r64
					ins:reg_reg(src, dst)
					self:emit_instruction(ins:get())
				end

				local function imm_to_reg(self, dst, imm)
					self:rex_reg(dst)
					handle_immediate_operation(self, dst, imm, 6) -- 6 is XOR in ModR/M
				end

				local function imm_to_mem(self, dst, imm)
					self:rex_reg(dst)

					if imm >= -128 and imm <= 127 then
						self:emit(0x83) -- XOR r/m64, imm8
						self:emit(0x34) -- ModR/M byte: 00 110 100
						self:emit(0x25) -- SIB byte: 00 100 101 for absolute addressing
						self:emit_i32(dst.disp) -- The absolute address
						self:emit_i8(imm)
					else
						self:emit(0x81) -- XOR r/m64, imm32
						self:emit(0x34) -- ModR/M byte: 00 110 100
						self:emit(0x25) -- SIB byte: 00 100 101 for absolute addressing
						self:emit_i32(dst.disp) -- The absolute address
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
