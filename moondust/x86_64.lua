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

		function Instruction:opcode_ext(v)
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

		function Instruction:imm(num)
			self.ctx.imm = num
			return self
		end

		function Instruction:imm8(num)
			self.ctx.imm8 = num
			return self
		end

		function Instruction:imm32(num)
			self.ctx.imm32 = num
			return self
		end

		function Instruction:rex_reg(reg2, reg1, index_reg)
			if type(reg1) == "number" then reg1 = nil end

			if (reg1 and reg1.bits == 64) or (reg2 and reg2.bits == 64) then
				self:wide_mode()
			end

			if reg1 and reg1.is_extended then self:extend_modrm_reg() end

			if index_reg and index_reg.is_extended then self:extend_sib_index() end

			if reg2 and reg2.is_extended then self:extend_modrm_rm() end

			return self
		end

		function Instruction:setup_operands(dst, src)
			src = src or dst

			if src.indirect and src.disp and not src.reg and not src.base and not src.index then
				self:modrm_mode("indirect")
				self:modrm_reg(dst.i)
				self:modrm_use_sib()
				self:sib_scale(1)
				self:sib_base(NO_BASE)
				self:displace(src.disp)
				return self
			elseif dst.indirect and dst.disp and not dst.reg and not dst.base and not dst.index then
				self:modrm_mode("indirect")
				self:modrm_reg(src.i)
				self:modrm_use_sib()
				self:sib_scale(1)
				self:sib_base(NO_BASE)
				self:displace(dst.disp)
				return self
			end

			if not src.indirect and not src.index and not src.scale and not src.rip then
				self:modrm_mode("direct")
				self:modrm_reg(dst.i)
				self:modrm_rm(src.i)
				return self
			end

			-- Special case: r12/rsp used as base requires SIB byte
			if src.indirect and (src.reg == "r12" or src.reg == "rsp") then
				self:modrm_mode("indirect")
				self:modrm_reg(dst.i)
				self:modrm_use_sib()
				self:sib_scale(1)
				self:sib_base(src.i)
				return self
			end

			if src.rip then
				self:modrm_mode("indirect")
				self:modrm_reg(dst.i)
				self:modrm_rm(RIP_RELATIVE)
				self:displace(src.disp or 0)
				return self
			end

			if src.index and src.scale and not src.base then
				self:modrm_mode("indirect")
				self:modrm_reg(dst.i)
				self:modrm_use_sib()
				self:sib_scale(src.scale)
				self:sib_reg(R[src.index].i)
				self:sib_base(NO_BASE)
				self:displace(src.disp or 0)
				return self
			end

			local mod = "indirect"
			local disp = src.disp
			local effective_disp = nil
			local is_bp = src.reg and (src.reg == "ebp" or src.reg == "rbp")

			if not disp and src.reg and (is_bp or src.reg == "r13") then
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

			if src.index or src.scale or src.reg == "rsp" or src.reg == "esp" then
				self:modrm_mode(mod)
				self:modrm_reg(dst.i)
				self:modrm_use_sib()
				local index_reg = src.index and R[src.index] or nil
				local base_reg = src.base and R[src.base] or src
				self:sib_scale(src.scale)
				self:sib_reg(index_reg and index_reg.i)
				self:sib_base(base_reg and base_reg.i)
			else
				self:modrm_mode(mod)
				self:modrm_reg(dst.i)
				self:modrm_rm(src.i)
			end

			if effective_disp then self:displace(effective_disp) end

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
		local function table_has_value(tbl, key)
			for i, v in ipairs(tbl) do
				if v == key then return true end
			end

			return false
		end

		local function prefix(prefixes)
			local out = {}
			local legacy_prefixes = {
				{
					lock = 0xf0,
					repne = 0xf2,
					repe = 0xf3,
				},
				{
					cs_segment_override = 0x2E,
					ss_segment_override = 0x36,
					ds_segment_override = 0x3E,
					es_segment_override = 0x26,
					fs_segment_override = 0x64,
					gs_segment_override = 0x65,
					branch_not_taken = 0x2E,
					branch_taken = 0x3E,
				},
				{
					operand_size_override = 0x66,
				},
				{
					address_size_override = 0x67,
				},
			}

			for _, group in ipairs(legacy_prefixes) do
				for key, byte in pairs(group) do
					if table_has_value(prefixes, key) then
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

						break
					end
				end
			end

			local rex_byte = 0x40
			local rex_flags = {
				rex_w = 0x08,
				rex_r = 0x04,
				rex_x = 0x02,
				rex_b = 0x01,
			}

			for flag, bitmask in pairs(rex_flags) do
				if table_has_value(prefixes, flag) then rex_byte = bit.bor(rex_byte, bitmask) end
			end

			if rex_byte ~= 0x40 then table.insert(out, rex_byte) end

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

		local scale_bits = {[1] = 0b00000000, [2] = 0b01000000, [4] = 0b10000000, [8] = 0b11000000}

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
				if info.prefix and table_has_value(info.prefix, "rex_x") and info.sib.index == 4 then
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

			if info.imm then
				local n = info.imm

				if n >= -128 and n <= 127 then
					self:emit_i8(n)
				elseif n >= -32768 and n <= 32767 then
					self:emit_i32(n)
				else
					error("Invalid immediate value: " .. tostring(n))
				end
			elseif info.imm8 then
				self:emit_i8(info.imm8)
			elseif info.imm32 then
				self:emit_i32(info.imm32)
			end
		end
	end

	function Assembler:mov(dst, src, signed)
		local ins = self:ins()

		if tonumber(src) then
			-- Immediate to register
			ins:rex_reg(dst)
			ins:opcode(0xB8 + dst.i)
			ins:encode()

			if dst.bits == 64 then
				if signed then self:emit_i64(src) else self:emit_u64(src) end
			else
				if signed then self:emit_i32(src) else self:emit_u32(src) end
			end

			return
		elseif src:pure_displacement() and type(src.disp) == "cdata" and dst.reg == "rax" then
			-- Load from 64-bit displacement to rax (special encoding)
			ins:rex_reg(dst)
			ins:opcode(0xA1)
			ins:encode()
			self:emit_u64(src.disp)
			return
		elseif src:pure_displacement() and type(src.disp) == "cdata" then
			-- Load from 64-bit displacement to register (through memory)
			self:mov(dst, src.disp)
			ins:rex_reg(dst, dst)
			ins:opcode(0x8B)
			ins:setup_operands(dst, dst:memory_address())
		elseif src:pure_displacement() then
			-- Load from regular displacement
			ins:rex_reg(src, dst)
			ins:opcode(0x8B)
			ins:setup_operands(dst, src)
		elseif dst:pure_displacement() and type(dst.disp) == "cdata" and src.reg == "rax" then
			-- Store rax to 64-bit displacement (special encoding)
			ins:rex_reg(src)
			ins:opcode(0xA3)
			ins:displace(dst.disp)
		elseif dst:pure_displacement() and type(dst.disp) == "cdata" then
			-- Store to 64-bit displacement (through temporary register)
			self:push(R.r11)
			self:mov(R.r11, dst.disp)
			ins:rex_reg(R.r11:memory_address(), src)
			ins:opcode(0x89)
			ins:setup_operands(src, R.r11:memory_address())
			ins:encode()
			self:pop(R.r11)
			return
		elseif dst:pure_displacement() then
			-- Store to regular displacement
			ins:rex_reg(dst, src)
			ins:opcode(0x89)
			ins:setup_operands(src, dst)
		elseif src:is_indirect() then
			-- Memory to register
			ins:rex_reg(dst, src)
			ins:opcode(0x8B)
			ins:setup_operands(dst, src)
		elseif dst:is_indirect() then
			-- Register to memory
			ins:rex_reg(src, dst)
			ins:opcode(0x89)
			ins:setup_operands(src, dst)
		elseif dst.reg and src.reg then
			-- Register to register
			ins:rex_reg(dst, src)
			ins:opcode(0x89)
			ins:setup_operands(src, dst)
		else
			error(
				"mov " .. tostring(dst) .. ", " .. tostring(src) .. " is not a valid combination",
				2
			)
		end

		ins:encode()
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

		do
			local function dst_src_instruction(r_rm, rm_r, opcode_ext)
				return function(self, dst, src)
					local ins = self:ins()

					if type(src) == "number" then
						ins:rex_reg(dst)

						if src >= -128 and src <= 127 then
							ins:setup_operands(dst)
							ins:opcode(0x83):opcode_ext(opcode_ext)
							ins:imm8(src)
						else
							ins:setup_operands(dst)
							ins:opcode(0x81):opcode_ext(opcode_ext)
							ins:imm32(src)
						end
					else
						ins:rex_reg(dst, src)

						if src:is_indirect() then
							ins:opcode(r_rm) -- reg ← r/m
						else
							ins:opcode(rm_r) -- r/m ← reg
						end

						ins:setup_operands(dst, src)
					end

					ins:encode()
				end
			end

			Assembler.add = dst_src_instruction(0x03, 0x01, 0)
			Assembler.or_ = dst_src_instruction(0x0B, 0x09, 1)
			Assembler.adc = dst_src_instruction(0x13, 0x11, 2)
			Assembler.sbb = dst_src_instruction(0x1B, 0x19, 3)
			Assembler.and_ = dst_src_instruction(0x23, 0x21, 4)
			Assembler.sub = dst_src_instruction(0x2B, 0x29, 5)
			Assembler.xor = dst_src_instruction(0x33, 0x31, 6)
			Assembler.cmp = dst_src_instruction(0x3B, 0x39, 7)
		end

		do
			local function instruction(opcode, ext)
				return function(self, dst)
					local ins = self:ins()
					ins:rex_reg(dst, src)
					ins:opcode(opcode)
					ins:setup_operands(dst, src)
					ins:opcode_ext(ext)
					ins:encode()
				end
			end

			Assembler.inc = instruction(0xFF, 0)
			Assembler.dec = instruction(0xFF, 1)
			Assembler.not_ = instruction(0xFF, 2)
			Assembler.neg = instruction(0xFF, 3)
			Assembler.mul = instruction(0xF7, 4)
			Assembler.imul = instruction(0xF7, 5)
			Assembler.div = instruction(0xF7, 6)
		end
	end

	function Assembler:lea(self, dst, src)
		if not src:is_indirect() then
			error("LEA requires indirect source operand")
		end

		local ins = self:ins()
		ins:rex_reg(dst, src)
		ins:opcode(0x8D)
		ins:setup_operands(dst, src)
		ins:encode()
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

	require("moondust.breakpoint")(Assembler) -- debug
	require("moondust.wip_x64")(Assembler)
end
