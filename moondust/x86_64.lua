-- moondust x64 assembler
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
					error("RIP-relative addressing cannot use index, scale, or base", 2)
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
				str = str .. " " .. (self.disp >= 0 and "+" or "-") .. " " .. math.abs(self.disp)
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

	do -- encoding helpers
		function Assembler:rex(_64bit_reg, B, R, X)
			local rex = 0b01000000

			if _64bit_reg then rex = bit.bor(rex, 0b00001000) end -- Operand size override (0 = default, 1 = 64-bit)
			if R then rex = bit.bor(rex, 0b00000100) end -- Extension of ModR/M reg field
			if X then rex = bit.bor(rex, 0b00000010) end -- Extension of SIB index field
			if B then rex = bit.bor(rex, 0b00000001) end -- Extension of ModR/M r/m field, SIB base field, or opcode reg field
			self:emit(rex)
		end

		function Assembler:rex_reg(reg2, reg1, index_reg)
			local rex = 0b01000000 -- REX prefix base
			-- W bit: 64-bit operation if either reg is 64-bit
			if (reg1 and reg1.bits == 64) or (reg2 and reg2.bits == 64) then
				rex = bit.bor(rex, 0b00001000)
			end

			-- R bit: reg1 is in ModR/M reg field
			if reg1 and reg1.is_extended then rex = bit.bor(rex, 0b00000100) end

			-- X bit: extended index register in SIB
			if index_reg and index_reg.is_extended then
				rex = bit.bor(rex, 0b00000010)
			end

			-- B bit: reg2 is in ModR/M r/m field
			if reg2 and reg2.is_extended then rex = bit.bor(rex, 0b00000001) end

			if rex ~= 0b01000000 then self:emit(rex) end
		end

		local MOD_NO_DISP = 0
		local MOD_DISP8 = 1
		local MOD_DISP32 = 2
		local MOD_REG = 3
		local SIB_INDICATOR = 4
		local NO_INDEX = 4
		local NO_BASE = 5
		local RIP_RELATIVE = 5
		local scale_bits = {[1] = 0x00, [2] = 0x40, [4] = 0x80, [8] = 0xC0}

		local function encode_modrm(mod, reg, rm)
			return bit.bor(
				bit.lshift(bit.band(mod, 0x3), 6),
				bit.lshift(bit.band(reg.i, 0x7), 3),
				bit.band(rm.i, 0x7)
			)
		end

		local function encode_sib(scale, index, base)
			local scale_val = scale_bits[scale or 1]
			local index_val = bit.lshift(bit.band((index and index.i or NO_INDEX), 0x7), 3)
			local base_val = bit.band((base and base.i or NO_BASE), 0x7)
			return bit.bor(scale_val, index_val, base_val)
		end

		function Assembler:emit_modrm_sib(reg1, reg2)
			if reg2.indirect and reg2.disp and not reg2.reg and not reg2.base and not reg2.index then
				self:emit(bit.bor(bit.lshift(bit.band(reg1.i, 0x7), 3), SIB_INDICATOR))
				self:emit(0x25)
				self:emit_i32(reg2.disp)
				return
			elseif reg1.indirect and reg1.disp and not reg1.reg and not reg1.base and not reg1.index then
				self:emit(bit.bor(bit.lshift(bit.band(reg2.i, 0x7), 3), SIB_INDICATOR))
				self:emit(0x25)
				self:emit_i32(reg1.disp)
				return
			end

			if not reg2.indirect and not reg2.index and not reg2.scale and not reg2.rip then
				self:emit(encode_modrm(MOD_REG, reg1, reg2))
				return
			end

			-- Special case: r12/rsp used as base requires SIB byte
			if reg2.indirect and (reg2.reg == "r12" or reg2.reg == "rsp") then
				self:emit(encode_modrm(MOD_NO_DISP, reg1, {i = SIB_INDICATOR}))
				self:emit(encode_sib(1, nil, reg2))
				return
			end

			if reg2.rip then
				self:emit(encode_modrm(MOD_NO_DISP, reg1, {i = RIP_RELATIVE}))
				self:emit_i32(reg2.disp or 0)
				return
			end

			if reg2.index and reg2.scale and not reg2.base then
				self:emit(encode_modrm(MOD_NO_DISP, reg1, {i = SIB_INDICATOR}))
				self:emit(encode_sib(reg2.scale, self.Registers[reg2.index], {i = NO_BASE}))
				self:emit_i32(reg2.disp or 0)
				return
			end

			local mod, effective_disp = MOD_NO_DISP, nil
			local disp = reg2.disp
			local is_bp = reg2.reg and (reg2.reg == "ebp" or reg2.reg == "rbp")

			if not disp and reg2.reg and (is_bp or reg2.reg == "r13") then
				mod, effective_disp = MOD_DISP8, 0
			elseif not disp or (disp == 0 and not is_bp) then
				mod = MOD_NO_DISP
			elseif disp >= -128 and disp <= 127 then
				mod, effective_disp = MOD_DISP8, disp
			else
				mod, effective_disp = MOD_DISP32, disp
			end

			if reg2.index or reg2.scale or reg2.reg == "rsp" or reg2.reg == "esp" then
				self:emit(encode_modrm(mod, reg1, {i = SIB_INDICATOR}))
				local index_reg = reg2.index and self.Registers[reg2.index] or nil
				local base_reg = reg2.base and self.Registers[reg2.base] or reg2
				self:emit(encode_sib(reg2.scale, index_reg, base_reg))
			else
				self:emit(encode_modrm(mod, reg1, reg2))
			end

			if mod == MOD_DISP8 then
				self:emit_i8(effective_disp)
			elseif mod == MOD_DISP32 then
				self:emit_i32(effective_disp)
			end
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
			self:rex_reg(dst, src)
			self:emit(0x89)
			self:emit_modrm_sib(src, dst)
		end

		local function mem_to_reg(self, dst, src)
			self:rex_reg(dst, src)
			self:emit(0x8B)
			self:emit_modrm_sib(dst, src)
		end

		local function reg_to_mem(self, dst, src)
			self:rex_reg(src, dst)
			self:emit(0x89)
			self:emit_modrm_sib(src, dst)
		end

		local function reg_to_moff(self, dst, src)
			if type(dst.disp) == "cdata" then
				if src.reg == "rax" then
					self:rex_reg(src)
					self:emit(0xA3)
					self:emit_u64(dst.disp)
					return
				end

				self:push(R.r11)
				self:mov(R.r11, dst.disp)
				self:rex_reg(R.r11:memory_address(), src)
				self:emit(0x89)
				self:emit_modrm_sib(src, R.r11:memory_address())
				self:pop(R.r11)
			else
				self:rex_reg(dst, src)
				self:emit(0x89)
				self:emit_modrm_sib(src, dst)
			end
		end

		local function moff_to_reg(self, dst, src)
			if type(src.disp) == "cdata" then
				if dst.reg == "rax" then
					self:rex_reg(dst)
					self:emit(0xA1)
					self:emit_u64(src.disp)
					return
				end

				self:mov(dst, src.disp)
				self:rex_reg(dst, dst)
				self:emit(0x8B)
				self:emit_modrm_sib(dst, dst:memory_address())
			else
				self:rex_reg(src, dst)
				self:emit(0x8B)
				self:emit_modrm_sib(dst, src)
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

		function Assembler:je(label)
			self:emit(0x0F, 0x84)
			local ref_pos = self:get_reference_label(label, "near", 4)
			self:emit(0, 0, 0, 0)
		end

		function Assembler:jne(label)
			self:emit(0x0F, 0x85)
			local ref_pos = self:get_reference_label(label, "near", 4)
			self:emit(0, 0, 0, 0)
		end

		function Assembler:jl(label)
			self:emit(0x0F, 0x8C)
			local ref_pos = self:get_reference_label(label, "near", 4)
			self:emit(0, 0, 0, 0)
		end

		function Assembler:jle(label)
			self:emit(0x0F, 0x8E)
			local ref_pos = self:get_reference_label(label, "near", 4)
			self:emit(0, 0, 0, 0)
		end

		function Assembler:jg(label)
			local jump_pos = self.pos
			self:emit(0x0F, 0x8F)

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
			self:emit(0x0F, 0x8D)
			local ref_pos = self:get_reference_label(label, "near", 4)
			self:emit(0, 0, 0, 0)
		end

		function Assembler:jne(label)
			local jump_pos = self.pos

			if self.labels[label] and self.labels[label].defined then
				local target_pos = self.labels[label].pos
				local rel32 = target_pos - (jump_pos + 6)
				self:emit(0x0F, 0x85)
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
			self:emit(0xE9)

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
			self:emit(0xC3)
		end
	end

	do -- debug
		require("moondust.breakpoint")(Assembler)
	end

	do
		function Assembler:movsd(dest_reg, src_op)
			if src_op.indirect then
				assert(dest_reg.class == "simd", "movsd load requires SSE2 register as destination")

				if dest_reg.is_extended then
					self:rex(false, false, dest_reg.is_extended, false)
				end

				self:emit(0xF2, 0x0F, 0x10)
				self:emit_modrm_sib(dest_reg, src_op)
				return
			end

			if dest_reg.indirect then
				assert(src_op.class == "simd", "movsd store requires SSE2 register as source")

				if src_op.is_extended then
					self:rex(false, false, src_op.is_extended, false)
				end

				self:emit(0xF2, 0x0F, 0x11)
				self:emit_modrm_sib(src_op, dest_reg)
				return
			end

			assert(
				dest_reg.class == "simd" and src_op.class == "simd",
				"movsd reg-reg requires SSE2 registers"
			)

			if dest_reg.is_extended or src_op.is_extended then
				self:rex(false, false, dest_reg.is_extended, false)
			end

			self:emit(0xF2, 0x0F, 0x10)
			self:emit_modrm_sib(dest_reg, src_op)
		end

		function Assembler:vmovaps(dst, src)
			assert(dst.class == "simd" and src.class == "simd", "vmovaps requires AVX registers")
			self:emit(0xC5, 0xFC, 0x28)
			self:emit_modrm_sib(dst, src)
		end

		function Assembler:vmovaps_store(dest_mem, src_reg)
			self:emit(0xC5, 0xFC, 0x29)
			self:emit_modrm_sib(src_reg, R({reg = "rax", indirect = true}))
		end

		function Assembler:vmovups(dst, src)
			self:emit(0xC5, 0xFC, 0x10)
			self:emit_modrm_sib(dst, src)
		end

		function Assembler:vmovups_load(dest_reg, src_mem)
			assert(dest_reg.class == "simd", "vmovups requires AVX register as destination")
			self:emit(0xC5, 0xFC, 0x10)
			self:emit_modrm_sib(dest_reg, R({reg = "rax", indirect = true}))
		end

		function Assembler:vmovups_store(dest_mem, src_reg)
			assert(src_reg.class == "simd", "vmovups requires AVX register as source")
			self:emit(0xC5, 0xFC, 0x11)
			self:emit_modrm_sib(src_reg, R({reg = "rax", indirect = true}))
		end

		function Assembler:movaps(dst, src)
			assert(dst.class == "simd" and src.class == "simd", "movaps requires SSE registers")

			if dst.is_extended or src.is_extended then
				self:rex(false, src.is_extended, dst.is_extended, false)
			end

			self:emit(0x0F, 0x28)
			self:emit_modrm_sib(dst, src)
		end

		function Assembler:movaps_load(dest_reg, src_mem)
			assert(dest_reg.class == "simd", "movaps requires SSE register as destination")

			if dest_reg.is_extended then
				self:rex(false, false, dest_reg.is_extended, false)
			end

			self:emit(0x0F, 0x28)
			self:emit_modrm_sib(dest_reg, R({reg = "rax", indirect = true}))
		end

		function Assembler:movaps_store(dest_mem, src_reg)
			assert(src_reg.class == "simd", "movaps requires SSE register as source")

			if src_reg.is_extended then
				self:rex(false, false, src_reg.is_extended, false)
			end

			self:emit(0x0F, 0x29)
			self:emit_modrm_sib(src_reg, R({reg = "rax", indirect = true}))
		end

		function Assembler:movdqu(reg1, reg2)
			assert(reg1.class == "simd" and reg2.class == "simd", "movdqu requires SSE registers")

			if reg1.is_extended or reg2.is_extended then
				self:rex(false, reg1.is_extended, reg2.is_extended, false)
			end

			self:emit(0xF3, 0x0F, 0x6F)
			self:emit_modrm_sib(reg2, reg1)
		end
	end

	function Assembler:mulsd(dest_reg, src_reg)
		assert(dest_reg.class == "simd" and src_reg.class == "simd", "mulsd requires SSE2 registers")

		if dest_reg.is_extended or src_reg.is_extended then
			self:rex(false, false, dest_reg.is_extended, false)
		end

		self:emit(0xF2, 0x0F, 0x59) -- F2 0F 59 /r - MULSD xmm1, xmm2/m64
		self:emit_modrm_sib(dest_reg, src_reg)
	end

	function Assembler:addsd(dest_reg, src_reg)
		assert(dest_reg.class == "simd" and src_reg.class == "simd", "addsd requires SSE2 registers")

		if dest_reg.is_extended or src_reg.is_extended then
			self:rex(false, false, dest_reg.is_extended, false)
		end

		self:emit(0xF2, 0x0F, 0x58) -- F2 0F 58 /r - ADDSD xmm1, xmm2/m64
		self:emit_modrm_sib(dest_reg, src_reg)
	end

	function Assembler:sqrtsd(dest_reg, src_reg)
		assert(dest_reg.class == "simd" and src_reg.class == "simd", "sqrtsd requires SSE2 registers")

		if dest_reg.is_extended or src_reg.is_extended then
			self:rex(false, false, dest_reg.is_extended, false)
		end

		self:emit(0xF2, 0x0F, 0x51) -- F2 0F 51 /r - SQRTSD xmm1, xmm2/m64
		self:emit_modrm_sib(dest_reg, src_reg)
	end

	function Assembler:push(reg)
		if reg.is_extended then self:rex(false, reg.is_extended, false, false) end

		self:emit(0x50 + reg.i)
	end

	function Assembler:pop(reg)
		if reg.is_extended then self:rex(false, reg.is_extended, false, false) end

		self:emit(0x58 + reg.i)
	end

	function Assembler:syscall()
		self:emit(0x0F, 0x05)
	end

	do
		function Assembler:addps(reg1, reg2)
			assert(reg1.class == "simd" and reg2.class == "simd", "addps requires SSE registers")

			if reg1.is_extended or reg2.is_extended then
				self:rex(false, reg1.is_extended, reg2.is_extended, false)
			end

			self:emit(0x0F, 0x58)
			self:emit_modrm_sib(reg2, reg1)
		end

		function Assembler:mulps(reg1, reg2)
			assert(reg1.class == "simd" and reg2.class == "simd", "mulps requires SSE registers")

			if reg1.is_extended or reg2.is_extended then
				self:rex(false, reg1.is_extended, reg2.is_extended, false)
			end

			self:emit(0x0F, 0x59)
			self:emit_modrm_sib(reg2, reg1)
		end
	end

	do
		local function create_avx_instruction(name, opcode)
			Assembler[name] = function(self, dst, src1, src2)
				assert(
					dst.class == "simd" and src1.class == "simd" and src2.class == "simd",
					name .. " requires AVX registers"
				)
				self:emit(0xC5, 0xF8, opcode)
				self:emit_modrm_sib(dst, src2)
			end
		end

		-- Define instructions using the template
		create_avx_instruction("vxorps", 0x57)
		create_avx_instruction("vmulps", 0x59)
		create_avx_instruction("vaddps", 0x58)
		create_avx_instruction("vsubps", 0x5C)
		create_avx_instruction("vdivps", 0x5E)
	end

	do
		local function handle_immediate_operation(self, reg, imm, base_opcode, extension)
			self:rex(true, reg.is_extended, false, false)

			if imm >= -128 and imm <= 127 then
				self:emit(0x83)
				self:emit_opext(extension, reg)
				self:emit_i8(imm)
			else
				self:emit(0x81)
				self:emit_opext(extension, reg)
				self:emit_i32(imm)
			end
		end

		local function handle_register_operation(self, reg1, reg2, opcode)
			self:rex(true, reg1.is_extended, reg2.is_extended, false)
			self:emit(opcode)
			self:emit_modrm_sib(reg1, reg2)
		end

		local function emit_opext(self, extension, rm, mod)
			local modrm = bit.bor(
				bit.lshift(bit.band(mod or 3, 0x3), 6),
				bit.lshift(bit.band(extension, 0x7), 3),
				bit.band(rm.i, 0x7)
			)
			self:emit(modrm)
		end

		function Assembler:xor(reg1, reg2)
			self:rex_reg(reg1, reg2)
			self:rex(true, reg1.is_extended, reg2.is_extended, false)
			self:emit(0x33)
			self:emit_modrm_sib(reg1, reg2)
		end

		function Assembler:inc(reg)
			assert(reg.bits == 64, "only supports 64-bit registers")
			self:rex(true, reg.is_extended, false, false)
			self:emit(0xFF)
			emit_opext(self, 0, reg)
		end

		function Assembler:dec(reg)
			assert(reg.bits == 64, "only supports 64-bit registers")
			self:rex(true, reg.is_extended, false, false)
			self:emit(0xFF)
			emit_opext(self, 1, reg)
		end

		function Assembler:cmp(reg1, op2)
			assert(reg1.bits == 64, "only supports 64-bit registers")

			if type(op2) == "number" then
				self:rex(true, reg1.is_extended, false, false)

				if op2 >= -128 and op2 <= 127 then
					self:emit(0x83)
					emit_opext(self, 7, reg1)
					self:emit_i8(op2)
				else
					self:emit(0x81)
					emit_opext(self, 7, reg1)
					self:emit_i32(op2)
				end
			else
				local reg2 = op2
				self:rex(true, reg1.is_extended, reg2.is_extended, false)
				self:emit(0x3B)
				self:emit_modrm_sib(reg1, reg2)
			end
		end

		function Assembler:add(reg1, op2)
			assert(reg1.bits == 64)

			if type(op2) == "number" then
				self:rex(true, reg1.is_extended, false, false)

				if op2 >= -128 and op2 <= 127 then
					self:emit(0x83)
					emit_opext(self, 0, reg1)
					self:emit_i8(op2)
				else
					self:emit(0x81)
					emit_opext(self, 0, reg1)
					self:emit_i32(op2)
				end
			else
				local reg2 = op2
				self:rex(true, reg1.is_extended, reg2.is_extended, false)
				self:emit(0x03)
				self:emit_modrm_sib(reg1, reg2)
			end
		end

		function Assembler:mul(reg)
			assert(reg.bits == 64)
			self:rex(true, reg.is_extended, false, false)
			self:emit(0xF7)
			emit_opext(self, 4, reg)
		end

		function Assembler:shl(reg1, op2)
			assert(reg1.bits == 64)

			if type(op2) == "number" then
				self:rex(true, reg1.is_extended, false, false)

				if op2 == 1 then
					self:emit(0xD1)
					emit_opext(self, 4, reg1)
				else
					self:emit(0xC1)
					emit_opext(self, 4, reg1)
					self:emit_i8(op2)
				end
			else
				local reg2 = op2

				if reg2.reg ~= "rcx" and reg2.reg ~= "cl" then
					error("shift count must be in CL register")
				end

				self:rex(true, reg1.is_extended, false, false)
				self:emit(0xD3)
				emit_opext(self, 4, reg1)
			end
		end

		function Assembler:sub(reg1, op2)
			assert(reg1.bits == 64)

			if type(op2) == "number" then
				self:rex(true, reg1.is_extended, false, false)

				if op2 >= -128 and op2 <= 127 then
					self:emit(0x83)
					emit_opext(self, 5, reg1)
					self:emit_i8(op2)
				else
					self:emit(0x81)
					emit_opext(self, 5, reg1)
					self:emit_i32(op2)
				end
			else
				local reg2 = op2
				self:rex(true, reg1.is_extended, reg2.is_extended, false)
				self:emit(0x2B)
				self:emit_modrm_sib(reg1, reg2)
			end
		end
	end
end
