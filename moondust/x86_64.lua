return function(Assembler) -- x64_86
	do
		local reginfo = {}

		-- Standard registers
		for i, name in ipairs({"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"}) do
			reginfo["r" .. name] = {
				bits = 64,
				is_extended = false,
				i = i - 1,
			}
			reginfo["e" .. name] = {
				bits = 32,
				is_extended = false,
				i = i - 1,
			}
		end

		-- r8-r15
		for i = 8, 15 do
			reginfo["r" .. i] = {
				bits = 64,
				is_extended = true,
				i = i - 8,
			}
		end

		-- r8d-r15d
		for i = 8, 15 do
			reginfo["r" .. i .. "d"] = {
				bits = 32,
				is_extended = true,
				i = i - 8,
			}
		end

		-- SIMD registers
		local simd_classes = {
			xmm = {count = 16, width = 128}, -- SSE
			ymm = {count = 16, width = 256}, -- AVX/AVX2
			zmm = {count = 32, width = 512}, -- AVX-512
		}

		for class, info in pairs(simd_classes) do
			for i = 0, info.count - 1 do
				reginfo[class .. i] = {
					bits = info.width,
					is_extended = i > 7,
					i = i % 8,
					class = "simd",
					width = info.width,
				}
			end
		end

		-- AVX-512 mask registers
		for i = 0, 7 do
			reginfo["k" .. i] = {bits = 64, is_extended = false, i = i, class = "mask"}
		end

		-- RIP for RIP-relative addressing
		reginfo.rip = {bits = 64, rip = true, class = "ip", i = 5}

		-- Helper function to validate scale values
		local function validate_scale(scale)
			local valid_scales = {[1] = true, [2] = true, [4] = true, [8] = true}

			if scale and not valid_scales[scale] then
				error("Invalid scale value: " .. tostring(scale) .. ". Must be 1, 2, 4, or 8", 2)
			end
		end

		-- Helper function to validate displacement values
		local function validate_displacement(disp)
			if disp and type(disp) ~= "number" then
				error("Displacement must be a number, got: " .. type(disp), 2)
			end
		end

		-- Helper function to validate register name
		local function validate_register_name(reg_name)
			if not reginfo[reg_name] then
				error(reg_name .. " is not a valid register", 2)
			end
		end

		-- Helper function to validate combinations
		local function validate_combinations(result)
			-- Validate RIP-relative addressing restrictions
			if result.rip then
				if result.index or result.scale or result.base then
					error("RIP-relative addressing cannot use index, scale, or base", 2)
				end
			end

			-- Validate ESP/RSP index restrictions
			if result.index == "esp" or result.index == "rsp" then
				error("ESP/RSP cannot be used as an index register", 2)
			end

			-- Validate scale usage
			if result.scale and not result.index then
				error("Scale can only be used with an index register", 2)
			end

			-- Validate SIMD register combinations
			if result.class == "simd" then
				-- Check width compatibility
				if
					result.index and
					reginfo[result.index].class == "simd" and
					reginfo[result.index].width ~= result.width
				then
					error("SIMD registers must have matching widths", 2)
				end
			end

			-- Validate mask register restrictions
			if result.class == "mask" then
				if result.index or result.scale then
					error("Mask registers cannot be used with index or scale", 2)
				end
			end
		end

		local function REG(val)
			if type(val) == "string" then
				-- Direct register reference
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

				-- Handle pure displacement addressing
				if val.indirect and val.disp and not (val.reg or val.base or val.index) then
					validate_displacement(val.disp)
					new.indirect = true
					new.disp = val.disp
					new.i = 0 -- Dummy index for ModRM/SIB encoding
					return new
				end

				-- Validate and copy register fields
				for _, key in ipairs({"reg", "index", "base"}) do
					if val[key] then
						validate_register_name(val[key])
						new[key] = val[key]

						-- Copy register info
						for k, v in pairs(reginfo[val[key]]) do
							if not new[k] then -- Don't overwrite existing values
							new[k] = v end
						end
					end
				end

				-- Validate scale if present
				validate_scale(val.scale)
				-- Validate displacement if present
				validate_displacement(val.disp)

				-- Copy remaining fields
				for k, v in pairs(val) do
					if k ~= "reg" and k ~= "index" and k ~= "base" then new[k] = v end
				end

				-- Perform combination validations
				validate_combinations(new)

				-- Return if we found at least one valid register reference
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

		function Register:__tostring()
			local parts = {}

			if self.reg then table.insert(parts, self.reg) end

			if self.index then
				table.insert(parts, self.index)

				if self.scale then table.insert(parts, "*" .. self.scale) end
			end

			if self.disp then table.insert(parts, tostring(self.disp)) end

			return table.concat(parts, " + ")
		end

		function Register:__mul(scale)
			validate_scale(scale)
			local new = {}

			for k, v in pairs(self) do
				new[k] = v
			end

			new.scale = scale
			validate_combinations(new)
			return new
		end

		function Register:__add(disp)
			validate_displacement(disp)
			local new = {}

			for k, v in pairs(self) do
				new[k] = v
			end

			new.disp = disp
			validate_combinations(new)
			return new
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
	local IS_REG = function(val)
		local ok = pcall(Assembler.Register.new, val)
		return ok
	end

	do
		function Assembler:rex(W, B, R, X)
			local rex = 0b01000000 -- Fixed REX prefix
			if W then rex = bit.bor(rex, 0b00001000) end -- 64-bit operand
			if R then rex = bit.bor(rex, 0b00000100) end -- Extension of ModR/M reg field
			if X then rex = bit.bor(rex, 0b00000010) end -- Extension of SIB index field
			if B then rex = bit.bor(rex, 0b00000001) end -- Extension of ModR/M r/m, SIB base, or opcode reg field
			self:emit(rex)
		end

		do
			local RIP_RELATIVE = 5
			local SIB_INDICATOR = 4
			local NO_INDEX = 4
			local NO_BASE = 5
			local NO_DISP = 0 -- No displacement
			local DISP8 = 1 -- 8-bit displacement
			local DISP32 = 2 -- 32-bit displacement
			local REG_TO_REG = 3
			local scale_bits = {[1] = 0b00, [2] = 0b01, [4] = 0b10, [8] = 0b11}

			local function encode_modrm(mod, reg, rm)
				assert(mod >= 0 and mod <= 3, "Invalid mod value")
				return bit.bor(
					bit.lshift(bit.band(mod, 0x3), 6),
					bit.lshift(bit.band(reg.i, 0x7), 3),
					bit.band(rm.i, 0x7)
				)
			end

			local function encode_sib(scale, index, base)
				return bit.bor(
					bit.lshift(scale_bits[scale or 1], 6),
					bit.lshift(bit.band(index and index.i or NO_INDEX, 0x7), 3),
					bit.band(base and base.i or NO_BASE, 0x7)
				)
			end

			function Assembler:emit_modrm_sib(reg1, reg2)
				-- Handle pure displacement case
				if reg2.indirect and reg2.disp and not reg2.reg and not reg2.base and not reg2.index then
					-- Encode ModRM with SIB byte (mod = 00, r/m = 100)
					self:emit(encode_modrm(0, reg1, {i = SIB_INDICATOR}))
					-- SIB byte: no scale (00), no index (100), no base (101)
					self:emit(0x25) -- Fixed SIB byte for pure displacement: scale=00, index=100, base=101
					-- Emit 32-bit displacement
					self:emit_i32(reg2.disp)
					return
				end

				-- Rest of the existing emit_modrm_sib logic...
				if
					not reg2.indirect and
					not reg2.index and
					not reg2.scale and
					not reg2.rip and
					reg1 and
					reg2
				then
					self:emit(encode_modrm(REG_TO_REG, reg1, reg2))
					return
				end

				local mod
				local effective_disp

				if reg2.rip then
					-- RIP-relative addressing
					mod = NO_DISP
					self:emit(encode_modrm(mod, reg1, {i = RIP_RELATIVE}))
					self:emit_i32(reg2.disp or 0)
					return
				end

				local disp = reg2.disp
				local is_bp = reg2.reg and (reg2.reg == "ebp" or reg2.reg == "rbp")

				if not disp and reg2.reg and (is_bp or reg2.reg == "r13") then
					mod = DISP8
					effective_disp = 0
				elseif not disp or (disp == 0 and not is_bp) then
					mod = NO_DISP
				elseif disp >= -128 and disp <= 127 then
					mod = DISP8
					effective_disp = disp
				else
					mod = DISP32
					effective_disp = disp
				end

				-- When there's only an index and scale, we should force NO_BASE
				if reg2.index and reg2.scale and not reg2.base then
					self:emit(encode_modrm(NO_DISP, reg1, {i = SIB_INDICATOR}))
					self:emit(encode_sib(reg2.scale, self.Registers[reg2.index], {i = NO_BASE}))
					self:emit_i32(0)
				else
					if reg2.index or reg2.scale or is_sp then
						self:emit(encode_modrm(mod, reg1, {i = SIB_INDICATOR}))
						local index_reg = reg2.index and self.Registers[reg2.index] or nil
						local base_reg = reg2.base and self.Registers[reg2.base] or reg2
						self:emit(encode_sib(reg2.scale, index_reg, base_reg))
					else
						self:emit(encode_modrm(mod, reg1, reg2))
					end
				end

				if reg2.reg == "rip" then
					self:emit_i32(effective_disp)
				elseif mod == DISP8 then
					self:emit_i8(effective_disp)
				elseif mod == DISP32 then
					self:emit_i32(effective_disp)
				end
			end
		end
	end

	function Assembler:ret()
		self:emit(0xC3)
	end

	function Assembler:mov_imm_to_reg(reg, imm, signed)
		assert(tonumber(imm), " immediate value must be a number")

		if reg.class == "simd" then
			self:push("rax")

			if reg.width == 128 then
				self:rex(true, false, false, false)
				self:emit(0x0F, 0x28, 0xC0 + reg.i)
			end

			self:pop("rax")
		elseif reg.bits == 64 then
			self:rex(true, reg.is_extended, false, false)
			self:emit(0xB8 + reg.i)

			if signed then self:emit_i64(imm) else self:emit_u64(imm) end
		elseif reg.bits == 32 then
			if reg.is_extended then self:rex(false, reg.is_extended, false, false) end

			self:emit(0xB8 + reg.i)

			if signed then self:emit_i32(imm) else self:emit_u32(imm) end
		end
	end

	function Assembler:mov_reg_to_reg(reg1, reg2)
		if reg1.class == "simd" and reg2.class == "simd" then
			if reg1.is_extended or reg2.is_extended then
				self:rex(false, reg1.is_extended, reg2.is_extended, false)
			end

			self:emit(0x0F, 0x28)
			self:emit_modrm_sib(reg2, reg1)
		elseif reg1.bits == 64 then
			self:rex(true, reg1.is_extended, reg2.is_extended, false)
			self:emit(0x89)
			self:emit_modrm_sib(reg2, reg1)
		end
	end

	-- Refactored mov_reg_to_pointer
	function Assembler:mov_reg_to_pointer(reg, ptr)
		if reg.class == "simd" then
			if reg.reg ~= "rcx" then self:push(R.rcx) end

			self:mov("rcx", ptr)

			if reg.is_extended then self:rex(false, reg.is_extended, false, false) end

			self:emit(0x0F, 0x29) -- MOVAPS store
			self:emit_modrm_sib(reg, R({reg = "rcx", indirect = true}))

			if reg.reg ~= "rcx" then self:pop(R.rcx) end
		elseif reg.bits == 64 then
			if reg.reg ~= "rcx" then self:push(R.rcx) end

			self:mov(R.rcx, ptr)
			self:rex(true, reg.is_extended, false, false)
			self:emit(0x89)
			self:emit_modrm_sib(reg, R({reg = "rcx", indirect = true}))

			if reg.reg ~= "rcx" then self:pop(R.rcx) end
		end
	end

	function Assembler:mov_pointer_to_reg(reg, ptr)
		if reg.class == "simd" then
			if reg.reg ~= "rcx" then self:push(R.rcx) end

			self:mov(R.rcx, ptr)

			if reg.is_extended then self:rex(false, reg.is_extended, false, false) end

			self:emit(0x0F, 0x28)
			self:emit_modrm_sib(reg, R({reg = "rcx", indirect = true}))

			if reg.reg ~= "rcx" then self:pop(R.rcx) end
		elseif reg.bits == 64 then
			if reg.reg == "rcx" then self:push(R.rcx) end

			self:mov(R.rcx, ptr)
			self:rex(true, reg.is_extended, false, false)
			self:emit(0x8B)
			self:emit_modrm_sib(reg, R({reg = "rcx", indirect = true}))

			if reg.reg == "rcx" then self:pop(R.rcx) end
		end
	end

	function Assembler:mov_reg_from_mem(reg, mem_op)
		if reg.bits == 64 then
			self:rex(true, reg.is_extended, mem_op.is_extended, false)
			self:emit(0x8B)
			self:emit_modrm_sib(reg, mem_op)
		else
			error("mov from memory only supports 64-bit registers", 2)
		end
	end

	function Assembler:mov_mem_from_reg(mem_op, reg)
		if reg.bits == 64 then
			self:rex(true, reg.is_extended, mem_op.is_extended, false)
			self:emit(0x89)
			self:emit_modrm_sib(reg, mem_op)
		else
			error("mov to memory only supports 64-bit registers", 2)
		end
	end

	function Assembler:mov(reg1, reg2, signed)
		if tonumber(reg2) then
			self:mov_imm_to_reg(reg1, reg2, signed)
		elseif
			type(reg2) == "table" and
			reg2.indirect and
			reg2.disp and
			not reg2.reg and
			not reg2.base and
			not reg2.index
		then
			self:rex(true, false, reg1.is_extended, false)
			self:emit(0x8B)
			self:emit_modrm_sib(reg1, reg2)
		elseif IS_REG(reg2) then
			if reg2.indirect or reg2.index or reg2.scale or reg2.base or reg2.rip then
				self:mov_reg_from_mem(reg1, reg2)
			elseif reg1.indirect or reg1.index or reg1.scale or reg1.base or reg1.rip then
				self:mov_mem_from_reg(reg1, reg2)
			else
				self:mov_reg_to_reg(reg1, reg2)
			end
		else
			error(
				tostring(reg1) .. ", " .. tostring(reg2) .. " is not a valid register combination",
				2
			)
		end
	end

	function Assembler:push(reg)
		assert(reg.bits == 64, "push only supports 64-bit registers")

		-- Check if we need REX prefix for r8-r15
		if reg.is_extended then self:rex(false, reg.is_extended, false, false) end

		-- Base opcode for push is 0x50 + register index
		self:emit(0x50 + reg.i)
	end

	function Assembler:pop(reg)
		assert(reg.bits == 64, "push only supports 64-bit registers")

		-- Check if we need REX prefix for r8-r15
		if reg.is_extended then self:rex(false, reg.is_extended, false, false) end

		-- Base opcode for pop is 0x58 + register index
		self:emit(0x58 + reg.i)
	end

	function Assembler:syscall()
		self:emit(0x0F, 0x05)
	end

	do --sse
		-- Add SSE instructions to the Assembler
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

	-- AVX store operations for the Assembler
	do
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
			self:emit_modrm_sib(dest_reg, R({reg = "rax", indirect = true})) -- Load from memory pointed by rax
		end

		function Assembler:vmovups_store(dest_mem, src_reg)
			assert(src_reg.class == "simd", "vmovups requires AVX register as source")
			self:emit(0xC5, 0xFC, 0x11)
			self:emit_modrm_sib(src_reg, R({reg = "rax", indirect = true})) -- St
		end

		-- AVX operations for the Assembler
		function Assembler:vxorps(dst, src1, src2)
			assert(
				dst.class == "simd" and src1.class == "simd" and src2.class == "simd",
				"vxorps requires AVX registers"
			)
			-- VEX prefix for AVX
			self:emit(0xC5)
			-- Second byte of VEX prefix:
			-- 1. R' inverted (0x80 if no high registers)
			-- 2. vvvv field (src1 register inverted)
			-- 3. L bit (0 for 128-bit, 1 for 256-bit)
			-- 4. pp field (00 for packed single precision)
			local vex2 = 0xF8 -- Base: R'=1, L=0, pp=00
			self:emit(vex2)
			-- Opcode for VXORPS
			self:emit(0x57)
			-- ModR/M byte
			self:emit_modrm_sib(dst, src2)
		end

		-- AVX arithmetic operations for the Assembler
		function Assembler:vmulps(dst, src1, src2)
			assert(
				dst.class == "simd" and src1.class == "simd" and src2.class == "simd",
				"vmulps requires AVX registers"
			)
			-- VEX prefix for AVX
			self:emit(0xC5)
			-- Second byte of VEX prefix
			local vex2 = 0xF8 -- Base: R'=1, L=0, pp=00
			self:emit(vex2)
			-- Opcode for VMULPS
			self:emit(0x59)
			-- ModR/M byte
			self:emit_modrm_sib(dst, src2)
		end

		function Assembler:vaddps(dst, src1, src2)
			assert(
				dst.class == "simd" and src1.class == "simd" and src2.class == "simd",
				"vaddps requires AVX registers"
			)
			-- VEX prefix for AVX
			self:emit(0xC5)
			-- Second byte of VEX prefix
			local vex2 = 0xF8 -- Base: R'=1, L=0, pp=00
			self:emit(vex2)
			-- Opcode for VADDPS
			self:emit(0x58)
			-- ModR/M byte
			self:emit_modrm_sib(dst, src2)
		end

		function Assembler:vsubps(dst, src1, src2)
			assert(
				dst.class == "simd" and src1.class == "simd" and src2.class == "simd",
				"vsubps requires AVX registers"
			)
			-- VEX prefix for AVX
			self:emit(0xC5)
			-- Second byte of VEX prefix
			local vex2 = 0xF8 -- Base: R'=1, L=0, pp=00
			self:emit(vex2)
			-- Opcode for VSUBPS
			self:emit(0x5C)
			-- ModR/M byte
			self:emit_modrm_sib(dst, src2)
		end

		function Assembler:vdivps(dst, src1, src2)
			assert(
				dst.class == "simd" and src1.class == "simd" and src2.class == "simd",
				"vdivps requires AVX registers"
			)
			-- VEX prefix for AVX
			self:emit(0xC5)
			-- Second byte of VEX prefix
			local vex2 = 0xF8 -- Base: R'=1, L=0, pp=00
			self:emit(vex2)
			-- Opcode for VDIVPS
			self:emit(0x5E)
			-- ModR/M byte
			self:emit_modrm_sib(dst, src2)
		end

		-- Memory versions of the instructions
		function Assembler:vmulps_mem(dst, src1)
			assert(dst.class == "simd" and src1.class == "simd", "vmulps requires AVX registers")
			-- VEX prefix for AVX
			self:emit(0xC5)
			local vex2 = 0xF8
			self:emit(vex2)
			self:emit(0x59)
			self:emit_modrm_sib(dst, R({reg = "rax", indirect = true}))
		end

		function Assembler:vaddps_mem(dst, src1)
			assert(dst.class == "simd" and src1.class == "simd", "vaddps requires AVX registers")
			-- VEX prefix for AVX
			self:emit(0xC5)
			local vex2 = 0xF8
			self:emit(vex2)
			self:emit(0x58)
			self:emit_modrm_sib(dst, R({reg = "rax", indirect = true}))
		end
	end

	do -- basic
		function Assembler:emit_opext(extension, rm, mod)
			local modrm = bit.bor(
				bit.lshift(bit.band(mod or 3, 0x3), 6), -- mod (default to 3 for register mode)
				bit.lshift(bit.band(extension, 0x7), 3), -- opcode extension
				bit.band(rm.i, 0x7) -- r/m field
			)
			self:emit(modrm)
		end

		function Assembler:xor(reg1, reg2)
			if reg1.bits == 64 then
				self:rex(true, reg1.is_extended, reg2.is_extended, false)
				self:emit(0x33) -- XOR r/m64, r64
				self:emit_modrm_sib(reg1, reg2)
			else
				error("xor only supports 64-bit registers")
			end
		end

		function Assembler:inc(reg)
			if reg.bits == 64 then
				self:rex(true, reg.is_extended, false, false)
				self:emit(0xFF) -- INC r/m64
				self:emit_opext(0, reg) -- /0
			else
				error("inc only supports 64-bit registers")
			end
		end

		function Assembler:dec(reg)
			if reg.bits == 64 then
				self:rex(true, reg.is_extended, false, false)
				self:emit(0xFF) -- DEC r/m64
				self:emit_opext(1, reg) -- /1
			else
				error("dec only supports 64-bit registers")
			end
		end

		function Assembler:cmp(reg1, op2)
			assert(reg1.bits == 64)

			if type(op2) == "number" then
				self:rex(true, reg1.is_extended, false, false)

				if op2 >= -128 and op2 <= 127 then
					self:emit(0x83) -- CMP r/m64, imm8
					self:emit_opext(7, reg1) -- /7
					self:emit_i8(op2)
				else
					self:emit(0x81) -- CMP r/m64, imm32
					self:emit_opext(7, reg1) -- /7
					self:emit_i32(op2)
				end
			else
				local reg2 = op2
				self:rex(true, reg1.is_extended, reg2.is_extended, false)
				self:emit(0x3B) -- CMP r64, r/m64
				self:emit_modrm_sib(reg1, reg2)
			end
		end

		function Assembler:add(reg1, op2)
			assert(reg1.bits == 64)

			if type(op2) == "number" then
				self:rex(true, reg1.is_extended, false, false)

				if op2 >= -128 and op2 <= 127 then
					self:emit(0x83) -- ADD r/m64, imm8
					self:emit_opext(0, reg1) -- /0
					self:emit_i8(op2)
				else
					self:emit(0x81) -- ADD r/m64, imm32
					self:emit_opext(0, reg1) -- /0
					self:emit_i32(op2)
				end
			else
				local reg2 = op2
				self:rex(true, reg1.is_extended, reg2.is_extended, false)
				self:emit(0x03) -- ADD r64, r/m64
				self:emit_modrm_sib(reg1, reg2)
			end
		end

		function Assembler:mul(reg)
			assert(reg.bits == 64)
			-- REX.W prefix for 64-bit operand
			self:rex(true, reg.is_extended, false, false)
			self:emit(0xF7) -- MUL opcode
			-- /4 is the extension for MUL
			self:emit_opext(4, reg) -- ModR/M byte with /4 extension
		end

		function Assembler:shl(reg1, op2)
			assert(reg1.bits == 64)

			if type(op2) == "number" then
				-- SHL reg, imm8
				self:rex(true, reg1.is_extended, false, false)

				if op2 == 1 then
					-- Special case for shift by 1
					self:emit(0xD1) -- Opcode for SHL r/m64, 1
					self:emit_opext(4, reg1) -- /4 for SHL
				else
					self:emit(0xC1) -- Opcode for SHL r/m64, imm8
					self:emit_opext(4, reg1) -- /4 for SHL
					self:emit_i8(op2)
				end
			else
				-- SHL reg, CL (shift count in CL register)
				local reg2 = op2

				if reg2.reg ~= "rcx" and reg2.reg ~= "cl" then
					error("shift count must be in CL register")
				end

				self:rex(true, reg1.is_extended, false, false)
				self:emit(0xD3) -- Opcode for SHL r/m64, CL
				self:emit_opext(4, reg1) -- /4 for SHL
			end
		end

		function Assembler:sub(reg1, op2)
			assert(reg1.bits == 64)

			if type(op2) == "number" then
				self:rex(true, reg1.is_extended, false, false)

				if op2 >= -128 and op2 <= 127 then
					self:emit(0x83) -- SUB r/m64, imm8
					self:emit_opext(5, reg1) -- /5
					self:emit_i8(op2)
				else
					self:emit(0x81) -- SUB r/m64, imm32
					self:emit_opext(5, reg1) -- /5
					self:emit_i32(op2)
				end
			else
				-- SUB reg, reg
				local reg2 = op2
				self:rex(true, reg1.is_extended, reg2.is_extended, false)
				self:emit(0x2B) -- SUB r64, r/m64
				self:emit_modrm_sib(reg1, reg2)
			end
		end
	end

	do -- labels
		function Assembler:get_reference_label(name, type, size)
			if not self.labels[name] then
				self.labels[name] = {references = {}, defined = false}
			end

			table.insert(self.labels[name].references, {pos = self.pos, type = type, size = size})
			-- Return current position so instruction can emit placeholder bytes
			return self.pos
		end

		function Assembler:je(label)
			-- Conditional jump is 6 bytes: 2 byte opcode (0x0F, 0x84) + 4 byte offset
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
			self:emit(0x0F, 0x8F) -- JG opcode
			if not self.labels[label] then
				self.labels[label] = {references = {}, defined = false}
			end

			-- Add reference with proper size information
			table.insert(
				self.labels[label].references,
				{
					pos = jump_pos,
					type = "long_conditional",
					size = 6, -- Total size: 2 byte opcode + 4 byte offset
				}
			)
			-- Emit placeholder bytes for offset
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
				local rel32 = target_pos - (jump_pos + 6) -- 6 = size of jne instruction (2 byte opcode + 4 byte offset)
				self:emit(0x0F, 0x85) -- JNE rel32
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
						size = 6, -- Total instruction size
					}
				)
				-- Emit placeholder instruction
				self:emit(0x0F, 0x85) -- JNE rel32
				self:emit(0, 0, 0, 0) -- Placeholder for 32-bit offset
			end
		end

		-- Update jmp implementation to properly record reference information
		function Assembler:jmp(label)
			-- Near jump is 5 bytes: 1 byte opcode (0xE9) + 4 byte offset
			local jump_pos = self.pos
			self:emit(0xE9)

			if not self.labels[label] then
				self.labels[label] = {references = {}, defined = false}
			end

			-- Add reference with proper size information
			table.insert(
				self.labels[label].references,
				{
					pos = jump_pos,
					type = "near",
					size = 5, -- Total size: 1 byte opcode + 4 byte offset
				}
			)
			-- Emit placeholder bytes for offset
			self:emit(0, 0, 0, 0)
		end

		-- Update label implementation
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

		-- Update resolve_labels to handle different jump types
		function Assembler:resolve_labels(code)
			local bytes = {string.byte(code, 1, #code)}

			for name, label in pairs(self.labels or {}) do
				if not label.defined then error("Undefined label: " .. name) end

				for _, ref in ipairs(label.references) do
					local next_instruction_pos = ref.pos + ref.size
					local offset = label.pos - next_instruction_pos
					-- Offset position depends on the instruction type
					local offset_pos = ref.pos + (ref.type == "near" and 1 or 2)
					-- Write offset in little-endian format
					bytes[offset_pos] = bit.band(offset, 0xFF)
					bytes[offset_pos + 1] = bit.band(bit.rshift(offset, 8), 0xFF)
					bytes[offset_pos + 2] = bit.band(bit.rshift(offset, 16), 0xFF)
					bytes[offset_pos + 3] = bit.band(bit.rshift(offset, 24), 0xFF)
				end
			end

			return string.char(unpack(bytes))
		end
	end
end
