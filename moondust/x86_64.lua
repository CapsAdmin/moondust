return function(Assembler) -- x64_86
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

	local function IS_REG(val)
		if type(val) == "string" and reginfo[val] then return true end

		if type(val) == "table" and val.reg and reginfo[val.reg] then
			return true
		end

		if type(val) == "table" and val.index and reginfo[val.index] then
			return true
		end

		if type(val) == "table" and val.base and reginfo[val.base] then
			return true
		end

		return false
	end

	local function REG(val)
		if type(val) == "string" then
			if not reginfo[val] then error(val .. " is not a valid register", 2) end

			local new = {reg = val}

			for k, v in pairs(reginfo[val]) do
				new[k] = v
			end

			assert(type(new.i) == "number")
			return new
		elseif type(val) == "table" then
			for _, key in ipairs({"reg", "index", "base"}) do
				if val[key] then
					if not reginfo[val[key]] then
						error(
							"field '" .. key .. "' in val (" .. tostring(val[key]) .. ") is not a valid register",
							2
						)
					end

					local new = {[key] = val[key]}

					for k, v in pairs(reginfo[val[key]]) do
						new[k] = v
					end

					for k, v in pairs(val) do
						new[k] = v
					end

					return new
				end
			end

			error("val is not a valid register")
		end
	end

	do
		function Assembler:rex(W, B, R, X)
			local rex = 0b01000000 -- Fixed REX prefix
			if W then rex = bit.bor(rex, 0b00001000) end -- 64-bit operand
			if R then rex = bit.bor(rex, 0b00000100) end -- Extension of ModR/M reg field
			if X then rex = bit.bor(rex, 0b00000010) end -- Extension of SIB index field
			if B then rex = bit.bor(rex, 0b00000001) end -- Extension of ModR/M r/m, SIB base, or opcode reg field
			return self:emit(rex)
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

			function Assembler:emit_modrm_sib(op1, op2)
				local reg1 = REG(op1)
				local reg2 = REG(op2)
				local is_sp = reg2 and (reg2.index == "esp" or reg2.index == "rsp")

				if reg2.index and is_sp then
					error("ESP/RSP cannot be used as an index register", 2)
				end

				if reg2.scale and not scale_bits[reg2.scale] then
					error("Invalid scale value: " .. tostring(reg2.scale), 2)
				end

				if reg2.rip and (reg2.index or reg2.scale or reg2.base) then
					error("RIP-relative addressing cannot use index, scale, or base", 2)
				end

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
					self:emit(encode_sib(reg2.scale, REG(reg2.index), {i = NO_BASE}))
					self:emit_i32(0) -- Important: emit 32-bit zero displacement
				else
					-- Inside emit_modrm_sib function, modify the SIB case handling:
					if reg2.index or reg2.scale or is_sp then
						self:emit(encode_modrm(mod, reg1, {i = SIB_INDICATOR}))
						-- Ensure we're using the correct index register for SIB
						local index_reg = reg2.index and REG(reg2.index) or nil
						local base_reg = reg2.base and REG(reg2.base) or reg2
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

	function Assembler:mov_imm_to_reg(op1, op2, signed)
		local reg = REG(op1)
		assert(tonumber(op2))
		local imm = op2

		if reg.class == "simd" then
			-- For SSE registers, we need to:
			-- 1. Store the immediate value in memory
			-- 2. Move it into the XMM register
			-- Save rax if we need it
			self:push("rax")

			-- Move immediate to memory via rax
			if reg.width == 128 then -- XMM registers
				self:rex(true, false, false, false)
				self:emit(0x0F, 0x28, 0xC0 + reg.i)
			end

			-- Restore rax
			self:pop("rax")
		elseif reg.bits == 64 then
			-- Moving 64-bit immediate to 64-bit register
			self:rex(true, reg.is_extended, false, false)
			self:emit(0xB8 + reg.i)

			if signed then self:emit_i64(imm) else self:emit_u64(imm) end
		elseif reg.bits == 32 then
			if reg.is_extended then self:rex(false, reg.is_extended, false, false) end

			self:emit(0xB8 + reg.i)

			if signed then self:emit_i32(imm) else self:emit_u32(imm) end
		end
	end

	function Assembler:mov_reg_to_reg(op1, op2)
		local reg1 = REG(op1)
		local reg2 = REG(op2)

		if reg1.class == "simd" and reg2.class == "simd" then
			if reg1.is_extended or reg2.is_extended then
				self:rex(false, reg1.is_extended, reg2.is_extended, false)
			end

			self:emit(0x0F, 0x28) -- MOVAPS
			self:emit_modrm_sib(reg2, reg1)
		elseif reg1.bits == 64 then
			self:rex(true, reg1.is_extended, reg2.is_extended, false)
			self:emit(0x89)
			self:emit_modrm_sib(reg2, reg1)
		end
	end

	-- Refactored mov_reg_to_pointer
	function Assembler:mov_reg_to_pointer(reg, ptr)
		local reg = REG(reg)

		if reg.class == "simd" then
			if reg ~= "rcx" then self:push("rcx") end

			self:mov("rcx", ptr)

			if reg.is_extended then self:rex(false, reg.is_extended, false, false) end

			self:emit(0x0F, 0x29) -- MOVAPS store
			self:emit_modrm_sib(reg, {reg = "rcx", indirect = true})

			if reg ~= "rcx" then self:pop("rcx") end
		elseif reg.bits == 64 then
			if reg ~= "rcx" then self:push("rcx") end

			self:mov("rcx", ptr)
			self:rex(true, reg.is_extended, false, false)
			self:emit(0x89)
			self:emit_modrm_sib(reg, {reg = "rcx", indirect = true})

			if reg ~= "rcx" then self:pop("rcx") end
		end
	end

	function Assembler:mov_pointer_to_reg(reg, ptr)
		local reg1 = REG(reg)

		if reg1.class == "simd" then
			if reg ~= "rcx" then self:push("rcx") end

			self:mov("rcx", ptr)

			if reg1.is_extended then self:rex(false, reg1.is_extended, false, false) end

			self:emit(0x0F)
			self:emit(0x28) -- MOVAPS load
			self:emit_modrm_sib(reg, {reg = "rcx", indirect = true})

			if reg ~= "rcx" then self:pop("rcx") end
		elseif reg1.bits == 64 then
			if reg == "rcx" then self:push("rcx") end

			self:mov("rcx", ptr)
			self:rex(true, reg1.is_extended, false, false)
			self:emit(0x8B)
			self:emit_modrm_sib(reg, {reg = "rcx", indirect = true})

			if reg == "rcx" then self:pop("rcx") end
		end
	end

	function Assembler:mov_reg_from_mem(reg, mem)
		local reg1 = REG(reg)
		local mem_op = REG(mem)

		if reg1.bits == 64 then
			self:rex(true, reg1.is_extended, mem_op.is_extended, false)
			self:emit(0x8B) -- MOV r64, r/m64
			self:emit_modrm_sib(reg1, mem_op)
		else
			error("mov from memory only supports 64-bit registers", 2)
		end
	end

	function Assembler:mov_mem_from_reg(mem, reg)
		local reg1 = REG(reg)
		local mem_op = REG(mem)

		if reg1.bits == 64 then
			self:rex(true, reg1.is_extended, mem_op.is_extended, false)
			self:emit(0x89) -- MOV r/m64, r64
			self:emit_modrm_sib(reg1, mem_op)
		else
			error("mov to memory only supports 64-bit registers", 2)
		end
	end

	-- Update the mov function to handle memory operands
	function Assembler:mov(op1, op2, signed)
		if IS_REG(op1) and tonumber(op2) then
			self:mov_imm_to_reg(op1, op2, signed)
		elseif IS_REG(op1) and IS_REG(op2) then
			-- Memory operand if it has indirect flag or uses SIB addressing
			if op2.indirect or op2.index or op2.scale or op2.base or op2.rip then
				self:mov_reg_from_mem(op1, op2)
			elseif op1.indirect or op1.index or op1.scale or op1.base or op1.rip then
				self:mov_mem_from_reg(op1, op2)
			else
				self:mov_reg_to_reg(op1, op2)
			end
		else
			error("is not a valid register", 2)
		end
	end

	function Assembler:push(op)
		-- If op is a register
		local reg = REG(op)

		-- Handle 64-bit registers
		if reg.bits == 64 then
			-- Check if we need REX prefix for r8-r15
			if reg.is_extended then self:rex(false, reg.is_extended, false, false) end

			-- Base opcode for push is 0x50 + register index
			self:emit(0x50 + reg.i)
		else
			error("push only supports 64-bit registers")
		end
	end

	function Assembler:pop(op)
		local reg = REG(op)

		-- Handle 64-bit registers
		if reg.bits == 64 then
			-- Check if we need REX prefix for r8-r15
			if reg.is_extended then self:rex(false, reg.is_extended, false, false) end

			-- Base opcode for pop is 0x58 + register index
			self:emit(0x58 + reg.i)
		else
			error("pop only supports 64-bit registers")
		end
	end

	function Assembler:syscall()
		self:emit(0x0F, 0x05)
	end

	do --sse
		-- Add SSE instructions to the Assembler
		function Assembler:movaps(op1, op2)
			local dst = REG(op1)
			local src = REG(op2)
			assert(dst.class == "simd" and src.class == "simd", "movaps requires SSE registers")

			if dst.is_extended or src.is_extended then
				self:rex(false, src.is_extended, dst.is_extended, false)
			end

			self:emit(0x0F, 0x28)
			self:emit_modrm_sib(dst, src)
		end

		function Assembler:movaps_load(dest_reg, src_mem)
			local reg = REG(dest_reg)
			assert(reg.class == "simd", "movaps requires SSE register as destination")

			if reg.is_extended then self:rex(false, false, reg.is_extended, false) end

			self:emit(0x0F, 0x28)
			self:emit_modrm_sib(dest_reg, {reg = "rax", indirect = true})
		end

		function Assembler:movaps_store(dest_mem, src_reg)
			local reg = REG(src_reg)
			assert(reg.class == "simd", "movaps requires SSE register as source")

			if reg.is_extended then self:rex(false, false, reg.is_extended, false) end

			self:emit(0x0F, 0x29)
			self:emit_modrm_sib(src_reg, {reg = "rax", indirect = true})
		end

		function Assembler:movdqu(op1, op2)
			local reg1 = REG(op1)
			local reg2 = REG(op2)
			assert(reg1.class == "simd" and reg2.class == "simd", "movdqu requires SSE registers")

			if reg1.is_extended or reg2.is_extended then
				self:rex(false, reg1.is_extended, reg2.is_extended, false)
			end

			self:emit(0xF3, 0x0F, 0x6F)
			self:emit_modrm_sib(reg2, reg1)
		end

		function Assembler:addps(op1, op2)
			local reg1 = REG(op1)
			local reg2 = REG(op2)
			assert(reg1.class == "simd" and reg2.class == "simd", "addps requires SSE registers")

			if reg1.is_extended or reg2.is_extended then
				self:rex(false, reg1.is_extended, reg2.is_extended, false)
			end

			self:emit(0x0F, 0x58)
			self:emit_modrm_sib(reg2, reg1)
		end

		function Assembler:mulps(op1, op2)
			local reg1 = REG(op1)
			local reg2 = REG(op2)
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
		function Assembler:vmovaps(op1, op2)
			local dst = REG(op1)
			local src = REG(op2)
			assert(dst.class == "simd" and src.class == "simd", "vmovaps requires AVX registers")
			self:emit(0xC5, 0xFC, 0x28)
			self:emit_modrm_sib(dst, src)
		end

		function Assembler:vmovaps_store(dest_mem, src_reg)
			local reg = REG(src_reg)
			assert(reg.class == "simd", "vmovaps requires AVX register as source")
			self:emit(0xC5, 0xFC, 0x29)
			self:emit_modrm_sib(reg, {reg = "rax", indirect = true})
		end

		function Assembler:vmovups(op1, op2)
			local dst = REG(op1)
			local src = REG(op2)
			assert(dst.class == "simd" and src.class == "simd", "vmovups requires AVX registers")
			self:emit(0xC5, 0xFC, 0x10)
			self:emit_modrm_sib(dst, src)
		end

		function Assembler:vmovups_load(dest_reg, src_mem)
			local reg = REG(dest_reg)
			assert(reg.class == "simd", "vmovups requires AVX register as destination")
			self:emit(0xC5, 0xFC, 0x10)
			self:emit_modrm_sib(dest_reg, {reg = "rax", indirect = true}) -- Load from memory pointed by rax
		end

		function Assembler:vmovups_store(dest_mem, src_reg)
			local reg = REG(src_reg)
			assert(reg.class == "simd", "vmovups requires AVX register as source")
			self:emit(0xC5, 0xFC, 0x11)
			self:emit_modrm_sib(src_reg, {reg = "rax", indirect = true}) -- Store to memory pointed by rax
		end
	end
end
