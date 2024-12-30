return function(Assembler) -- x64_86
	local reginfo = {}

	-- Standard registers
	for i, name in ipairs({"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"}) do
		reginfo["r" .. name] = {
			bits = 64,
			extra = false,
			index = i - 1,
		}
		reginfo["e" .. name] = {
			bits = 32,
			extra = false,
			index = i - 1,
		}
	end

	-- r8-r15
	for i = 8, 15 do
		reginfo["r" .. i] = {
			bits = 64,
			extra = true,
			index = i - 8,
		}
	end

	-- r8d-r15d
	for i = 8, 15 do
		reginfo["r" .. i .. "d"] = {
			bits = 32,
			extra = true,
			index = i - 8,
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
				extra = i > 7,
				index = i % 8,
				class = "simd",
				width = info.width,
			}
		end
	end

	-- AVX-512 mask registers
	for i = 0, 7 do
		reginfo["k" .. i] = {bits = 64, extra = false, index = i, class = "mask"}
	end

	-- RIP for RIP-relative addressing
	reginfo.rip = {bits = 64, rip = true, class = "ip"}

	local function IS_REG(val)
		if type(val) == "string" and reginfo[val] then return true end

		if type(val) == "table" and val.reg and reginfo[val.reg] then
			return true
		end

		if type(val) == "table" and val.index and reginfo[val.index] then
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

			return new
		elseif type(val) == "table" then
			if not reginfo[val.reg] and not reginfo[val.index] then
				error(
					"field 'reg' or 'index' in val (" .. tostring(val.index or val.reg) .. ") is not a valid register",
					2
				)
			end

			local new = {reg = val.reg, index = val.index}

			for k, v in pairs(reginfo[val.reg or val.index]) do
				new[k] = v
			end

			for k, v in pairs(val) do
				new[k] = v
			end

			return new
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
			local function log2(n)
				local result = 0

				while n > 1 do
					n = n / 2
					result = result + 1
				end

				return result
			end

			local function encode_modrm(mod, reg, rm)
				-- mod: 2 bits (00, 01, 10, 11)
				-- reg: 3 bits (000-111)
				-- rm:  3 bits (000-111)
				return bit.bor(
					bit.lshift(bit.band(mod, 0x3), 6),
					bit.lshift(bit.band(reg, 0x7), 3),
					bit.band(rm, 0x7)
				)
			end

			local function encode_sib(scale, index, base)
				-- scale: 2 bits (00=1, 01=2, 10=4, 11=8)
				-- index: 3 bits (000-111)
				-- base:  3 bits (000-111)
				return bit.bor(
					bit.lshift(bit.band(scale, 0x3), 6),
					bit.lshift(bit.band(index, 0x7), 3),
					bit.band(base, 0x7)
				)
			end

			function Assembler:emit_modrm_sib(op1, op2)
				op1 = REG(op1)
				op2 = REG(op2)
				local reg1 = op1.reg and reginfo[op1.reg].index
				local reg2 = op2.reg and reginfo[op2.reg].index
				local index = IS_REG(op2.index) and REG(op2.index).index
				local scale = op2.scale
				local disp = op2.disp
				local indirect = op2.indirect

				-- Handle register-to-register
				if not indirect and reg1 and reg2 then
					-- ModRM: mod=11, reg=reg1, rm=reg2
					self:emit(encode_modrm(3, reg1, reg2))
					return
				end

				-- Handle indirect memory access
				if indirect and reg2 then
					if disp == nil then
						-- [reg] - no displacement
						self:emit(encode_modrm(0, reg1, reg2))
					elseif disp >= -128 and disp <= 127 then
						-- [reg + disp8]
						self:emit(encode_modrm(1, reg1, reg2))
						self:emit_i8(disp)
					else
						-- [reg + disp32]
						self:emit(encode_modrm(2, reg1, reg2))
						self:emit_i32(disp)
					end

					return
				end

				-- Handle SIB cases (scaled index, with or without base)
				if index or op2.scale then
					-- Calculate scale bits (00=1, 01=2, 10=4, 11=8)
					local scale_bits = 0

					if scale == 2 then
						scale_bits = 1
					elseif scale == 4 then
						scale_bits = 2
					elseif scale == 8 then
						scale_bits = 3
					end

					-- Get base register if specified
					local base = op2.base and reginfo[op2.base].index or 5 -- 5 = no base
					-- ModRM byte: mod=00/01/10 (depending on displacement), reg=reg1, rm=100 (SIB follows)
					local mod = 0

					if disp then mod = (disp >= -128 and disp <= 127) and 1 or 2 end

					self:emit(encode_modrm(mod, reg1, 4)) -- 4 = 0b100 indicates SIB follows
					-- SIB byte: scale=scale_bits, index=index register, base=base register
					local idx = index or 4 -- 4 = 0b100 means no index
					self:emit(encode_sib(scale_bits, idx, base))

					-- Emit displacement
					if disp then
						if mod == 1 then
							self:emit_i8(disp)
						else
							self:emit_i32(disp)
						end
					elseif base == 5 then
						-- When no base register or base is [rbp+disp], we need a 32-bit displacement
						self:emit_i32(0)
					end

					return
				end

				-- Handle RIP-relative addressing
				if op2.reg == "rip" then
					self:emit(encode_modrm(0, reg1, 5)) -- ModRM: mod=00, reg=reg1, rm=101
					self:emit_i32(disp or 0)
					return
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
				self:emit(0x0F, 0x28, 0xC0 + reg.index)
			end

			-- Restore rax
			self:pop("rax")
		elseif reg.bits == 64 then
			-- Moving 64-bit immediate to 64-bit register
			self:rex(true, reg.extra, false, false)
			self:emit(0xB8 + reg.index)

			if signed then self:emit_i64(imm) else self:emit_u64(imm) end
		elseif reg.bits == 32 then
			if reg.extra then self:rex(false, reg.extra, false, false) end

			self:emit(0xB8 + reg.index)

			if signed then self:emit_i32(imm) else self:emit_u32(imm) end
		end
	end

	function Assembler:mov_reg_to_reg(op1, op2)
		local reg1 = REG(op1)
		local reg2 = REG(op2)

		if reg1.class == "simd" and reg2.class == "simd" then
			if reg1.extra or reg2.extra then
				self:rex(false, reg1.extra, reg2.extra, false)
			end

			self:emit(0x0F, 0x28) -- MOVAPS
			self:emit_modrm_sib(reg2, reg1)
		elseif reg1.bits == 64 then
			self:rex(true, reg1.extra, reg2.extra, false)
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

			if reg.extra then self:rex(false, reg.extra, false, false) end

			self:emit(0x0F, 0x29) -- MOVAPS store
			self:emit_modrm_sib(reg, {reg = "rcx", indirect = true})

			if reg ~= "rcx" then self:pop("rcx") end
		elseif reg.bits == 64 then
			if reg ~= "rcx" then self:push("rcx") end

			self:mov("rcx", ptr)
			self:rex(true, reg.extra, false, false)
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

			if reg1.extra then self:rex(false, reg1.extra, false, false) end

			self:emit(0x0F)
			self:emit(0x28) -- MOVAPS load
			self:emit_modrm_sib(reg, {reg = "rcx", indirect = true})

			if reg ~= "rcx" then self:pop("rcx") end
		elseif reg1.bits == 64 then
			if reg == "rcx" then self:push("rcx") end

			self:mov("rcx", ptr)
			self:rex(true, reg1.extra, false, false)
			self:emit(0x8B)
			self:emit_modrm_sib(reg, {reg = "rcx", indirect = true})

			if reg == "rcx" then self:pop("rcx") end
		end
	end

	function Assembler:mov(op1, op2, signed)
		if IS_REG(op1) and tonumber(op2) then
			self:mov_imm_to_reg(op1, op2, signed)
		elseif IS_REG(op1) and IS_REG(op2) then
			self:mov_reg_to_reg(op1, op2)
		else
			error("invalid arguments", 2)
		end
	end

	function Assembler:push(op)
		-- If op is a register
		local reg = REG(op)

		-- Handle 64-bit registers
		if reg.bits == 64 then
			-- Check if we need REX prefix for r8-r15
			if reg.extra then self:rex(false, reg.extra, false, false) end

			-- Base opcode for push is 0x50 + register index
			self:emit(0x50 + reg.index)
		else
			error("push only supports 64-bit registers")
		end
	end

	function Assembler:pop(op)
		local reg = REG(op)

		-- Handle 64-bit registers
		if reg.bits == 64 then
			-- Check if we need REX prefix for r8-r15
			if reg.extra then self:rex(false, reg.extra, false, false) end

			-- Base opcode for pop is 0x58 + register index
			self:emit(0x58 + reg.index)
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

			if dst.extra or src.extra then
				self:rex(false, src.extra, dst.extra, false)
			end

			self:emit(0x0F, 0x28)
			self:emit_modrm_sib(dst, src)
		end

		function Assembler:movaps_load(dest_reg, src_mem)
			local reg = REG(dest_reg)
			assert(reg.class == "simd", "movaps requires SSE register as destination")

			if reg.extra then self:rex(false, false, reg.extra, false) end

			self:emit(0x0F, 0x28)
			self:emit_modrm_sib(dest_reg, {reg = "rax", indirect = true})
		end

		function Assembler:movaps_store(dest_mem, src_reg)
			local reg = REG(src_reg)
			assert(reg.class == "simd", "movaps requires SSE register as source")

			if reg.extra then self:rex(false, false, reg.extra, false) end

			self:emit(0x0F, 0x29)
			self:emit_modrm_sib(src_reg, {reg = "rax", indirect = true})
		end

		function Assembler:movdqu(op1, op2)
			local reg1 = REG(op1)
			local reg2 = REG(op2)
			assert(reg1.class == "simd" and reg2.class == "simd", "movdqu requires SSE registers")

			if reg1.extra or reg2.extra then
				self:rex(false, reg1.extra, reg2.extra, false)
			end

			self:emit(0xF3, 0x0F, 0x6F)
			self:emit_modrm_sib(reg2, reg1)
		end

		function Assembler:addps(op1, op2)
			local reg1 = REG(op1)
			local reg2 = REG(op2)
			assert(reg1.class == "simd" and reg2.class == "simd", "addps requires SSE registers")

			if reg1.extra or reg2.extra then
				self:rex(false, reg1.extra, reg2.extra, false)
			end

			self:emit(0x0F, 0x58)
			self:emit_modrm_sib(reg2, reg1)
		end

		function Assembler:mulps(op1, op2)
			local reg1 = REG(op1)
			local reg2 = REG(op2)
			assert(reg1.class == "simd" and reg2.class == "simd", "mulps requires SSE registers")

			if reg1.extra or reg2.extra then
				self:rex(false, reg1.extra, reg2.extra, false)
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
			self:emit_modrm_sib(dest_reg, {reg = "rax", indirect = true} -- Load from memory pointed by rax
			)
		end

		function Assembler:vmovups_store(dest_mem, src_reg)
			local reg = REG(src_reg)
			assert(reg.class == "simd", "vmovups requires AVX register as source")
			self:emit(0xC5, 0xFC, 0x11)
			self:emit_modrm_sib(src_reg, {reg = "rax", indirect = true} -- Store to memory pointed by rax
			)
		end
	end
end
