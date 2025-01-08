return function(Assembler)
	local R = Assembler.Registers

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
	end
end
