local Assembler = require("moondust")

do
	do
		-- Instructions use the pattern:
		-- F2 0F opcode ModRM
		-- Where F2 is the REPNE/REPNZ prefix used to indicate double-precision operation
		function Assembler:movsd(dest_reg, src_op)
			-- If source is memory operand
			if src_op.indirect then
				assert(dest_reg.class == "simd", "movsd load requires SSE2 register as destination")

				if dest_reg.is_extended then
					self:rex(false, false, dest_reg.is_extended, false)
				end

				self:emit(0xF2, 0x0F, 0x10) -- F2 0F 10 /r - MOVSD xmm, m64
				self:emit_modrm_sib(dest_reg, src_op)
				return
			end

			-- If destination is memory operand
			if dest_reg.indirect then
				assert(src_op.class == "simd", "movsd store requires SSE2 register as source")

				if src_op.is_extended then
					self:rex(false, false, src_op.is_extended, false)
				end

				self:emit(0xF2, 0x0F, 0x11) -- F2 0F 11 /r - MOVSD m64, xmm
				self:emit_modrm_sib(src_op, dest_reg)
				return
			end

			-- Register to register move
			assert(
				dest_reg.class == "simd" and src_op.class == "simd",
				"movsd reg-reg requires SSE2 registers"
			)

			if dest_reg.is_extended or src_op.is_extended then
				self:rex(false, false, dest_reg.is_extended, false)
			end

			self:emit(0xF2, 0x0F, 0x10) -- F2 0F 10 /r - MOVSD xmm1, xmm2
			self:emit_modrm_sib(dest_reg, src_op)
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
	end
end

local R = Assembler.Registers
local memory = require("moondust.memory")
local ffi = require("ffi")
-- Create test values
local x, y, z = 10.5, 23, 123
print(math.sqrt(x * x + y * y + z * z))
-- Create input/output arrays
local input = ffi.new("double[3]", x, y, z)
local output = ffi.new("double[1]", 0)
_G.refs = {input, output}
-- Create assembler instance
local a = Assembler()
-- Load the values into XMM registers using absolute addressing
a:movsd(R.xmm0, R({indirect = true, disp = memory.object_to_address(input + 0)}))
a:movsd(R.xmm1, R({indirect = true, disp = memory.object_to_address(input + 1)}))
a:movsd(R.xmm2, R({indirect = true, disp = memory.object_to_address(input + 2)}))
-- Perform calculations
a:mulsd(R.xmm0, R.xmm0)
a:mulsd(R.xmm1, R.xmm1)
a:mulsd(R.xmm2, R.xmm2)
-- add
a:addsd(R.xmm2, R.xmm1)
a:addsd(R.xmm1, R.xmm0)
a:sqrtsd(R.xmm0, R.xmm0)
-- Store the result
a:movsd(R({indirect = true, disp = memory.object_to_address(output)}), R.xmm0)
a:ret()
print(a:debug_disassemble())
print(a:debug_hex())
-- Build and run
local func = a:build("void (*)(void)")
func()
print(output[0])
