local Assembler = require("moondust")
local memory = require("moondust.memory")
local ffi = require("ffi")

local function run_tests()
	local function equal(a, b)
		if a ~= b then
			error("expected " .. tostring(a) .. " got " .. tostring(b), 2)
		end
	end

	local function test(test_name, test_function)
		io.write("test - " .. test_name)
		local asm = Assembler()
		local ok, err = xpcall(test_function, debug.traceback, asm)

		if not ok then
			io.write("fail\n\n")
			print("source:")
			print("===")
			print(asm:debug_disassemble())
			print("===")
			error(err)
		end
	end

	test("write std out", function(asm)
		local msg = "hello world\n"
		local STDOUT_FILENO = 1
		local WRITE = jit.os == "Linux" and 1 or 0x2000004
		asm:mov("rax", WRITE)
		asm:mov("rdi", STDOUT_FILENO)
		asm:mov("rsi", memory.object_to_address(msg))
		asm:mov("rdx", #msg)
		asm:syscall()
		asm:ret()
		local fn = ffi.cast("void (*)(void)", asm:build())
		fn()
	end)

	test("generated mov operations", function(asm)
		-- Generate list of all 64-bit registers
		local regs_64 = {
			-- Standard registers
			"rax",
			"rbx",
			"rcx",
			"rdx",
			"rsi",
			"rdi",
			"rsp",
			"rbp",
			-- Extended registers
			"r8",
			"r9",
			"r10",
			"r11",
			"r12",
			"r13",
			"r14",
			"r15",
		}
		-- Test values to try (including edge cases and interesting bit patterns)
		local test_values = {
			0ULL, -- Zero
			42ULL, -- Small positive
			0xFFULL, -- One byte
			0xFFFFULL, -- Two bytes
			0xFFFFFFFFULL, -- Four bytes
			0x7FFFFFFFFFFFFFFFLL, -- Max signed 64-bit
			-1LL, -- All bits set (signed)
			0x1234567890ABCDEFULL, -- Mixed bits (unsigned)
			0x0F0F0F0F0F0F0F0FULL, -- Pattern (unsigned)
			0xF0F0F0F0F0F0F0F0ULL, -- Inverse pattern (unsigned)
			-- Additional edge cases
			0x8000000000000000ULL, -- Min signed value as unsigned
			0xFFFFFFFFFFFFFFFFULL, -- Max unsigned value
		}

		-- Test immediate to register for each register and test value
		for _, reg in ipairs(regs_64) do
			for _, val in ipairs(test_values) do
				-- Skip rsp and rbp as they're special registers that might crash
				if reg ~= "rsp" and reg ~= "rbp" then
					asm = Assembler()
					print(string.format("\tmov %s, 0x%x", reg, val))

					if reg ~= "rax" then asm:push(reg) end

					-- Move test value to target register
					asm:mov(reg, val)

					-- Move from target register to rax for return
					if reg ~= "rax" then asm:mov("rax", reg) end

					if reg ~= "rax" then asm:pop(reg) end

					asm:ret()
					local fn = ffi.cast("uint64_t (*)(void)", asm:build())
					local result = fn()

					if result ~= val then
						error(
							string.format(
								"Immediate to register failed: mov %s, 0x%x - Expected 0x%x, got 0x%x",
								reg,
								val,
								val,
								result
							)
						)
					end
				end
			end
		end

		for _, src_reg in ipairs(regs_64) do
			for _, dst_reg in ipairs(regs_64) do
				-- Skip combinations with rsp and rbp
				if
					src_reg ~= "rsp" and
					src_reg ~= "rbp" and
					dst_reg ~= "rsp" and
					dst_reg ~= "rbp"
				then
					asm = Assembler()
					local test_val = 0x1234567890ABCDEFLL
					print(string.format("\tmov %s, %s", dst_reg, src_reg))

					-- Save registers we're going to modify
					if src_reg ~= "rax" then asm:push(src_reg) end

					if dst_reg ~= "rax" and dst_reg ~= src_reg then asm:push(dst_reg) end

					-- Setup source register with test value
					asm:mov(src_reg, test_val)
					-- Perform register to register move
					asm:mov(dst_reg, src_reg)

					-- Move result to rax if it's not already there
					if dst_reg ~= "rax" then asm:mov("rax", dst_reg) end

					-- Restore registers in reverse order
					if dst_reg ~= "rax" and dst_reg ~= src_reg then asm:pop(dst_reg) end

					if src_reg ~= "rax" then asm:pop(src_reg) end

					asm:ret()
					local fn = ffi.cast("uint64_t (*)(void)", asm:build())
					local result = fn()

					if result ~= test_val then
						error(
							string.format(
								"Register to register failed: mov %s, %s - Expected 0x%x, got 0x%x",
								dst_reg,
								src_reg,
								test_val,
								result
							)
						)
					end
				end
			end
		end

		local mem = ffi.new("uint64_t[1]")

		-- Test storing each value from register to memory
		for _, val in ipairs(test_values) do
			asm = Assembler()
			print(string.format("\tmov [mem], rax (storing 0x%x)", val))
			-- Load test value into rax
			asm:mov("rax", val)
			-- Store rax to memory
			asm:mov_reg_to_pointer("rax", memory.object_to_address(mem))
			asm:ret()
			local fn = ffi.cast("void (*)(void)", asm:build())
			fn()

			-- Verify memory contains the correct value
			if mem[0] ~= val then
				error(string.format("Memory store failed - Expected 0x%x, got 0x%x", val, memory[0]))
			end
		end

		-- Test loading each value from memory to register
		for _, val in ipairs(test_values) do
			-- First set up the test value in memory
			mem[0] = val
			asm = Assembler()
			print(string.format("\tmov rax, [mem] (loading 0x%x)", val))
			-- Load from memory into rax
			asm:mov_pointer_to_reg("rax", memory.object_to_address(mem))
			asm:ret()
			local fn = ffi.cast("uint64_t (*)(void)", asm:build())
			local result = fn()

			if result ~= val then
				error(string.format("Memory load failed - Expected 0x%x, got 0x%x", val, result))
			end
		end

		-- Test round trip (register -> memory -> different register)
		for _, val in ipairs(test_values) do
			asm = Assembler()
			print(string.format("\tround trip through memory 0x%x", val))
			-- Save rbx as we'll use it
			asm:push("rbx")
			-- Load test value into rbx
			asm:mov("rbx", val)
			-- Store rbx to memory
			asm:mov_reg_to_pointer("rbx", memory.object_to_address(mem))
			-- Load from memory into rax
			asm:mov_pointer_to_reg("rax", memory.object_to_address(mem))
			-- Restore rbx
			asm:pop("rbx")
			asm:ret()
			local fn = ffi.cast("uint64_t (*)(void)", asm:build())
			local result = fn()

			if result ~= val then
				error(string.format("Memory round trip failed - Expected 0x%x, got 0x%x", val, result))
			end
		end
	end)

	ffi.cdef[[
        typedef struct { 
            float data[8] __attribute__((aligned(32))); 
        } AlignedAVXArray;
    ]]

	test("avx unaligned store", function(asm)
		local asm = Assembler()
		-- Create source and destination arrays (not necessarily aligned)
		local source = ffi.new("float[8]")
		local result = ffi.new("float[8]")

		-- Initialize source data
		for i = 0, 7 do
			source[i] = i + 1.0
			result[i] = 0.0
		end

		-- Generate AVX unaligned store test code
		asm:push("rax")
		-- Load source address into rax
		asm:mov("rax", memory.object_to_address(source))
		asm:vmovups_load("ymm0", "rax")
		-- Store ymm0 to result
		asm:mov("rax", memory.object_to_address(result))
		asm:vmovups_store("rax", "ymm0")
		asm:pop("rax")
		asm:ret()
		-- Run the code
		local fn = ffi.cast("void (*)(void)", asm:build())
		fn()

		-- Verify results
		for i = 0, 7 do
			local expected = source[i]
			local got = result[i]
			print(string.format("\tindex %d: expected=%f, got=%f", i, expected, got))
			assert(
				math.abs(got - expected) < 0.0001,
				string.format(
					"AVX unaligned store test failed at index %d: expected %f, got %f",
					i,
					expected,
					got
				)
			)
		end
	end)

	test("avx aligned store", function(asm)
		local asm = Assembler()
		-- Create aligned source and destination arrays
		local source = ffi.new("AlignedAVXArray")
		local result = ffi.new("AlignedAVXArray")

		-- Initialize source data
		for i = 0, 7 do
			source.data[i] = i + 1.0
			result.data[i] = 0.0 -- Clear result array
		end

		-- Generate AVX store test code
		asm:push("rax")
		-- Load source address into rax and load data into ymm0
		asm:mov("rax", memory.object_to_address(source.data))
		asm:vmovups_load("ymm0", "rax")
		-- Store ymm0 to result
		asm:mov("rax", memory.object_to_address(result.data))
		asm:vmovaps_store("rax", "ymm0")
		asm:pop("rax")
		asm:ret()
		-- Run the code
		local fn = ffi.cast("void (*)(void)", asm:build())
		fn()

		-- Verify results
		for i = 0, 7 do
			local expected = source.data[i]
			local got = result.data[i]
			print(string.format("\tindex %d: expected=%f, got=%f", i, expected, got))
			assert(
				math.abs(got - expected) < 0.0001,
				string.format("AVX store test failed at index %d: expected %f, got %f", i, expected, got)
			)
		end
	end)

	test("sse store", function(asm)
		-- Define aligned float array type
		ffi.cdef[[
			typedef struct { float data[4] __attribute__((aligned(16))); } AlignedFloatArray;
		]]
		local source = ffi.new("AlignedFloatArray")
		local result = ffi.new("AlignedFloatArray")
		-- Initialize source data
		source.data[0] = 1.0
		source.data[1] = 2.0
		source.data[2] = 3.0
		source.data[3] = 4.0

		-- Clear result array
		for i = 0, 3 do
			result.data[i] = 0.0
		end

		-- Generate SSE code
		asm:push("rax")
		-- Load source address and load into xmm0
		asm:mov("rax", memory.object_to_address(source.data))
		-- Load from [rax] to xmm0
		asm:movaps_load("xmm0", "rax")
		-- Move from xmm0 to xmm1
		asm:movaps("xmm1", "xmm0")
		-- Store xmm1 to result
		asm:mov("rax", memory.object_to_address(result.data))
		asm:movaps_store("rax", "xmm1")
		asm:pop("rax")
		asm:ret()
		-- Run the code
		local fn = ffi.cast("void (*)(void)", asm:build())
		fn()

		-- Verify results
		for i = 0, 3 do
			local expected = source.data[i]
			local got = result.data[i]
			print(string.format("\tindex %d: expected=%f, got=%f", i, expected, got))
			assert(
				math.abs(got - expected) < 0.0001,
				string.format("SSE test failed at index %d: expected %f, got %f", i, expected, got)
			)
		end
	end)
end

local function test_modrm_sib()
	local asm = Assembler()
	-- Test 1: Register to register (mov %rax,%rbx)
	asm:emit(0x48) -- REX.W
	asm:emit(0x89) -- MOV r/m64, r64
	asm:emit_modrm_sib({reg = "rax"}, {reg = "rbx"})
	asm:emit(0x90) -- nop
	-- Test 2: Base register only (mov (%rcx),%rax)
	asm:emit(0x48) -- REX.W
	asm:emit(0x8B) -- MOV r64, r/m64
	asm:emit_modrm_sib({reg = "rax"}, {reg = "rcx", indirect = true})
	asm:emit(0x90) -- nop
	-- Test 3: Base + 8-bit displacement (mov 8(%rdx),%rax)
	asm:emit(0x48) -- REX.W
	asm:emit(0x8B) -- MOV r64, r/m64
	asm:emit_modrm_sib({reg = "rax"}, {reg = "rdx", disp = 8, indirect = true})
	asm:emit(0x90) -- nop
	-- Test 4: Base + 32-bit displacement (mov 1000(%rbx),%rax)
	asm:emit(0x48) -- REX.W
	asm:emit(0x8B) -- MOV r64, r/m64
	asm:emit_modrm_sib({reg = "rax"}, {reg = "rbx", disp = 1000, indirect = true})
	asm:emit(0x90) -- nop
	-- Test 5: SIB with scaled index (mov (,%rcx,4),%rax)
	asm:emit(0x48) -- REX.W
	asm:emit(0x8B) -- MOV r64, r/m64
	asm:emit_modrm_sib({reg = "rax"}, {index = "rcx", scale = 4})
	asm:emit(0x90) -- nop
	-- Test 6: SIB with base + scaled index (mov (%rbx,%rcx,4),%rax)
	asm:emit(0x48) -- REX.W
	asm:emit(0x8B) -- MOV r64, r/m64
	asm:emit_modrm_sib({reg = "rax"}, {base = "rbx", index = "rcx", scale = 4})
	asm:emit(0x90) -- nop
	-- Test 7: SIB with base + scaled index + 8-bit disp (mov 8(%rbx,%rcx,4),%rax)
	asm:emit(0x48) -- REX.W
	asm:emit(0x8B) -- MOV r64, r/m64
	asm:emit_modrm_sib({reg = "rax"}, {base = "rbx", index = "rcx", scale = 4, disp = 8})
	asm:emit(0x90) -- nop
	-- Test 8: SIB with base + scaled index + 32-bit disp (mov 1000(%rbx,%rcx,4),%rax)
	asm:emit(0x48) -- REX.W
	asm:emit(0x8B) -- MOV r64, r/m64
	asm:emit_modrm_sib({reg = "rax"}, {base = "rbx", index = "rcx", scale = 4, disp = 1000})
	asm:emit(0x90) -- nop
	-- Test 9: RIP-relative (mov 32(%rip),%rax)
	asm:emit(0x48) -- REX.W
	asm:emit(0x8B) -- MOV r64, r/m64
	asm:emit_modrm_sib({reg = "rax"}, {reg = "rip", disp = 32})
	asm:emit(0x90) -- nop
	-- Test 10: Special case - [rbp] (mov 0(%rbp),%rax)
	asm:emit(0x48) -- REX.W
	asm:emit(0x8B) -- MOV r64, r/m64
	asm:emit_modrm_sib({reg = "rax"}, {reg = "rbp", disp = 0, indirect = true})
	asm:emit(0x90) -- nop
	-- Print hex and disassembly
	print("\nGenerated machine code (hex):")
	print(asm:debug_print_hex())
	asm:build()
	print("\nDisassembly:")
	print(asm:debug_disassemble())
end

-- Run the tests
test_modrm_sib()
run_tests()
