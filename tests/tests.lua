local Assembler = require("moondust")
local memory = require("moondust.memory")
local ffi = require("ffi")

local function equal(a, b, level)
	if a ~= b then
		error("expected " .. tostring(a) .. " got " .. tostring(b), level or 2)
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
		error(err, 2)
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

				--print(string.format("\tmov %s, 0x%x", reg, val))
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

				--print(string.format("\tmov %s, %s", dst_reg, src_reg))
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
		--print(string.format("\tmov [mem], rax (storing 0x%x)", val))
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
		--print(string.format("\tmov rax, [mem] (loading 0x%x)", val))
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
		--print(string.format("\tround trip through memory 0x%x", val))
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
		--print(string.format("\tindex %d: expected=%f, got=%f", i, expected, got))
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
		--print(string.format("\tindex %d: expected=%f, got=%f", i, expected, got))
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
		--print(string.format("\tindex %d: expected=%f, got=%f", i, expected, got))
		assert(
			math.abs(got - expected) < 0.0001,
			string.format("SSE test failed at index %d: expected %f, got %f", i, expected, got)
		)
	end
end)

local function compare(func, expect)
	local asm = Assembler()
	func(asm)
	equal(expect, asm:debug_disassemble(), 3)
end

-- Test 1: Register to register
compare(function(asm)
	asm:mov("rbx", "rax")
end, "mov rbx,rax")

-- Test 2: Base register only (indirect)
compare(
	function(asm)
		asm:mov("rax", {reg = "rcx", indirect = true})
	end,
	"mov rax,QWORD PTR [rcx]"
)

-- Test 3: Base + 8-bit displacement
compare(
	function(asm)
		asm:mov("rax", {reg = "rdx", disp = 8, indirect = true})
	end,
	"mov rax,QWORD PTR [rdx+0x8]"
)

-- Test 4: Base + 32-bit displacement
compare(
	function(asm)
		asm:mov("rax", {reg = "rbx", disp = 1000, indirect = true})
	end,
	"mov rax,QWORD PTR [rbx+0x3e8]"
)

-- Test 5: SIB with scaled index
compare(
	function(asm)
		asm:mov("rax", {index = "rcx", scale = 4})
	end,
	"mov rax,QWORD PTR [rcx*4+0x0]"
)

-- Test 6: SIB with base + scaled index
compare(
	function(asm)
		asm:mov("rax", {base = "rbx", index = "rcx", scale = 4})
	end,
	"mov rax,QWORD PTR [rbx+rcx*4]"
)

-- Test 7: SIB with base + scaled index + 8-bit displacement
compare(
	function(asm)
		asm:mov("rax", {base = "rbx", index = "rcx", scale = 4, disp = 8})
	end,
	"mov rax,QWORD PTR [rbx+rcx*4+0x8]"
)

-- Test 8: SIB with base + scaled index + 32-bit displacement
compare(
	function(asm)
		asm:mov("rax", {base = "rbx", index = "rcx", scale = 4, disp = 1000})
	end,
	"mov rax,QWORD PTR [rbx+rcx*4+0x3e8]"
)

-- Test 9: RIP-relative
compare(
	function(asm)
		asm:mov("rax", {reg = "rip", rip = true, disp = 32})
	end,
	"mov rax,QWORD PTR [rip+0x20]"
)

-- Test 10: Special case - [rbp]
compare(
	function(asm)
		asm:mov("rax", {reg = "rbp", disp = 0, indirect = true})
	end,
	"mov rax,QWORD PTR [rbp+0x0]"
)

test("additional mov scenarios", function(asm)
	-- Test values using proper 64-bit literals
	local test_values = {
		0ULL, -- Zero
		42ULL, -- Small positive
		0xFFULL, -- One byte
		0xFFFFULL, -- Two bytes
		0xFFFFFFFFULL, -- Four bytes
		0x7FFFFFFFFFFFFFFFULL, -- Max signed 64-bit
		ffi.new("int64_t", -1), -- All bits set (signed)
		0x1234567890ABCDEFULL, -- Mixed bits
		0x0F0F0F0F0F0F0F0FULL, -- Pattern
		0xF0F0F0F0F0F0F0F0ULL, -- Inverse pattern
		0x8000000000000000ULL, -- Min signed value
		0xFFFFFFFFFFFFFFFFULL, -- Max unsigned value
	}

	-- Test immediate to register - only use caller-saved registers first
	for _, reg in ipairs(
		{
			"rax",
			"rcx",
			"rdx", -- Caller-saved
			"r8",
			"r9",
			"r10",
			"r11", -- Also caller-saved
		}
	) do
		for _, val in ipairs(test_values) do
			asm = Assembler()
			-- Move test value directly
			asm:mov(reg, val)

			-- Move to rax for return if not already there
			if reg ~= "rax" then asm:mov("rax", reg) end

			asm:ret()
			local fn = ffi.cast("uint64_t (*)(void)", asm:build())
			local result = fn()
			assert(
				result == val,
				string.format(
					"64-bit mov failed for %s with value 0x%x: got 0x%x, expected 0x%x",
					reg,
					val,
					result,
					val
				)
			)
		end
	end

	-- Test memory addressing modes with displacement
	-- Using more reasonable displacements that stay within our buffer
	local test_displacements = {
		0, -- No displacement
		8, -- Positive small
		-8, -- Negative small
		24, -- Positive medium, 3 elements forward
		-24, -- Negative medium, 3 elements back
		120, -- Positive below 127 (8-bit displacement)
		-120, -- Negative above -128 (8-bit displacement)
		240, -- Positive requiring 32-bit displacement
		-240, -- Negative requiring 32-bit displacement
	}
	-- Allocate enough space for our displacement tests (positive and negative offsets)
	-- Each uint64_t is 8 bytes, so we need enough for our max offset in either direction
	local buffer_size = 64 -- This gives us ±256 bytes of safe addressing space
	local mem = ffi.new("uint64_t[?]", buffer_size)
	-- Get the middle of our buffer for base pointer
	local middle_offset = (buffer_size / 2) * 8 -- Convert to bytes
	local test_val = 0x1234567890ABCDEFULL

	for _, disp in ipairs(test_displacements) do
		asm = Assembler()
		-- Set up base address in rcx (caller-saved), pointing to middle of buffer
		asm:mov("rcx", memory.object_to_address(mem) + middle_offset)
		-- Store test value
		asm:mov("rax", test_val)
		asm:mov({reg = "rcx", disp = disp, indirect = true}, "rax")
		-- Load and verify
		asm:mov("rax", {reg = "rcx", disp = disp, indirect = true})
		asm:ret()
		local fn = ffi.cast("uint64_t (*)(void)", asm:build())
		local result = fn()
		assert(
			result == test_val,
			string.format(
				"Memory addressing with displacement %d failed: got 0x%x, expected 0x%x",
				disp,
				result,
				test_val
			)
		)
	end

	-- Test SIB addressing with different scales
	local scales = {1, 2, 4, 8}

	for _, scale in ipairs(scales) do
		asm = Assembler()
		-- Set up base and index registers (using caller-saved)
		asm:mov("rcx", memory.object_to_address(mem))
		asm:mov("rdx", 1) -- Use rdx instead of r8 for index
		-- Store test value
		asm:mov("rax", test_val)
		-- Store rax to memory using SIB addressing
		asm:mov({base = "rcx", index = "rdx", scale = scale}, "rax")
		-- Load back using same addressing mode to verify
		asm:mov("rax", {base = "rcx", index = "rdx", scale = scale})
		asm:ret()
		local fn = ffi.cast("uint64_t (*)(void)", asm:build())
		local result = fn()
		assert(
			result == test_val,
			string.format(
				"SIB addressing with scale %d failed: got 0x%x, expected 0x%x",
				scale,
				result,
				test_val
			)
		)
	end
end)

-- Test invalid register combinations
local function expect_error(fn, error_msg)
	local ok, err = pcall(fn)

	if not ok and string.find(err, error_msg, 1, true) then

	else
		error(string.format("Expected error containing '%s', got: %s", error_msg, err), 3)
	end
end

local asm = Assembler()

-- Test invalid register names
expect_error(function()
	asm:mov("invalid_reg", "rax")
end, "is not a valid register")

-- Test invalid scale values
expect_error(
	function()
		asm:mov("rax", {index = "rcx", scale = 3})
	end,
	"Invalid scale value"
)

-- Test ESP/RSP as index register
expect_error(
	function()
		asm:mov("rax", {index = "rsp", scale = 4})
	end,
	"ESP/RSP cannot be used as an index register"
)

-- Test invalid RIP-relative addressing combinations
expect_error(
	function()
		asm:mov("rax", {reg = "rip", index = "rcx", rip = true})
	end,
	"RIP-relative addressing cannot use index"
)
