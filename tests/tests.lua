local Assembler = require("moondust")
local R = Assembler.Registers
local memory = require("moondust.memory")
local ffi = require("ffi")

local function expect_error(fn, error_msg)
	local ok, err = pcall(fn)

	if not ok and string.find(err, error_msg, 1, true) then

	else
		error(string.format("Expected error containing '%s', got: %s", error_msg, err), 3)
	end
end

local function equal(a, b, level)
	if a ~= b then
		error("expected " .. tostring(a) .. " got " .. tostring(b), level or 2)
	end
end

local function cmp()
	local asm = Assembler()
	local tbl = {}

	function tbl.__index(_, key)
		local func = asm[key]
		return function(_, ...)
			func(asm, ...)
			return tbl
		end
	end

	function tbl:with(code)
		local a = code
		local b = asm:debug_disassemble()

		if a ~= b then
			error(
				"expected " .. tostring(a) .. " got: \n==asm==\n" .. tostring(b) .. "\n==asm==\n" .. "\n==hex==\n" .. tostring(asm:debug_hex()) .. "\n==hex==\n",
				level or 2
			)
		end
	end

	setmetatable(tbl, tbl)
	return tbl
end

local function test(test_name, test_function)
	io.write("test " .. test_name)
	io.flush()
	local asm = Assembler()
	local ok, err = xpcall(test_function, debug.traceback, asm)

	if ok then
		io.write(" - OK\n")
		io.flush()
	else
		io.write("fail\n\n")
		print("source:")
		print("===")
		print(asm:debug_disassemble())
		print("===")
		io.flush()
		error(err, 2)
	end
end

local test_values = {
	0ULL,
	42ULL,
	0xFFULL,
	0xFFFFULL,
	0xFFFFFFFFULL,
	0x7FFFFFFFFFFFFFFFLL,
	-1LL,
	0x1234567890ABCDEFULL,
	0x0F0F0F0F0F0F0F0FULL,
	0xF0F0F0F0F0F0F0F0ULL,
	0x8000000000000000ULL,
	0xFFFFFFFFFFFFFFFFULL,
}
local regs_64 = {
	R.rax,
	R.rbx,
	R.rcx,
	R.rdx,
	R.rsi,
	R.rdi,
	R.rsp,
	R.rbp,
	R.r8,
	R.r9,
	R.r10,
	R.r11,
	R.r12,
	R.r13,
	R.r14,
	R.r15,
}

if false then
	test("write std out", function(asm)
		local msg = "hello world\n"
		local STDOUT_FILENO = 1
		local WRITE = jit.os == "Linux" and 1 or 0x2000004
		asm:mov(R.rax, WRITE)
		asm:mov(R.rdi, STDOUT_FILENO)
		asm:mov(R.rsi, memory.object_to_address(msg))
		asm:mov(R.rdx, #msg)
		asm:syscall()
		asm:ret()
		asm:build("void (*)(void)")()
	end)
end

test("mov imm to reg", function()
	for _, reg in ipairs(regs_64) do
		for _, val in ipairs(test_values) do
			if reg.reg ~= "rsp" and reg.reg ~= "rbp" then
				local asm = Assembler()

				if reg.reg ~= "rax" then asm:push(reg) end

				asm:mov(reg, val)

				if reg.reg ~= "rax" then asm:mov(R.rax, reg) end

				if reg.reg ~= "rax" then asm:pop(reg) end

				asm:ret()
				local result = asm:build("uint64_t (*)(void)")()

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
end)

test("mov reg to reg", function()
	for _, src_reg in ipairs(regs_64) do
		for _, dst_reg in ipairs(regs_64) do
			if
				src_reg.reg ~= "rsp" and
				src_reg.reg ~= "rbp" and
				dst_reg.reg ~= "rsp" and
				dst_reg.reg ~= "rbp"
			then
				local asm = Assembler()
				local test_val = 0x1234567890ABCDEFLL

				if src_reg.reg ~= "rax" then asm:push(src_reg) end

				if dst_reg.reg ~= "rax" and dst_reg ~= src_reg then asm:push(dst_reg) end

				asm:mov(src_reg, test_val)
				asm:mov(dst_reg, src_reg)

				if dst_reg.reg ~= "rax" then asm:mov(R.rax, dst_reg) end

				if dst_reg.reg ~= "rax" and dst_reg ~= src_reg then asm:pop(dst_reg) end

				if src_reg.reg ~= "rax" then asm:pop(src_reg) end

				asm:ret()
				local result = asm:build("uint64_t (*)(void)")()

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
end)

test("mov reg to pointer", function()
	for _, val in ipairs(test_values) do
		local mem = ffi.new("uint64_t[1]")
		local asm = Assembler()
		asm:mov(R.rax, val)
		asm:mov_reg_to_pointer(R.rax, memory.object_to_address(mem))
		asm:ret()
		asm:build("void (*)(void)")()

		if mem[0] ~= val then
			error(string.format("Memory store failed - Expected 0x%x, got 0x%x", val, memory[0]))
		end
	end
end)

test("mov pointer to reg", function()
	for _, val in ipairs(test_values) do
		local mem = ffi.new("uint64_t[1]")
		mem[0] = val
		local asm = Assembler()
		asm:mov_pointer_to_reg(R.rax, memory.object_to_address(mem))
		asm:ret()
		local result = asm:build("uint64_t (*)(void)")()

		if result ~= val then
			error(string.format("Memory load failed - Expected 0x%x, got 0x%x", val, result))
		end
	end
end)

test("mov reg pointer roundtrip", function()
	for _, val in ipairs(test_values) do
		local mem = ffi.new("uint64_t[1]")
		local asm = Assembler()
		asm:push(R.rbx)
		asm:mov(R.rbx, val)
		asm:mov_reg_to_pointer(R.rbx, memory.object_to_address(mem))
		asm:mov_pointer_to_reg(R.rax, memory.object_to_address(mem))
		asm:pop(R.rbx)
		asm:ret()
		local result = asm:build("uint64_t (*)(void)")()

		if result ~= val then
			error(string.format("Memory round trip failed - Expected 0x%x, got 0x%x", val, result))
		end
	end
end)

test("avx unaligned store", function(asm)
	local source = ffi.new("float[8]")
	local result = ffi.new("float[8]")

	for i = 0, 7 do
		source[i] = i + 1.0
		result[i] = 0.0
	end

	asm:push(R.rax)
	asm:mov(R.rax, memory.object_to_address(source))
	asm:vmovups_load(R.ymm0, R.rax)
	asm:mov(R.rax, memory.object_to_address(result))
	asm:vmovups_store(R.rax, R.ymm0)
	asm:pop(R.rax)
	asm:ret()
	asm:build("void (*)(void)")()

	for i = 0, 7 do
		local expected = source[i]
		local got = result[i]
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
	local AlignedAVXArray = ffi.typeof[[struct { 
		float data[8] __attribute__((aligned(32))); 
	}]]
	local source = AlignedAVXArray()
	local result = AlignedAVXArray()

	for i = 0, 7 do
		source.data[i] = i + 1.0
		result.data[i] = 0.0
	end

	asm:push(R.rax)
	asm:mov(R.rax, memory.object_to_address(source.data))
	asm:vmovups_load(R.ymm0, R.rax)
	asm:mov(R.rax, memory.object_to_address(result.data))
	asm:vmovaps_store(R.rax, R.ymm0)
	asm:pop(R.rax)
	asm:ret()
	asm:build("void (*)(void)")()

	for i = 0, 7 do
		local expected = source.data[i]
		local got = result.data[i]
		assert(
			math.abs(got - expected) < 0.0001,
			string.format("AVX store test failed at index %d: expected %f, got %f", i, expected, got)
		)
	end
end)

test("sse store", function(asm)
	ffi.cdef[[
			typedef struct { float data[4] __attribute__((aligned(16))); } AlignedFloatArray;
		]]
	local source = ffi.new("AlignedFloatArray")
	local result = ffi.new("AlignedFloatArray")
	source.data[0] = 1.0
	source.data[1] = 2.0
	source.data[2] = 3.0
	source.data[3] = 4.0

	for i = 0, 3 do
		result.data[i] = 0.0
	end

	asm:push(R.rax)
	asm:mov(R.rax, memory.object_to_address(source.data))
	asm:movaps_load(R.xmm0, R.rax)
	asm:movaps(R.xmm1, R.xmm0)
	asm:mov(R.rax, memory.object_to_address(result.data))
	asm:movaps_store(R.rax, R.xmm1)
	asm:pop(R.rax)
	asm:ret()
	asm:build("void (*)(void)")()

	for i = 0, 3 do
		local expected = source.data[i]
		local got = result.data[i]
		assert(
			math.abs(got - expected) < 0.0001,
			string.format("SSE test failed at index %d: expected %f, got %f", i, expected, got)
		)
	end
end)

cmp():mov(R.rbx, R.rax):with("mov rbx,rax")
cmp():mov(R.rax, R({reg = "rcx", indirect = true})):with("mov rax,QWORD PTR [rcx]")
cmp():mov(R.rax, R({reg = "rdx", disp = 8, indirect = true})):with("mov rax,QWORD PTR [rdx+0x8]")
cmp():mov(R.rax, R({reg = "rbx", disp = 1000, indirect = true})):with("mov rax,QWORD PTR [rbx+0x3e8]")
cmp():mov(R.rax, R({index = "rcx", scale = 4})):with("mov rax,QWORD PTR [rcx*4+0x0]")
cmp():mov(R.rax, R({base = "rbx", index = "rcx", scale = 4})):with("mov rax,QWORD PTR [rbx+rcx*4]")
cmp():mov(R.rax, R({base = "rbx", index = "rcx", scale = 4, disp = 8})):with("mov rax,QWORD PTR [rbx+rcx*4+0x8]")
cmp():mov(R.rax, R({base = "rbx", index = "rcx", scale = 4, disp = 1000})):with("mov rax,QWORD PTR [rbx+rcx*4+0x3e8]")
cmp():mov(R.rax, R({reg = "rip", rip = true, disp = 32})):with("mov rax,QWORD PTR [rip+0x20]")
cmp():mov(R.rax, R({reg = "rbp", disp = 0, indirect = true})):with("mov rax,QWORD PTR [rbp+0x0]")
cmp():mov(R.r12, R.rdi):with("mov r12,rdi")
cmp():mov(R.r12, R({disp = 0x1, indirect = true})):with("mov r12,QWORD PTR ds:0x1")
cmp():mov(R.rcx, R.rbx):with("mov rcx,rbx")
cmp():mov(R.rcx, R({disp = 0x1, indirect = true})):with("mov rcx,QWORD PTR ds:0x1")
cmp():mov(R.rcx, R({disp = 0xdead, indirect = true})):with("mov rcx,QWORD PTR ds:0xdead")
cmp():mov(R.rcx, R({reg = "rbx", indirect = true})):with("mov rcx,QWORD PTR [rbx]")
cmp():mov(R({reg = "rcx", indirect = true}), R.rbx):with("mov QWORD PTR [rcx],rbx")
cmp():mov(R.rcx, R({index = "rbx", scale = 1, indirect = true})):with("mov rcx,QWORD PTR [rbx*1+0x0]")
cmp():mov(R.rcx, R({index = "rbx", scale = 2, indirect = true})):with("mov rcx,QWORD PTR [rbx*2+0x0]")
cmp():mov(R.rcx, R({index = "rbx", scale = 4, indirect = true})):with("mov rcx,QWORD PTR [rbx*4+0x0]")
cmp():mov(R.rcx, R({index = "rbx", scale = 8, indirect = true})):with("mov rcx,QWORD PTR [rbx*8+0x0]")
cmp():mov(R.rcx, R({index = "rbx", scale = 1, disp = 0xdead, indirect = true})):with("mov rcx,QWORD PTR [rbx*1+0xdead]")
cmp():mov(R.rcx, R({index = "rbx", scale = 2, disp = 0xdead, indirect = true})):with("mov rcx,QWORD PTR [rbx*2+0xdead]")
cmp():mov(R.rcx, R({index = "rbx", scale = 4, disp = 0xdead, indirect = true})):with("mov rcx,QWORD PTR [rbx*4+0xdead]")
cmp():mov(R.rcx, R({index = "rbx", scale = 8, disp = 0xdead, indirect = true})):with("mov rcx,QWORD PTR [rbx*8+0xdead]")
cmp():mov(R.rcx, R({base = "rdx", index = "rbx", scale = 1, disp = 0xdead})):with("mov rcx,QWORD PTR [rdx+rbx*1+0xdead]")
cmp():mov(R.rcx, R({base = "rdx", index = "rbx", scale = 2, disp = 0xdead})):with("mov rcx,QWORD PTR [rdx+rbx*2+0xdead]")
cmp():mov(R.rcx, R({base = "rdx", index = "rbx", scale = 4, disp = 0xdead})):with("mov rcx,QWORD PTR [rdx+rbx*4+0xdead]")
cmp():mov(R.rcx, R({base = "rdx", index = "rbx", scale = 8, disp = 0xdead})):with("mov rcx,QWORD PTR [rdx+rbx*8+0xdead]")
cmp():mov(R({index = "rbx", scale = 1, indirect = true}), R.rcx):with("mov QWORD PTR [rbx*1+0x0],rcx")
cmp():mov(R({index = "rbx", scale = 2, indirect = true}), R.rcx):with("mov QWORD PTR [rbx*2+0x0],rcx")
cmp():mov(R({index = "rbx", scale = 2, disp = 0xdead, indirect = true}), R.rcx):with("mov QWORD PTR [rbx*2+0xdead],rcx")
cmp():mov(R({index = "rbx", scale = 1, disp = 1024, indirect = true}), R.rcx):with("mov QWORD PTR [rbx*1+0x400],rcx")
cmp():mov(R.rbp, R.rsp):with("mov rbp,rsp")

test("additional mov scenarios", function(asm)
	for _, reg in ipairs({
		R.rax,
		R.rcx,
		R.rdx,
		R.r8,
		R.r9,
		R.r10,
		R.r11,
	}) do
		for _, val in ipairs(test_values) do
			local asm = Assembler()
			asm:mov(reg, val)

			if reg.reg ~= "rax" then asm:mov(R.rax, reg) end

			asm:ret()
			local result = asm:build("uint64_t (*)(void)")()
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

	local test_displacements = {
		0,
		8,
		-8,
		24,
		-24,
		120,
		-120,
		240,
		-240,
	}
	local buffer_size = 64
	local mem = ffi.new("uint64_t[?]", buffer_size)
	local middle_offset = (buffer_size / 2) * 8
	local test_val = 0x1234567890ABCDEFULL

	for _, disp in ipairs(test_displacements) do
		asm = Assembler()
		asm:mov(R.rcx, memory.object_to_address(mem) + middle_offset)
		asm:mov(R.rax, test_val)
		asm:mov(R({reg = "rcx", disp = disp, indirect = true}), R.rax)
		asm:mov(R.rax, R({reg = "rcx", disp = disp, indirect = true}))
		asm:ret()
		local result = asm:build("uint64_t (*)(void)")()
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

	local scales = {1, 2, 4, 8}

	for _, scale in ipairs(scales) do
		asm = Assembler()
		asm:mov(R.rcx, memory.object_to_address(mem))
		asm:mov(R.rdx, 1)
		asm:mov(R.rax, test_val)
		asm:mov(R({base = "rcx", index = "rdx", scale = scale}), R.rax)
		asm:mov(R.rax, R({base = "rcx", index = "rdx", scale = scale}))
		asm:ret()
		local result = asm:build("uint64_t (*)(void)")()
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

test("basic forward jump", function(asm)
	asm:xor(R.rax, R.rax)
	asm:jmp("skip")
	asm:mov(R.rax, 1)
	asm:label("skip")
	asm:ret()
	local result = asm:build("uint64_t (*)(void)")()
	assert(result == 0, string.format("Forward jump failed: expected 0, got %d", result))
end)

test("conditional jumps", function(asm)
	asm:mov(R.rax, 5)
	asm:cmp(R.rax, 5)
	asm:jne("not_equal")
	asm:mov(R.rax, 1)
	asm:jmp("end")
	asm:label("not_equal")
	asm:mov(R.rax, 0)
	asm:label("end")
	asm:ret()
	local result = asm:build("uint64_t (*)(void)")()
	assert(result == 1, "JE/JNE test failed")
end)

test("multiple jumps", function(asm)
	asm:mov(R.rax, 0)
	asm:jmp("middle")
	asm:mov(R.rax, 1)
	asm:jmp("end")
	asm:label("middle")
	asm:mov(R.rax, 2)
	asm:jmp("end")
	asm:label("end")
	asm:ret()
	local result = asm:build("uint64_t (*)(void)")()
	assert(result == 2, "Multiple jumps test failed")
end)

test("loop with conditional", function(asm)
	asm:mov(R.rax, 0)
	asm:mov(R.rcx, 5)
	asm:label("loop")
	asm:inc(R.rax)
	asm:dec(R.rcx)
	asm:cmp(R.rcx, 0)
	asm:jg("loop")
	asm:ret()
	local result = asm:build("uint64_t (*)(void)")()
	assert(result == 5, "Loop test failed")
end)

test("forward and backward jumps", function(asm)
	asm:mov(R.rax, 0)
	asm:mov(R.rcx, 3)
	asm:jmp("start")
	asm:label("loop")
	asm:inc(R.rax)
	asm:dec(R.rcx)
	asm:label("start")
	asm:cmp(R.rcx, 0)
	asm:jg("loop")
	asm:ret()
	local result = asm:build("uint64_t (*)(void)")()
	assert(result == 3, "Forward/backward jump test failed")
end)

test("error cases", function(asm)
	local function test_undefined()
		local asm = Assembler()
		asm:jmp("undefined")
		asm:ret()
		return asm:build()
	end

	local success = pcall(test_undefined)
	assert(not success, "Should fail on undefined label")

	local function test_duplicate()
		local asm = Assembler()
		asm:label("same")
		asm:label("same")
		return asm:build()
	end

	local success = pcall(test_duplicate)
	assert(not success, "Should fail on duplicate label")
end)

local asm = Assembler()

expect_error(function()
	asm:mov(R.invalid_reg, R.rax)
end, "Invalid register")

expect_error(
	function()
		asm:mov(R.rax, R({index = "rcx", scale = 3}))
	end,
	"Invalid scale value"
)
