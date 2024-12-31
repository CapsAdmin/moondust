local Assembler = require("moondust")
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
		equal(code, asm:debug_disassemble(), 2)
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
	"rax",
	"rbx",
	"rcx",
	"rdx",
	"rsi",
	"rdi",
	"rsp",
	"rbp",
	"r8",
	"r9",
	"r10",
	"r11",
	"r12",
	"r13",
	"r14",
	"r15",
}

if false then
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
		asm:build("void (*)(void)")()
	end)
end

test("mov imm to reg", function()
	for _, reg in ipairs(regs_64) do
		for _, val in ipairs(test_values) do
			if reg ~= "rsp" and reg ~= "rbp" then
				local asm = Assembler()

				if reg ~= "rax" then asm:push(reg) end

				asm:mov(reg, val)

				if reg ~= "rax" then asm:mov("rax", reg) end

				if reg ~= "rax" then asm:pop(reg) end

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
				src_reg ~= "rsp" and
				src_reg ~= "rbp" and
				dst_reg ~= "rsp" and
				dst_reg ~= "rbp"
			then
				local asm = Assembler()
				local test_val = 0x1234567890ABCDEFLL

				if src_reg ~= "rax" then asm:push(src_reg) end

				if dst_reg ~= "rax" and dst_reg ~= src_reg then asm:push(dst_reg) end

				asm:mov(src_reg, test_val)
				asm:mov(dst_reg, src_reg)

				if dst_reg ~= "rax" then asm:mov("rax", dst_reg) end

				if dst_reg ~= "rax" and dst_reg ~= src_reg then asm:pop(dst_reg) end

				if src_reg ~= "rax" then asm:pop(src_reg) end

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
		asm:mov("rax", val)
		asm:mov_reg_to_pointer("rax", memory.object_to_address(mem))
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
		asm:mov_pointer_to_reg("rax", memory.object_to_address(mem))
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
		asm:push("rbx")
		asm:mov("rbx", val)
		asm:mov_reg_to_pointer("rbx", memory.object_to_address(mem))
		asm:mov_pointer_to_reg("rax", memory.object_to_address(mem))
		asm:pop("rbx")
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

	asm:push("rax")
	asm:mov("rax", memory.object_to_address(source))
	asm:vmovups_load("ymm0", "rax")
	asm:mov("rax", memory.object_to_address(result))
	asm:vmovups_store("rax", "ymm0")
	asm:pop("rax")
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

	asm:push("rax")
	asm:mov("rax", memory.object_to_address(source.data))
	asm:vmovups_load("ymm0", "rax")
	asm:mov("rax", memory.object_to_address(result.data))
	asm:vmovaps_store("rax", "ymm0")
	asm:pop("rax")
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

	asm:push("rax")
	asm:mov("rax", memory.object_to_address(source.data))
	asm:movaps_load("xmm0", "rax")
	asm:movaps("xmm1", "xmm0")
	asm:mov("rax", memory.object_to_address(result.data))
	asm:movaps_store("rax", "xmm1")
	asm:pop("rax")
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

cmp():mov("rbx", "rax"):with("mov rbx,rax")
cmp():mov("rax", {reg = "rcx", indirect = true}):with("mov rax,QWORD PTR [rcx]")
cmp():mov("rax", {reg = "rdx", disp = 8, indirect = true}):with("mov rax,QWORD PTR [rdx+0x8]")
cmp():mov("rax", {reg = "rbx", disp = 1000, indirect = true}):with("mov rax,QWORD PTR [rbx+0x3e8]")
cmp():mov("rax", {index = "rcx", scale = 4}):with("mov rax,QWORD PTR [rcx*4+0x0]")
cmp():mov("rax", {base = "rbx", index = "rcx", scale = 4}):with("mov rax,QWORD PTR [rbx+rcx*4]")
cmp():mov("rax", {base = "rbx", index = "rcx", scale = 4, disp = 8}):with("mov rax,QWORD PTR [rbx+rcx*4+0x8]")
cmp():mov("rax", {base = "rbx", index = "rcx", scale = 4, disp = 1000}):with("mov rax,QWORD PTR [rbx+rcx*4+0x3e8]")
cmp():mov("rax", {reg = "rip", rip = true, disp = 32}):with("mov rax,QWORD PTR [rip+0x20]")
cmp():mov("rax", {reg = "rbp", disp = 0, indirect = true}):with("mov rax,QWORD PTR [rbp+0x0]")

do
	cmp():mov("r12", "rdi"):with("mov r12,rdi")
	cmp():mov("r12", {disp = 0x1, indirect = true}):with("mov r12,QWORD PTR ds:0x1")
	cmp():mov("rcx", "rbx"):with("mov rcx,rbx")
	cmp():mov("rcx", {disp = 0x1, indirect = true}):with("mov rcx,QWORD PTR ds:0x1")
	cmp():mov("rcx", {disp = 0xdead, indirect = true}):with("mov rcx,QWORD PTR ds:0xdead")
	cmp():mov("rcx", {reg = "rbx", indirect = true}):with("mov rcx,QWORD PTR [rbx]")
	cmp():mov({reg = "rcx", indirect = true}, "rbx"):with("mov QWORD PTR [rcx],rbx")

	if false then
		cmp():mov("rcx", {reg = "rbx", scale = 1, indirect = true}):with("mov rcx,QWORD PTR [rbx*1]")
		cmp():mov("rcx", {reg = "rbx", scale = 2, indirect = true}):with("mov rcx,QWORD PTR [rbx*2]")
		cmp():mov("rcx", {reg = "rbx", scale = 4, indirect = true}):with("mov rcx,QWORD PTR [rbx*4]")
		cmp():mov("rcx", {reg = "rbx", scale = 8, indirect = true}):with("mov rcx,QWORD PTR [rbx*8]")
		cmp():mov("rcx", {reg = "rbx", scale = 1, disp = 0xdead, indirect = true}):with("mov rcx,QWORD PTR [rbx*1+0xdead]")
		cmp():mov("rcx", {reg = "rbx", scale = 2, disp = 0xdead, indirect = true}):with("mov rcx,QWORD PTR [rbx*2+0xdead]")
		cmp():mov("rcx", {reg = "rbx", scale = 4, disp = 0xdead, indirect = true}):with("mov rcx,QWORD PTR [rbx*4+0xdead]")
		cmp():mov("rcx", {reg = "rbx", scale = 8, disp = 0xdead, indirect = true}):with("mov rcx,QWORD PTR [rbx*8+0xdead]")
		cmp():mov("rcx", {base = "rdx", index = "rbx", scale = 1, disp = 0xdead}):with("mov rcx,QWORD PTR [rdx+rbx*1+0xdead]")
		cmp():mov("rcx", {base = "rdx", index = "rbx", scale = 2, disp = 0xdead}):with("mov rcx,QWORD PTR [rdx+rbx*2+0xdead]")
		cmp():mov("rcx", {base = "rdx", index = "rbx", scale = 4, disp = 0xdead}):with("mov rcx,QWORD PTR [rdx+rbx*4+0xdead]")
		cmp():mov("rcx", {base = "rdx", index = "rbx", scale = 8, disp = 0xdead}):with("mov rcx,QWORD PTR [rdx+rbx*8+0xdead]")
		cmp():mov({reg = "rbx", scale = 1, indirect = true}, "rcx"):with("mov QWORD PTR [rbx*1],rcx")
		cmp():mov({reg = "rbx", scale = 2, indirect = true}, "rcx"):with("mov QWORD PTR [rbx*2],rcx")
		cmp():mov({reg = "rbx", scale = 2, disp = 0xdead, indirect = true}, "rcx"):with("mov QWORD PTR [rbx*2+0xdead],rcx")
		cmp():mov({reg = "rbx", scale = 1, disp = 1024, indirect = true}, "rcx"):with("mov QWORD PTR [rbx*1+0x400],rcx")
		cmp():mov("xmm1", "xmm0"):with("movsd xmm1,xmm0")
		cmp():mov("rbp", nil):with("push rbp")
		cmp():mov("rbp", "rsp"):with("mov rbp,rsp")
		cmp():mov("rax", {disp = 1337222223, lea = true}):with("lea rax,[1337222223]")
		cmp():mov("rax", nil):with("call rax")
		cmp():mov("rdi", {reg = "rip", disp = 0xf * 2, lea = true}):with("lea rdi,[rip+0x1e]")
		cmp():mov("rdi", {reg = "rip", disp = 0xf, lea = true}):with("lea rdi,[rip+0xf]")
		cmp():mov("rdi", {reg = "rip", lea = true}):with("lea rdi,[rip]")
		cmp():mov({reg = "rbp", disp = 0, indirect = true}, "ebx"):with("mov DWORD PTR [rbp],ebx")
		cmp():mov({reg = "rbp", disp = 1, indirect = true}, "ebx"):with("mov DWORD PTR [rbp+0x1],ebx")
		cmp():mov({reg = "rbp", disp = 123123, indirect = true}, "ebx"):with("mov DWORD PTR [rbp+0x1e0f3],ebx")
		cmp():mov({reg = "rbp", indirect = true}, "ecx"):with("mov DWORD PTR [rbp],ecx")
		cmp():mov({reg = "rbp", disp = 0, indirect = true}, "ebx"):with("mov DWORD PTR [rbp+0x0],ebx")
	end
end

test("additional mov scenarios", function(asm)
	for _, reg in ipairs({
		"rax",
		"rcx",
		"rdx",
		"r8",
		"r9",
		"r10",
		"r11",
	}) do
		for _, val in ipairs(test_values) do
			asm = Assembler()
			asm:mov(reg, val)

			if reg ~= "rax" then asm:mov("rax", reg) end

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
		asm:mov("rcx", memory.object_to_address(mem) + middle_offset)
		asm:mov("rax", test_val)
		asm:mov({reg = "rcx", disp = disp, indirect = true}, "rax")
		asm:mov("rax", {reg = "rcx", disp = disp, indirect = true})
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
		asm:mov("rcx", memory.object_to_address(mem))
		asm:mov("rdx", 1)
		asm:mov("rax", test_val)
		asm:mov({base = "rcx", index = "rdx", scale = scale}, "rax")
		asm:mov("rax", {base = "rcx", index = "rdx", scale = scale})
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
	asm:xor("rax", "rax")
	asm:jmp("skip")
	asm:mov("rax", 1)
	asm:label("skip")
	asm:ret()
	local result = asm:build("uint64_t (*)(void)")()
	assert(result == 0, string.format("Forward jump failed: expected 0, got %d", result))
end)

test("conditional jumps", function(asm)
	asm:mov("rax", 5)
	asm:cmp("rax", 5)
	asm:jne("not_equal")
	asm:mov("rax", 1)
	asm:jmp("end")
	asm:label("not_equal")
	asm:mov("rax", 0)
	asm:label("end")
	asm:ret()
	local result = asm:build("uint64_t (*)(void)")()
	assert(result == 1, "JE/JNE test failed")
end)

test("multiple jumps", function(asm)
	asm:mov("rax", 0)
	asm:jmp("middle")
	asm:mov("rax", 1)
	asm:jmp("end")
	asm:label("middle")
	asm:mov("rax", 2)
	asm:jmp("end")
	asm:label("end")
	asm:ret()
	local result = asm:build("uint64_t (*)(void)")()
	assert(result == 2, "Multiple jumps test failed")
end)

test("loop with conditional", function(asm)
	asm:mov("rax", 0)
	asm:mov("rcx", 5)
	asm:label("loop")
	asm:inc("rax")
	asm:dec("rcx")
	asm:cmp("rcx", 0)
	asm:jg("loop")
	asm:ret()
	local result = asm:build("uint64_t (*)(void)")()
	assert(result == 5, "Loop test failed")
end)

test("forward and backward jumps", function(asm)
	asm:mov("rax", 0)
	asm:mov("rcx", 3)
	asm:jmp("start")
	asm:label("loop")
	asm:inc("rax")
	asm:dec("rcx")
	asm:label("start")
	asm:cmp("rcx", 0)
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

expect_error(
	function()
		asm:mov("invalid_reg", "rax")
	end,
	"first argument must be a register"
)

expect_error(
	function()
		asm:mov("rax", {index = "rcx", scale = 3})
	end,
	"is not a valid register combination"
)
