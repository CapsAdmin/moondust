collectgarbage("stop")
local Assembler = require("moondust")
local R = Assembler.Registers
local memory = require("moondust.memory")
local ffi = require("ffi")

local function u64(n)
	local mem = memory.malloc("uint64_t*", ffi.sizeof("uint64_t"))
	mem[0] = n
	return mem
end

local function expect_error(fn, error_msg)
	local ok, err = pcall(fn)

	if not ok and string.find(err, error_msg, 1, true) then

	else
		error(string.format("Expected error containing '%s', got: %s", error_msg, err), 3)
	end
end

local function equal(a, b, level)
	if a ~= b then
		error("expected " .. tostring(b) .. " got " .. tostring(a), level or 2)
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

test("raw instructions", function()
	-- Test helper to compare byte arrays
	local function compare_bytes(expected, actual)
		assert(
			#expected == #actual,
			string.format("Expected %d bytes but got %d", #expected, #actual)
		)

		for i = 1, #expected do
			assert(
				expected[i] == string.byte(actual[i]),
				string.format(
					"Byte mismatch at position %d: expected 0x%02x, got 0x%02x",
					i,
					expected[i],
					string.byte(actual[i])
				)
			)
		end
	end

	local function cmp(tbl, ...)
		local asm = Assembler()
		asm:emit_instruction(tbl)
		compare_bytes({...}, asm.code)
	end

	-- Basic instruction tests
	cmp({opcode = {0x90}}, 0x90) -- NOP
	-- ModR/M direct register-to-register tests
	cmp(
		{
			opcode = {0x89}, -- MOV r/m64, r64
			modrm = {
				mode = "direct",
				reg = 0, -- EAX
				rm = 1, -- ECX
			},
		},
		0x89,
		0xC1
	)
	-- ModR/M with 8-bit displacement
	cmp(
		{
			opcode = {0x89}, -- MOV m64, r64
			modrm = {
				mode = "indirect8",
				reg = 0, -- EAX
				rm = 1, -- [RCX + disp8]
			},
			disp = 0x42,
		},
		0x89,
		0x41,
		0x42
	)
	-- ModR/M with 32-bit displacement
	cmp(
		{
			opcode = {0x89}, -- MOV m64, r64
			modrm = {
				mode = "indirect32",
				reg = 0,
				rm = 1,
			},
			disp = 0x12345678,
		},
		0x89,
		0x81,
		0x78,
		0x56,
		0x34,
		0x12
	)
	-- SIB testing
	cmp(
		{
			opcode = {0x89}, -- MOV m64, r64
			modrm = {
				mode = "indirect",
				reg = 0,
				rm = 4, -- Indicates SIB follows
			},
			sib = {
				scale = 4,
				index = 2, -- RDX
				base = 1, -- RCX
			},
		},
		0x89,
		0x04,
		0x91
	)
	-- REX prefix tests
	cmp(
		{
			prefix = {"rex_w"}, -- 64-bit operand size
			opcode = {0x89},
			modrm = {mode = "direct", reg = 0, rm = 1},
		},
		0x48,
		0x89,
		0xC1
	)
	-- Legacy prefix tests
	cmp(
		{
			prefix = {"lock"}, -- LOCK prefix
			opcode = {0x89},
			modrm = {mode = "direct", reg = 0, rm = 1},
		},
		0xF0,
		0x89,
		0xC1
	)
	-- Multiple prefix test
	cmp(
		{
			prefix = {"lock", "rex_w"},
			opcode = {0x89},
			modrm = {mode = "direct", reg = 0, rm = 1},
		},
		0xF0,
		0x48,
		0x89,
		0xC1
	)
	-- Segment override prefix test
	cmp(
		{
			prefix = {"fs_segment_override"},
			opcode = {0x89},
			modrm = {mode = "direct", reg = 0, rm = 1},
		},
		0x64,
		0x89,
		0xC1
	)
	-- Complex SIB with displacement
	cmp(
		{
			prefix = {"rex_w"},
			opcode = {0x89},
			modrm = {
				mode = "indirect8",
				reg = 0,
				rm = 4,
			},
			sib = {
				scale = 8,
				index = 3, -- RBX
				base = 5, -- RBP
			},
			disp = 127,
		},
		0x48,
		0x89,
		0x44,
		0xDD,
		127
	)
	-- Test displacement bounds
	-- Maximum 8-bit signed displacement
	cmp(
		{
			opcode = {0x89},
			modrm = {
				mode = "indirect8",
				reg = 0,
				rm = 1,
			},
			disp = 127,
		},
		0x89,
		0x41,
		127
	)
	cmp(
		{
			prefix = {
				"rex_w",
				"lock",
				"cs_segment_override",
				"operand_size_override",
				"address_size_override",
			},
			opcode = {0x81},
			modrm = {
				mode = "indirect32",
				reg = 1,
				rm = 1,
			},
			sib = {
				scale = 2,
				index = 0,
				base = 0,
			},
			disp = 0,
		},
		0xf0, -- lock
		0x2E, -- cs_segment_override
		0x66, -- operand_size_override
		0x67, -- address_size_override
		0x48, -- rex_w
		0x81, -- opcode
		0x89, -- modrm
		0x40, -- sib
		0x00,
		0x00,
		0x00,
		0x00
	)

	-- Test error cases
	-- Invalid ModR/M mode
	local function assert_error(f, err_msg)
		local success, error = pcall(f)
		assert(
			not success and string.find(error, err_msg, 1, true),
			string.format("Expected error containing '%s', got '%s'", err_msg, error)
		)
	end

	assert_error(
		function()
			cmp(
				{
					opcode = {0x89},
					modrm = {
						mode = "invalid_mode",
						reg = 0,
						rm = 1,
					},
				}
			)
		end,
		"invalid ModR/M mode"
	)

	-- Invalid displacement range
	assert_error(
		function()
			cmp(
				{
					opcode = {0x89},
					modrm = {
						mode = "indirect8",
						reg = 0,
						rm = 1,
					},
					disp = 128, -- Out of range for 8-bit signed
				}
			)
		end,
		"8-bit number must be between -128 and 127"
	)

	-- Test prefix conflicts
	assert_error(
		function()
			cmp(
				{
					prefix = {"lock", "repne"},
					opcode = {0x89},
					modrm = {mode = "direct", reg = 0, rm = 1},
				}
			)
		end,
		"cannot coexist with"
	)
end)

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

do
	equal(tostring(R.rax), "rax")
	equal(tostring(R.rax:memory_address()), "[rax]")
	equal(tostring(R.rax * 1), "[rax*1]")
	equal(tostring(R.rax * 2), "[rax*2]")
	equal(tostring(R.rax * 4), "[rax*4]")
	equal(tostring(R.rax * 8), "[rax*8]")
	equal(tostring(R.rax + 0), "[rax + 0]")
	equal(tostring(R.rax - 1), "[rax - 1]")
	equal(tostring(R.rax + R.rbx), "[rax + rbx]")
	equal(tostring(R.rax + R.rbx * 4 + 0x1), "[rax + rbx*4 + 1]")
end

do
	do -- pure displacement / memory offset / moff
		do
			cmp():mov(R.rbx, R(0x123456789abcdef0ULL)):with("movabs rbx,0x123456789abcdef0\nmov rbx,QWORD PTR [rbx]")
			cmp():mov(R(0x123456789abcdef0ULL), R.rbx):with("push\nmovabs r11,0x123456789abcdef0\nmov QWORD PTR [r11],rbx\npop")
			cmp():mov(R.rax, R(0x123456789abcdef0ULL)):with("movabs rax,ds:0x123456789abcdef0")
			cmp():mov(R(0x123456789abcdef0ULL), R.rax):with("movabs ds:0x123456789abcdef0,rax")
		end

		cmp():mov(R.rcx, R(0xdead)):with("mov rcx,QWORD PTR ds:0xdead")
		cmp():mov(R.r12, R(1)):with("mov r12,QWORD PTR ds:0x1")
		cmp():mov(R.rax, R(1ull)):with("movabs rax,ds:0x1") -- rax can use 64 bit displacement
		cmp():mov(R(1ull), R.rax):with("movabs ds:0x1,rax") -- rax can use 64 bit displacement
		cmp():mov(R.r10, R(1ull)):with("movabs r10,0x1\nmov r10,QWORD PTR [r10]")
		cmp():mov(R(1ull), R.r12):with("push\nmovabs r11,0x1\nmov QWORD PTR [r11],r12\npop")
	end

	cmp():mov(R.rbx, R.rax):with("mov rbx,rax")
	cmp():mov(R.rax, R.rcx:memory_address()):with("mov rax,QWORD PTR [rcx]")
	cmp():mov(R.rax, R.rdx + 0x8):with("mov rax,QWORD PTR [rdx+0x8]")
	cmp():mov(R.rax, R.rbx + 1000):with("mov rax,QWORD PTR [rbx+0x3e8]")
	cmp():mov(R.rax, R.rcx * 4):with("mov rax,QWORD PTR [rcx*4+0x0]")
	cmp():mov(R.rax, R.rbx + R.rcx * 4):with("mov rax,QWORD PTR [rbx+rcx*4]")
	cmp():mov(R.rax, R.rbx + R.rcx * 4 + 8):with("mov rax,QWORD PTR [rbx+rcx*4+0x8]")
	cmp():mov(R.rax, R.rbx + R.rcx * 4 + 1000):with("mov rax,QWORD PTR [rbx+rcx*4+0x3e8]")
	cmp():mov(R.rax, R.rip + 32):with("mov rax,QWORD PTR [rip+0x20]")
	cmp():mov(R.r12, R.rdi):with("mov r12,rdi")
	cmp():mov(R.r12, R.r12:memory_address()):with("mov r12,QWORD PTR [r12]")
	cmp():mov(R.rcx, R.rbx):with("mov rcx,rbx")
	cmp():mov(R.rcx, R.rbx):with("mov rcx,rbx")
	cmp():mov(R.rcx, R.rbx * 1):with("mov rcx,QWORD PTR [rbx*1+0x0]")
	cmp():mov(R.rcx, R.rbx * 2):with("mov rcx,QWORD PTR [rbx*2+0x0]")
	cmp():mov(R.rcx, R.rbx * 4):with("mov rcx,QWORD PTR [rbx*4+0x0]")
	cmp():mov(R.rcx, R.rbx * 8):with("mov rcx,QWORD PTR [rbx*8+0x0]")
	cmp():mov(R.rcx, R.rbx * 1 + 0xdead):with("mov rcx,QWORD PTR [rbx*1+0xdead]")
	cmp():mov(R.rcx, R.rbx * 2 + 0xdead):with("mov rcx,QWORD PTR [rbx*2+0xdead]")
	cmp():mov(R.rcx, R.rbx * 4 + 0xdead):with("mov rcx,QWORD PTR [rbx*4+0xdead]")
	cmp():mov(R.rcx, R.rbx * 8 + 0xdead):with("mov rcx,QWORD PTR [rbx*8+0xdead]")
	cmp():mov(R.rcx, R.rdx + R.rbx * 1 + 0xdead):with("mov rcx,QWORD PTR [rdx+rbx*1+0xdead]")
	cmp():mov(R.rcx, R.rdx + R.rbx * 2 + 0xdead):with("mov rcx,QWORD PTR [rdx+rbx*2+0xdead]")
	cmp():mov(R.rcx, R.rdx + R.rbx * 4 + 0xdead):with("mov rcx,QWORD PTR [rdx+rbx*4+0xdead]")
	cmp():mov(R.rcx, R.rdx + R.rbx * 8 + 0xdead):with("mov rcx,QWORD PTR [rdx+rbx*8+0xdead]")
	cmp():mov(R(R.rbx * 1), R.rcx):with("mov QWORD PTR [rbx*1+0x0],rcx")
	cmp():mov(R(R.rbx * 2), R.rcx):with("mov QWORD PTR [rbx*2+0x0],rcx")
	cmp():mov(R(R.rbx * 2 + 0xdead), R.rcx):with("mov QWORD PTR [rbx*2+0xdead],rcx")
	cmp():mov(R(R.rbx * 1 + 1024), R.rcx):with("mov QWORD PTR [rbx*1+0x400],rcx")
	cmp():mov(R.rbp, R.rsp):with("mov rbp,rsp")
	cmp():mov(R.rax, R.rbp + 0):with("mov rax,QWORD PTR [rbp+0x0]")

	do
		cmp():mov(R.rbx, R.rax * 1):with("mov rbx,QWORD PTR [rax*1+0x0]")
		cmp():mov(R.rbx, R.rax * 2):with("mov rbx,QWORD PTR [rax*2+0x0]")
	end
end

do
	local cpuid = require("moondust.cpuid")

	test("cpuid", function(asm)
		print("")
		local cpu_info = cpuid()

		local function tprint(tbl, level)
			level = level or 0

			for k, v in pairs(tbl) do
				if type(v) == "table" then
					print(("\t"):rep(level) .. k .. ": ")
					tprint(v, level + 1)
				else
					print(("\t"):rep(level) .. k .. ": " .. tostring(v))
				end
			end
		end

		tprint(cpu_info)
	end)
end

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
		local mem = u64(0)
		local asm = Assembler()
		asm:mov(R.rax, val)
		asm:mov(R(memory.object_to_address(mem)), R.rax)
		asm:ret()
		asm:build("void (*)(void)")()

		if mem[0] ~= val then
			error(string.format("Memory store failed - Expected 0x%x, got 0x%x", val, memory[0]))
		end
	end
end)

test("mov pointer to reg", function()
	for _, val in ipairs(test_values) do
		local mem = u64(0)
		mem[0] = val
		local asm = Assembler()
		asm:mov(R.rax, R(memory.object_to_address(mem)))
		asm:ret()
		local result = asm:build("uint64_t (*)(void)")()

		if result ~= val then
			error(string.format("Memory load failed - Expected 0x%x, got 0x%x", val, result))
		end
	end
end)

test("mov reg pointer roundtrip", function()
	for _, val in ipairs(test_values) do
		local mem = u64(val)
		local asm = Assembler()
		asm:mov(R.rax, R(memory.object_to_address(mem)))
		asm:mov(R(memory.object_to_address(mem)), R.rax)
		asm:mov(R.rax, R(memory.object_to_address(mem)))
		asm:ret()
		local result = asm:build("uint64_t (*)(void)")()

		if result ~= val then
			print(asm:debug_disassemble())
			print(asm:debug_hex())
			error(string.format("Memory round trip failed - Expected 0x%x, got 0x%x", val, result))
		end
	end

	for _, val in ipairs(test_values) do
		local mem = u64(val)
		local asm = Assembler()
		asm:mov(R.r9, R(memory.object_to_address(mem)))
		asm:mov(R.rax, R.r9)
		asm:ret()
		local result = asm:build("uint64_t (*)(void)")()

		if result ~= val then
			print(asm:debug_disassemble())
			print(asm:debug_hex())
			error(string.format("Memory round trip failed - Expected 0x%x, got 0x%x", val, result))
		end
	end
end)

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
	local mem = u64(buffer_size)
	local middle_offset = (buffer_size / 2) * 8
	local test_val = 0x1234567890ABCDEFULL

	for _, disp in ipairs(test_displacements) do
		asm = Assembler()
		asm:mov(R.rcx, memory.object_to_address(mem) + middle_offset)
		asm:mov(R.rax, test_val)
		asm:mov(R.rcx + disp, R.rax)
		asm:mov(R.rax, R.rcx + disp)
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
		asm:mov(R.rcx + R.rdx * scale, R.rax)
		asm:mov(R.rax, R.rcx + R.rdx * scale)
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
	asm:jump("skip")
	asm:mov(R.rax, 1)
	asm:label("skip")
	asm:ret()
	local result = asm:build("uint64_t (*)(void)")()
	assert(result == 0, string.format("Forward jump failed: expected 0, got %d", result))
end)

test("conditional jumps", function(asm)
	asm:mov(R.rax, 5)
	asm:cmp(R.rax, 5)
	asm:jump("not_equal", "~=")
	asm:mov(R.rax, 1)
	asm:jump("end")
	asm:label("not_equal")
	asm:mov(R.rax, 0)
	asm:label("end")
	asm:ret()
	local result = asm:build("uint64_t (*)(void)")()
	assert(result == 1, "JE/JNE test failed")
end)

test("multiple jumps", function(asm)
	asm:mov(R.rax, 0)
	asm:jump("middle")
	asm:mov(R.rax, 1)
	asm:jump("end")
	asm:label("middle")
	asm:mov(R.rax, 2)
	asm:jump("end")
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
	asm:jump("loop", ">")
	asm:ret()
	local result = asm:build("uint64_t (*)(void)")()
	assert(result == 5, "Loop test failed")
end)

test("forward and backward jumps", function(asm)
	asm:mov(R.rax, 0)
	asm:mov(R.rcx, 3)
	asm:jump("start")
	asm:label("loop")
	asm:inc(R.rax)
	asm:dec(R.rcx)
	asm:label("start")
	asm:cmp(R.rcx, 0)
	asm:jump("loop", ">")
	asm:ret()
	local result = asm:build("uint64_t (*)(void)")()
	assert(result == 3, "Forward/backward jump test failed")
end)

test("error cases", function(asm)
	local function test_undefined()
		local asm = Assembler()
		asm:jump("undefined")
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

expect_error(function()
	asm:mov(R.rax, R.rcx * 3)
end, "Invalid scale value")

test("debug interrupt", function(asm)
	local old_value = nil

	asm:debug(function(state)
		old_value = state.r15
	end)

	asm:push(R.r15)
	asm:mov(R.r15, 2)

	asm:debug(function(state)
		assert(state.r15 == 2ull)
	end)

	asm:mov(R.r15, 3)

	asm:debug(function(state)
		assert(state.r15 == 3ull)
	end)

	asm:pop(R.r15)

	asm:debug(function(state)
		assert(state.r15 == old_value)
	end)

	asm:ret()
	asm:build("uint64_t (*)(void)")()
end)

test("basic operations", function(asm)
	asm:mov(R.rax, 0)
	asm:inc(R.rax)

	asm:debug(function(state)
		assert(state.rax == 1)
	end)

	asm:dec(R.rax)

	asm:debug(function(state)
		assert(state.rax == 0)
	end)

	asm:add(R.rax, 1)

	asm:debug(function(state)
		assert(state.rax == 1)
	end)

	asm:sub(R.rax, 1)

	asm:debug(function(state)
		assert(state.rax == 0)
	end)

	asm:add(R.rax, 2)
	asm:mul(R.rax, 2)

	asm:debug(function(state)
		assert(state.rax == 4)
	end)

	asm:xor(R.rax, R.rax)

	asm:debug(function(state)
		assert(state.rax == 0)
	end)

	asm:xor(R.rax, R.rax)
	asm:add(R.rax, 1000)

	asm:debug(function(state)
		assert(state.rax == 1000)
	end)

	asm:add(R.rax, 2)
	asm:xor(R.rax, R.rax)

	asm:debug(function(state)
		assert(state.rax == 0)
	end)

	asm:ret()
	asm:build("void (*)(void)")()
end)

test("xor operations", function(asm)
	do
		return
	end

	asm:push(R.rax)
	asm:push(R.rbx)
	asm:push(R.rcx)
	asm:push(R.rdx)
	-- Test register to register XOR
	asm:mov(R.rax, 0xFFFFFFFFFFFFFFFF) -- all bits set
	asm:xor(R.rax, R.rax) -- XOR with self = clear
	asm:debug(function(state)
		assert(state.rax == 0, "reg,reg XOR failed")
	end)

	-- Test immediate to register XOR
	asm:mov(R.rax, 5) -- 0101
	asm:xor(R.rax, 3) -- 0011
	asm:debug(function(state)
		assert(state.rax == 6, "reg,imm XOR failed")
	end)

	-- Test memory to register XOR
	local mem1 = u64(12)
	asm:mov(R.rcx, 5)
	asm:xor(R.rcx, R(memory.object_to_address(mem1)))

	asm:debug(function(state)
		assert(state.rcx == 9, "mem,reg XOR failed") -- 5 XOR 12 = 9
	end)

	-- Test register to memory XOR
	local mem2 = u64(15)
	asm:mov(R.rbx, 8)
	asm:xor(R(memory.object_to_address(mem2)), R.rbx)

	asm:debug(function(state)
		assert(mem2[0] == 7, "reg,mem XOR failed") -- 15 XOR 8 = 7
	end)

	-- Test memory with immediate XOR
	local mem3 = u64(255)
	asm:xor(R(memory.object_to_address(mem3)), 170)

	asm:debug(function(state)
		assert(mem3[0] == 85, "mem,imm XOR failed") -- 255 XOR 170 = 85
	end)

	-- Test larger immediate values
	asm:mov(R.rax, 0x12345678)
	asm:xor(R.rax, 0x11111111)

	asm:debug(function(state)
		assert(state.rax == 0x03254769, "large immediate XOR failed")
	end)

	-- Test classic XOR trick for zeroing register
	asm:mov(R.rax, -1) -- fill with 1s
	asm:xor(R.rax, R.rax) -- should zero the register
	asm:debug(function(state)
		assert(state.rax == 0, "XOR zero trick failed")
	end)

	asm:pop(R.rdx)
	asm:pop(R.rcx)
	asm:pop(R.rbx)
	asm:pop(R.rax)
	asm:ret()
	print(asm:debug_disassemble())
	asm:build("void (*)(void)")()
end)

test("modrm and sib errors", function(asm)
	-- Test 1: SIB required error
	expect_error(
		function()
			asm:emit_instruction(
				{
					opcode = {0x89},
					modrm = {
						mode = "indirect",
						reg = 0,
						rm = 4, -- SIB indicator without SIB byte
					},
				}
			)
		end,
		"SIB required"
	)

	-- Test 2: 8-bit displacement required
	expect_error(
		function()
			asm:emit_instruction(
				{
					opcode = {0x89},
					modrm = {
						mode = "indirect8",
						reg = 0,
						rm = 1,
					},
				}
			)
		end,
		"8-bit displacement required"
	)

	-- Test 3: 32-bit displacement required
	expect_error(
		function()
			asm:emit_instruction(
				{
					opcode = {0x89},
					modrm = {
						mode = "indirect32",
						reg = 0,
						rm = 1,
					},
				}
			)
		end,
		"32-bit displacement required"
	)

	-- Test 4: 32-bit displacement required for displacement-only addressing
	expect_error(
		function()
			asm:emit_instruction(
				{
					opcode = {0x89},
					modrm = {
						mode = "indirect",
						reg = 0,
						rm = 5, -- RIP_RELATIVE
					},
				}
			)
		end,
		"32-bit displacement required for displacement-only addressing"
	)

	-- Test 5: 32-bit displacement required for rip-relative addressing
	expect_error(
		function()
			asm:emit_instruction(
				{
					opcode = {0x89},
					modrm = {
						mode = "indirect",
						reg = 0,
						rm = 4, -- SIB indicator
					},
					sib = {
						base = 5, -- RIP_RELATIVE
						index = 0,
						scale = 1,
					},
				}
			)
		end,
		"32-bit displacement required for rip-relative addressing"
	)

	-- Test 6: Cannot use RSP/R12 as SIB index register
	expect_error(
		function()
			asm:emit_instruction(
				{
					opcode = {0x89},
					modrm = {
						mode = "indirect",
						reg = 0,
						rm = 4,
					},
					prefix = {"rex_x"},
					sib = {
						scale = 1,
						index = 4, -- RSP/R12
						base = 0,
					},
				}
			)
		end,
		"Cannot use RSP/R12 as SIB index register"
	)

	-- Test 7: Invalid scale value
	expect_error(
		function()
			asm:emit_instruction(
				{
					opcode = {0x89},
					modrm = {
						mode = "indirect",
						reg = 0,
						rm = 4,
					},
					sib = {
						scale = 3, -- Invalid scale (must be 1, 2, 4, or 8)
						index = 0,
						base = 0,
					},
				}
			)
		end,
		"Invalid scale value"
	)

	-- Test 8: Invalid displacement type
	expect_error(
		function()
			asm:emit_instruction(
				{
					opcode = {0x89},
					modrm = {
						mode = "indirect8",
						reg = 0,
						rm = 1,
					},
					disp = "invalid", -- Displacement must be a number
				}
			)
		end,
		"Displacement must be a number"
	)
end)
