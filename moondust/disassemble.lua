local function disassemble(str)
	-- Write machine code to temp file
	local temp_bin = os.tmpname and os.tmpname() or "/tmp/asm_debug.bin"
	local temp_asm = os.tmpname and os.tmpname() or "/tmp/asm_debug.asm"
	local f = assert(io.open(temp_bin, "wb"))
	f:write(str)
	f:close()
	-- Use appropriate disassembler based on OS
	local cmd

	if os == "Windows" then
		-- Try to find MSVC's dumpbin
		cmd = string.format("dumpbin /DISASM %s > %s", temp_bin, temp_asm)
	else
		-- Use objdump or ndisasm on Unix-like systems
		local has_objdump = os.execute("which objdump >/dev/null 2>&1")

		if has_objdump == 0 then
			cmd = string.format("objdump -D -b binary -m i386:x86-64 %s > %s", temp_bin, temp_asm)
		else
			local has_ndisasm = os.execute("which ndisasm >/dev/null 2>&1")

			if has_ndisasm == 0 then
				cmd = string.format("ndisasm -b 64 %s > %s", temp_bin, temp_asm)
			else
				error("No suitable disassembler found (need objdump or ndisasm)")
			end
		end
	end

	-- Run disassembler
	local success = os.execute(cmd)

	if not success then error("Failed to run disassembler") end

	-- Read and return disassembly
	local f = assert(io.open(temp_asm, "r"))
	local disasm = f:read("*all")
	f:close()
	-- Clean up temp files
	os.remove(temp_bin)
	os.remove(temp_asm)
	return disasm
end

return disassemble
