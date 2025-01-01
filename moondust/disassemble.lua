local function disassemble(str)
	local temp_bin = os.tmpname and os.tmpname() or "/tmp/asm_debug.bin"
	local temp_asm = os.tmpname and os.tmpname() or "/tmp/asm_debug.asm"
	local f = assert(io.open(temp_bin, "wb"))
	f:write(str)
	f:close()
	local output
	local tbl = {}

	if os == "Windows" then
		local success = os.execute(string.format("dumpbin /DISASM %s > %s", temp_bin, temp_asm))

		if not success then error("Failed to run disassembler") end

		local f = assert(io.open(temp_asm, "r"))
		output = f:read("*all")
		f:close()
	else
		local success = os.execute(
			string.format(
				"objdump --wide --disassembler-options=intel --disassemble-all --target=binary --architecture=i386:x86-64 --no-show-raw-insn --no-addresses %s > %s",
				temp_bin,
				temp_asm
			)
		)

		if not success then error("Failed to run disassembler") end

		local f = assert(io.open(temp_asm, "r"))
		output = f:read("*all")

		if not output or output == "" then return "" end

		f:close()
		output = output:match("%<.data%>:\n(.+)")

		for line in output:gmatch("(.-)\n") do
			line = line:gsub("%s+#%s*", "")
			local inst, args = line:match("%s+(%S+)%s+(.+)")

			if not inst then inst = line:match("%s+(%S+)") end

			local a, b

			if args then a, b = args:match("(.+),(.+)") end

			if a and b then
				table.insert(tbl, inst .. " " .. a .. "," .. b)
			elseif a then
				table.insert(tbl, inst .. " " .. a)
			else
				table.insert(tbl, inst)
			end
		end
	end

	os.remove(temp_bin)
	os.remove(temp_asm)
	output = table.concat(tbl, "\n")
	return output
end

return disassemble
