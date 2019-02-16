package.path = package.path .. ";../src/?.lua"

-- this requires that lua can execute gcc, as and objdump (so typically in a unix envionment with dev tools)

local gas = require("gas")
local util = require("util")
local x86_64 = require("x86_64")

local function compare(str, bytes)
	gas.dump_asm(str, function(bytes)
		-- max 15 bytes per row, separate each byte by "  ", show hex
		return util.string_binformat(bytes, 15, "  ", true)
	end,
	bytes)
end

compare("mov $10, %rax", x86_64.encode("mov", {reg = "rax"}, 10).bytes)
compare("mov $10, %rax", x86_64.encode("mov", {reg = "rax"}, 0xdead).bytes)