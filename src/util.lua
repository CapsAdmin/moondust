local util = {}

function util.string_totable(self)
	local tbl = {}
	for i = 1, #self do
		tbl[i] = self:sub(i, i)
	end
	return tbl
end

function util.string_split(self, separator, plain_search)
	if separator == nil or separator == "" then
		return util.string_totable(self)
	end

	if plain_search == nil then
		plain_search = true
	end

	local tbl = {}
	local current_pos = 1

	for i = 1, #self do
		local start_pos, end_pos = self:find(separator, current_pos, plain_search)
		if not start_pos then break end
		tbl[i] = self:sub(current_pos, start_pos - 1)
		current_pos = end_pos + 1
	end

	if current_pos > 1 then
		tbl[#tbl + 1] = self:sub(current_pos)
	else
		tbl[1] = self
	end

	return tbl
end

function util.string_startswith(a, b)
	return a:sub(0, #b) == b
end

function util.string_endswith(a, b)
	return a:sub(-#b) == b
end

function util.string_trim(self, char)
	if char then
		char = char:patternsafe() .. "*"
	else
		char = "%s*"
	end

	local _, start = self:find(char, 0)
	local end_start, end_stop = self:reverse():find(char, 0)

	if start and end_start then
		return self:sub(start + 1, (end_start - end_stop) - 2)
	elseif start then
		return self:sub(start + 1)
	elseif end_start then
		return self:sub(0, (end_start - end_stop) - 2)
	end

	return self
end

function util.string_levenshtein(a, b)
	local distance = {}

	for i = 0, #a do
	  distance[i] = {}
	  distance[i][0] = i
	end

	for i = 0, #b do
	  distance[0][i] = i
	end

	local str1 = util.string_totable(a)
	local str2 = util.string_totable(b)

	for i = 1, #a do
		for j = 1, #b do
			distance[i][j] = math.min(
				distance[i-1][j] + 1,
				distance[i][j-1] + 1,
				distance[i-1][j-1] + (str1[i-1] == str2[j-1] and 0 or 1)
			)
		end
	end

	return distance[#a][#b]
end

local ffi = require("ffi")

function util.object_to_address(var)
    if type(var) == "cdata" or type (var) == "string" then
        return assert(loadstring("return " .. tostring(ffi.cast("void *", var)):match(": (0x.+)") .. "ULL"))()
    end

    return loadstring("return " .. string.format("%p", var) .. "ULL")()
end


function util.string_readablehex(str)
	return (str:gsub("(.)", function(str) str = ("%X"):format(str:byte()) if #str == 1 then str = "0" .. str end return str .. " " end))
end
function util.string_hexformat(str, chunk_width, row_width, space_separator)
	row_width = row_width or 4
	chunk_width = chunk_width or 4
	space_separator = space_separator or " "

	local str = util.string_split(util.string_readablehex(str):lower(), " ")
	local out = {}

	local chunk_i = 1
	local row_i = 1

	for _, char in pairs(str) do
		table.insert(out, char)
		table.insert(out, " ")

		if row_i >= (row_width * chunk_width) then
			table.insert(out, "\n")
			chunk_i = 0
			row_i = 0
		end

		if chunk_i >= chunk_width then
			table.insert(out, space_separator)
			chunk_i = 0
		end

		row_i = row_i + 1
		chunk_i = chunk_i + 1
	end

	return util.string_trim(table.concat(out))
end


function util.number2binary(num, bits)
	bits = bits or 32
	local bin = {}

	for i = 1, bits do
		if num > 0 then
			rest = math.fmod(num,2)
			table.insert(bin, rest)
			num = (num - rest) / 2
		else
			table.insert(bin, 0)
		end
	end

	return table.concat(bin):reverse()
end

function util.binary2number(bin)
	return tonumber(bin, 2)
end

function util.string_binformat(str, row_width, space_separator, with_hex, format)
	row_width = row_width or 8
	space_separator = space_separator or " "

	local str = util.string_totable(str)
	local out = {}

	local chunk_i = 1
	local row_i = 1

	for _, char in pairs(str) do

        local bin = util.number2binary(char:byte(), 8)
		if with_hex then
			table.insert(out, ("%02X/"):format(char:byte()))
		end

		if format then
			local str = ""
			local bin = util.string_totable(bin)


			local offset = 1
			for _, num in ipairs(util.string_totable(format)) do
				num = tonumber(num)
				table.insert(bin, num + offset, "-")
				offset = offset + 1
			end

			table.insert(out, table.concat(bin))
		else
			table.insert(out, bin)
		end
		table.insert(out, space_separator)

		if row_i >= row_width then
			table.insert(out, "\n")
			row_i = 0
		end

		row_i = row_i + 1
	end

	return util.string_trim(table.concat(out))
end


return util