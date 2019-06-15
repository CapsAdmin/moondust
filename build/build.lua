io.write("building moondust/x86_64_data.lua")
io.flush()


local function string_startswith(a, b)
	return a:sub(0, #b) == b
end

local function string_endswith(a, b)
	return a:sub(-#b) == b
end


local json = require("build/json")
local util = require("moondust/util")

local type_translate = {
	i8 = "int8_t",
	i16 = "int16_t",
	i32 = "int32_t",
	i64 = "int64_t",

	u8 = "uint8_t",
	u16 = "uint16_t",
	u32 = "uint32_t",
	u64 = "uint64_t",
}

local type_translate2 = {
	ib = "i8",
	iw = "i16",
	id = "i32",
	iq = "i64",

	ub = "u8",
	uw = "u16",
	ud = "u32",
	uq = "u64",

	rel8 = "i8",
	rel16 = "i16",
	rel32 = "i32",
}

local function parse_db(db)
    local map = {}
    local function parse_instruction(name, operands, encoding, opcode, metadata, operands2)
        local real_operands = {}
        local arg_line = {}
        for i, v in ipairs(operands) do
            real_operands[i] = v
            v = type_translate2[v] or v
            operands[i] = v
            arg_line[i] =  "op" .. i
        end

        local key = table.concat(operands, ",")

        if map[name] and map[name][key] and map[name][key].encoding == "MR" then
            return
        end

        arg_line = table.concat(arg_line, ", ")


        local lua = "function("..arg_line..")"

        local instr_length = 0

        local instr = {}

        if opcode[1] == "REX.W" then
            local op2 = ")"

            if operands[2] and (string_startswith(operands[2], "r") or string_startswith(operands[2], "m")) then
                op2 = ", op2.reg and x86_64.reginfo[op2.reg].extra, op2.index and x86_64.reginfo[op2.index].extra)"
            end

            table.insert(instr, "x86_64.encode_rex(true, "..tostring(encoding == "RM")..", op1.reg and x86_64.reginfo[op1.reg].extra" .. op2)
        end

        for _, byte in ipairs(opcode) do
            if byte == "/r" then
                if encoding == "MR" and operands[1]:sub(1,1) == "m" and (operands[2]:sub(1,1) == "r" or operands[2]:sub(1,1) == "x") then
                    table.insert(instr, "x86_64.encode_modrm_sib(op2, op1)")
                else
                    table.insert(instr, "x86_64.encode_modrm_sib(op1, op2)")
                end
            elseif string_startswith(byte, "c") then
                local s = byte:sub(2,2)
                if s == "b" then
                    table.insert(instr, "x86_64.encode_int('int8_t', op"..#operands..")")
                elseif s == "w" then
                    table.insert(instr, "x86_64.encode_int('int16_t', op"..#operands..")")
                elseif s == "d" then
                    table.insert(instr, "x86_64.encode_int('int32_t', op"..#operands..")")
                end
            elseif string_startswith(byte, "/") and tonumber(byte:sub(2,2)) then
                table.insert(instr, "x86_64.encode_modrm_sib(op1, "..byte:sub(2,2)..")")
            elseif string_endswith(byte, "+r") then
                table.insert(instr, "string.char(0x"..byte:sub(1, 2).." + x86_64.reginfo[op1.reg].index)")
            elseif type_translate[type_translate2[byte]] then
                table.insert(instr, "x86_64.encode_int(\""..type_translate[type_translate2[byte]].."\", op"..#operands..")")
            elseif tonumber(byte, 16) then
                table.insert(instr, "\"\\x"..byte.."\"")
                instr_length = instr_length + 1
            end
        end

        local has_relative = false
        local alt_key

        for i, v in ipairs(real_operands) do
            if string_startswith(v, "rel") then
                instr_length = instr_length + tonumber(v:sub(4)) / 8
                --lua = lua .. "\nop" .. i .. " = op" .. i .. " - " .. instr_length .. "\n"
                has_relative = true
                operands[i] = "string"
            end
        end

        if has_relative then
            alt_key = table.concat(operands)
        end

        lua = lua .. " return " .. table.concat(instr, "..")
        lua = lua:gsub("\"%s*%.%.%s*\"", "")
        lua = lua .." end"

        map[name] = map[name] or {}
        map[name][key] = {
            func = loadstring("local x86_64 = ... return " .. lua)(x86_64),
            lua = lua,
            name = name,
            operands = operands,
            encoding = encoding,
            opcode = opcode,
            metadata = metadata,
            operands2 = operands2,
            real_operands = real_operands,
            has_relative = has_relative,
        }

        if alt_key then
            map[name][alt_key] = map[name][key]
        end
    end

    for i, v in ipairs(db.instructions) do
        local name, operands, encoding, opcode, metadata = unpack(v)

        if operands:find("mem", 1, true) then
            operands = operands:gsub("mem", "m32/m64")
        elseif operands:find("m32", 1, true) then
            operands = operands:gsub("m32", "m32/m64")
        elseif operands:find("m64", 1, true) then
            operands = operands:gsub("m64", "m32/m64")
        end

        local args = {}

        local tbl = util.string_split(operands, ",")
        --for i = #tbl, 1, -1 do local arg = tbl[i]
        for i, arg in ipairs(tbl) do
            arg = util.string_trim(arg)

            local mode
            if arg:sub(2,2) == ":" then
                mode = arg:sub(1, 1)
                arg = arg:sub(3)
            end

            if string_startswith(arg, "~") then
                arg = arg:sub(2) -- also swap args?
            end


            if arg == "m64fp" then arg = "m64" end
            if arg == "m32fp" then arg = "m32" end

            if not string_startswith(arg, "<") then
                table.insert(args, util.string_trim(arg))
            end
        end

        if #args == 0 then
            for _, name in ipairs(util.string_split(name, "/")) do
                parse_instruction(name, args, encoding, util.string_split(opcode, " "), metadata, operands)
            end
        else
            local temp = {}
            local max = 0

            for i, arg in ipairs(args) do
                temp[i] = temp[i] or {}
                for z, var in ipairs(util.string_split(arg, "/")) do
                    temp[i][z] = var
                end
                max = math.max(max, #temp[i])
            end

            for z = 1, max do
                local args2 = {}
                for i = 1, #args do
                    table.insert(args2, temp[i][math.min(z, #temp[i])])
                end

                for _, name in ipairs(util.string_split(name, "/")) do
                    parse_instruction(name, args2, encoding, util.string_split(opcode, " "), metadata, operands)
                end
            end
        end
    end

    return map
end

local js = assert(io.open("build/x86data.js", "rb")):read("*all")

local data = js:match("// %$%{JSON:BEGIN%}(.+)// ${JSON:END}")
data = data:gsub("%/%*.-%*/", "")

local map = parse_db(json.decode(data))

do
    local lua = {}
    local i = 1
    local function line(str)
        lua[i] = str
        i = i + 1
    end
    line "local x86_64 = _G.x86_64 or require('moondust.x86_64')"
    line "local map = {"

    for name, functions in pairs(map) do
        line("\t['" .. name .. "'] = {")

        for type, data in pairs(functions) do
            line("\t\t['" .. type .. "'] = {")

            for k, v in pairs(data) do
                local str

                if _G.type(v) == "table" then
                    local temp = {}
                    for i,v in ipairs(v) do
                        temp[i] = string.format("%q", v)
                    end
                    str = "{" .. table.concat(temp, ", ") .. "}"
                elseif k == "func" then
                    str = nil
                elseif k == "lua" then
                    k = "func"
                    str = v
                elseif _G.type(v) == "string" then
                    str = string.format("%q", v)
                else
                    str = tostring(v)
                end

                if str then
                    line("\t\t\t" .. k .. " = " .. str .. ",")
                end
            end

            line ("\t\t},")
        end

        line("\t},")
    end

    line("}")

    line("return map")

    local file = io.open("moondust/x86_64_data.lua", "w")
    file:write(table.concat(lua, "\n"))
    file:close()
end

print(" - OK")