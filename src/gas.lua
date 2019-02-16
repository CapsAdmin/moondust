local util = require("util")

local gas = {}

function gas.dump_asm(code, format_func, compare, left_align)
    local tbl = gas.asm_to_table(code)
    if tbl then
        local str = gas.format_table(tbl, nil, format_func, compare, left_align)
        io.write(str, "\n")
    end
end

function gas.dump_c(code, format_func)
    if not code:find("int main") then
        local template = [[
            #include <stdio.h>

            int main( int argc, char *argv[] )
            {
                ]]..code..[[
                return 0;
            }
        ]]

        code = template
    end

    local tbl = gas.asm_to_table(code, true)
    if tbl then
        local str = gas.format_table(tbl, nil, format_func)
        io.write(str, "\n")
    end
end

function gas.format_table(tbl, skip_print_matched, format_func, compare, left_align)
    format_func = format_func or util.string_hexformat
    if compare then
        tbl[1].compare_bytes = compare
    end
    local ok = true

    local out = {}

    do
        local longest = 0

        for _, data in ipairs(tbl) do
            for _, arg in ipairs(data.guess) do
                longest = math.max(longest, #arg)
            end
        end

        for _, data in ipairs(tbl) do
            local fmt = ("%-"..longest.."s "):rep(#data.guess - 1) .. "%s "
            data.guess = string.format(fmt, unpack(data.guess))
        end
    end

    do
        local longest_left = 0
        local longest_right = 0

        for _, data in ipairs(tbl) do
            data.hex = format_func(data.bytes)

            longest_left = math.min(math.max(longest_left, #data.guess), 99)
            longest_right = math.min(math.max(longest_right, #data.hex), 99)
        end

        for i, data in ipairs(tbl) do
            local str = string.format("%-"..longest_left.."s: %-"..longest_right.."s", data.guess, data.hex)
            if not skip_print_matched then
                table.insert(out, str)
            end

            local compare_bytes = data.compare_bytes or (compare and compare[i] and compare[i].bytes)

            if compare_bytes and compare_bytes ~= data.bytes then
                if skip_print_matched then
                    table.insert(out, str)
                end

                local hex = format_func(compare_bytes)

                hex =  ("%-"..longest_right.."s"):format(hex)
                hex = (" "):rep(longest_left + 2) .. hex

                hex = hex:gsub("(%s+)$", "")

                local diff = ""
                for i = 1, #str do
                    if str:sub(i, i) == hex:sub(i, i) then
                        diff = diff .. " "
                    else
                        diff = diff .. hex:sub(i, i)
                    end
                end

                if #util.string_trim(diff) == 0 then
                    diff = hex
                end

                table.insert(out, diff .. " << DIFF")
                --table.insert(out, (" "):rep(longest_left + 2) .. ("^"):rep(#hex))
                table.insert(out, "")

                ok = false
            end
        end
    end

    return table.concat(out, "\n"), ok
end

local function to_table(str, c_source, execute)
    if not c_source then
        if not str:find("_start", nil, true) then
            str = ".global _start\n.text\n_start:\n" .. str
            str = str:gsub("; ", "\n")
        end
        str = str .. "\n"
    end

    local function go()

        if c_source then
            local f, err = io.open("temp.c", "wb")

            if not f then
                return nil, "failed to read temp.c: " .. err
            end

            f:write(str)
            f:close()

            if not os.execute("gcc -S temp.c") then return nil, "failed to compile C code" end
        else
            local f, err = io.open("temp.s", "wb")

            if not f then
                return nil, "failed to read temp.s: " .. err
            end

            f:write(str)
            f:close()
        end

        if not os.execute("as -march=generic64 -o temp.o temp.s") then return nil, "failed to assemble temp.S" end
        if not os.execute("ld -s -o temp temp.o") then return nil, "failed to generate executable from temp.o" end

        if execute then
            os.execute("./temp")
        end

        local f, err = io.popen("objdump -M suffix --special-syms --disassemble-zeroes -S -M amd64 --insn-width=16 --disassemble temp")
        if not f then
            return nil, "failed to read temp.dump: " .. err
        end
        local bin = f:read("*all")
        f:close()
        local content = bin:match("<.text>:(.+)")
        if not content then
            return nil, "failed to find .text"
        end

        local chunk = util.string_trim(content):gsub("\n%s+", "\n")

        local tbl
        for line in (chunk.."\n"):gmatch("(.-)\n") do
            tbl = tbl or {}
            local address, bytes, guess = line:match("^(.-):%s+(%S.-)  %s+(%S.+)")
            guess = guess:gsub(",", ", ")
            guess = guess:gsub("%%", "")
            guess = guess:gsub("%$", "IMM_")-- FIX THE CONSOLE OUTPUT
            guess = guess:gsub(",", "")
            guess = guess:gsub("%s+", " ")
            guess = util.string_split(guess, " ")

            local bin = ""

            local hex_numbers = util.string_split(bytes, " ")


            for _, hex in ipairs(hex_numbers) do
                bin = bin .. string.char(tonumber(hex, 16))
            end

            table.insert(tbl, {address = address, bytes = bin, guess = guess})
        end

        return tbl
    end

    local res, err = go()

    os.remove("temp.o")
    os.remove("temp.s")
    os.remove("temp")

    return res, err
end

function gas.asm_to_table(str, execute)
    return to_table(str, false, execute)
end

function gas.c_to_table(str, execute)
    return to_table(str, true, execute)
end

return gas