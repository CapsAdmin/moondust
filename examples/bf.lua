package.path = package.path .. ";./src/?.lua"

local asm = require("assembler")
local util = require("util")
local ffi = require("ffi")

local reg = asm.reg

local TAPE_SIZE = 30000
local MAX_NESTING = 100

local function bf_run(program)
    local state = {}
    state.tape = ffi.new("unsigned char[?]", TAPE_SIZE)

    local a = asm.assembler()

    local loops = {}
    local nloops = 0
    local n

    local npc = 8
    local nextpc = 0

    local aPtr
    local aState
    local aTapeBegin
    local aTapeEnd
    local rArg1
    local rArg2
    local prepcall1
    local prepcall2
    local prologue
    local epilogue

    if jit.arch == "x64" then
        aPtr = reg.rbx
        aState = reg.r12
        aTapeBegin = reg.rsi
        aTapeEnd = reg.rdi
        rArg1 = reg.rcx
        rArg2 = reg.rdx

        function prepcall1(a, arg1)
            a:mov(rArg1, arg1)
        end

        function prepcall2(a, arg1, arg2)
            a:mov(rArg1, arg1)
            a:mov(rArg2, arg2)
        end

        function prologue(a)
            a:push(aPtr)
            a:push(aState)
            a:push(aTapeBegin)
            a:push(aTapeEnd)
            a:push(reg.rax)
            a:mov(aState, rArg1)
        end

        function epilogue()
            a:pop(reg.rax)
            a:pop(aTapeEnd)
            a:pop(aTapeBegin)
            a:pop(aState)
            a:pop(aPtr)
            a:ret()
        end
    end

    prologue(a)
    a:mov(aPtr, state.tape)
    a:lea(aTapeBegin, aPtr - 1)
    a:lea(aTapeEnd, aPtr + TAPE_SIZE - 1)

    local i = 1
    while true do
        local c = program:sub(i, i)

        if c == "<" then
            local n = 1
            while program:sub(i, i) == "<" do
                a:sub(aPtr, n - TAPE_SIZE)
                a:cmp(aPtr, aTapeBegin)

                a:ja("1")
                    a:add(aPtr, TAPE_SIZE)
                a:label("1")
                i = i + 1
                n = n + 1
            end
        elseif c == ">" then
            local n = 1
            while program:sub(i, i) == "<" do
                a:add(aPtr, n - TAPE_SIZE)
                a:cmp(aPtr, aTapeEnd)

                a:ja("1")
                    a:add(aPtr, TAPE_SIZE)
                a:label("1")
                i = i + 1
                n = n + 1
            end
        elseif c == "+" then
            local n = 1
            while program:sub(i, i) == "<" do
                a:add(aPtr(), n)
            end
        elseif c == "-" then
            local n = 1
            while program:sub(i, i) == "<" do
                a:sub(aPtr(), n)
            end
        elseif c == "," then
            prepcall1(a, aState)
            a:call(string.byte("n")) -- NYI
            -- postcall
            a:mov(aPtr(), reg.al)
        elseif c == "." then
            a:movzx(reg.r0, aPtr()) -- ???
            prepcall2(a, r0)
            a:call(string.byte("n")) -- NYI
            -- postcall
            a:mov(aPtr(), reg.al)
        elseif c == "[" then

        end
    end
end