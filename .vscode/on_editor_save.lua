local did_something = false

local function run_lua(path, ...)
	did_something = true
	print("running ", path)
	assert(loadfile(path))(...)
end

local function has_test_focus()
	local f = io.open("test_focus.lua")

	if not f or (f and #f:read("*all") == 0) then
		if f then f:close() end

		return false
	end

	return true
end

local path = ...
local normalized = path:lower():gsub("\\", "/")

if normalized:find("on_editor_save.lua", nil, true) then return end

if normalized:find("/moondust/", nil, true) then
	if not path then error("no path") end

	local is_lua = path:sub(-4) == ".lua"

	if not is_lua then return end

	if has_test_focus() then
		print("running test focus")
		run_lua("./test_focus.lua")	
	elseif path:find("/moondust/moondust/", nil, true) then
		run_lua("tests/init.lua")
	elseif path:find("/tests/", nil, true) then
		run_lua(path)
	end
end

if not did_something then
	print("not sure how to run " .. path)
	print("running as normal lua")
	run_lua(path)
end
