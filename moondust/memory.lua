local ffi = require("ffi")
local memory = {}

function memory.object_to_address(var)
	if type(var) == "cdata" or type(var) == "string" then
		return ffi.cast("uintptr_t", var)
	end

	return loadstring("return " .. string.format("%p", var) .. "ULL")()
end

ffi.cdef("char *strerror(int errnum);")

local function last_error(num)
	num = num or ffi.errno()
	local err = ffi.string(ffi.C.strerror(num))
	return err == "" and tostring(num) or err
end

if jit.os ~= "Windows" then
	ffi.cdef[[
		char *mmap(void *addr, size_t length, int prot, int flags, int fd, long int offset);
		int munmap(void *addr, size_t length);
		void *dlopen(const char *filename, int flag);
		char *dlerror(void);
		void *dlsym(void *handle, const char *symbol);
		int dlclose(void *handle);
	]]
	local PROT_READ = 0x1
	local PROT_WRITE = 0x2
	local PROT_EXEC = 0x4
	local MAP_PRIVATE
	local MAP_ANONYMOUS

	if jit.os == "OSX" then
		MAP_PRIVATE = 0x0002
		MAP_ANONYMOUS = 0x1000
	else
		MAP_PRIVATE = 0x02
		MAP_ANONYMOUS = 0x20
	end

	local MAP_FAILED = ffi.cast("char *", -1)

	function memory.make_executable(str)
		local bytes = #str
		local mem = ffi.C.mmap(
			nil,
			bytes,
			bit.bor(PROT_READ, PROT_WRITE, PROT_EXEC),
			bit.bor(MAP_PRIVATE, MAP_ANONYMOUS),
			-1,
			0
		)

		if mem == MAP_FAILED then return nil, last_error() end

		ffi.copy(mem, str)
		mem = ffi.gc(mem, function()
			local code = ffi.C.munmap(mem, bytes)

			if code ~= 0 then
				io.write("failed to unmap memory: ", last_error(), "\n")
			end
		end)
		return mem
	end

	function memory.address_of_library_function(name, lib)
		local handle = ffi.C.dlopen(lib, 1)
		local ptr = ffi.C.dlsym(handle, name)
		return object_to_address(ptr)
	end
else
	ffi.cdef[[
		void *VirtualAlloc(void *lpAddress, size_t dwSize, uint16_t flAllocationType, uint16_t flProtect);
		int VirtualProtect(void *lpAddress, size_t dwSize, uint16_t  flNewProtect, uint16_t *lpflOldProtect);
		int VirtualFree(void *lpAddress, size_t dwSize, uint32_t dwFreeType);
		void *LoadLibraryA(const char *lpLibFileName);
		void *GetProcAddress(void *hModule, const char* lpProcName);
	]]
	local PAGE_EXECUTE_READWRITE = 0x40
	local PAGE_READWRITE = 0x04
	local MEM_COMMIT = 0x00001000
	local MEM_RELEASE = 0x8000

	function memory.make_executable(str)
		local mem = ffi.C.VirtualAlloc(nil, #str, MEM_COMMIT, PAGE_READWRITE)

		if mem == nil then return nil, "failed to allocate memory" end

		local temp = ffi.new("uint16_t[1]")

		if ffi.C.VirtualProtect(mem, #str, PAGE_EXECUTE_READWRITE, temp) == 0 then
			return nil, "failed to mark memory as executable"
		end

		ffi.copy(mem, str)
		mem = ffi.gc(mem, function()
			if ffi.C.VirtualFree(mem, 0, MEM_RELEASE) == 0 then
				io.write("failed to free memory\n")
			end
		end)
		return mem
	end

	function memory.address_of_library_function(name, lib)
		local handle = ffi.C.LoadLibraryA(lib)
		local ptr = ffi.C.GetProcAddress(handle, name)
		return object_to_address(ptr)
	end
end

return memory
