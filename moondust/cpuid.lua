local memory = require("moondust.memory")
local ffi = require("ffi")
local bit = require("bit")
local Assembler = require("moondust.assembler")
local R = Assembler.Registers
local M = memory.object_to_address

-- Utility function to convert register values to strings
local function bytes_to_string(value)
	local bytes = {}

	for i = 0, 3 do
		table.insert(bytes, bit.band(bit.rshift(value, i * 8), 0xFF))
	end

	return string.char(unpack(bytes))
end

-- Core CPUID function
local function cpuid(leaf, subleaf)
	local res = memory.malloc("uint32_t*", ffi.sizeof("uint32_t") * 4)
	local asm = Assembler.new()
	-- Save registers
	asm:push(R.rax)
	asm:push(R.rbx)
	asm:push(R.rcx)
	asm:push(R.rdx)
	-- Execute CPUID
	asm:mov(R.eax, leaf or 0)
	asm:mov(R.ecx, subleaf or 0)
	asm:emit(0x0F, 0xA2) -- CPUID instruction
	-- Store results
	asm:mov(R(M(res + 0)), R.rax)
	asm:mov(R(M(res + 1)), R.rbx)
	asm:mov(R(M(res + 2)), R.rcx)
	asm:mov(R(M(res + 3)), R.rdx)
	-- Restore registers
	asm:pop(R.rdx)
	asm:pop(R.rcx)
	asm:pop(R.rbx)
	asm:pop(R.rax)
	asm:ret()
	-- Execute assembled code
	asm:build("void(*)(void)")()
	local a, b, c, d = res[0], res[1], res[2], res[3]
	memory.free(res)
	return a, b, c, d
end

-- Query basic CPU information (Leaf 0)
local function query_basic_cpu_info()
	local max_leaf, b, c, d = cpuid(0, 0)
	return {
		max_leaf = max_leaf,
		vendor = bytes_to_string(b) .. bytes_to_string(d) .. bytes_to_string(c),
	}
end

-- Query CPU features and version information (Leaf 1)
local function query_cpu_features_and_version()
	local a, b, c, d = cpuid(1, 0)
	local features = {}
	-- Standard feature flags in EDX
	local edx_features = {
		[0] = "fpu",
		[1] = "vme",
		[2] = "de",
		[3] = "pse",
		[4] = "tsc",
		[5] = "msr",
		[6] = "pae",
		[7] = "mce",
		[8] = "cx8",
		[9] = "apic",
		[11] = "sep",
		[12] = "mtrr",
		[13] = "pge",
		[14] = "mca",
		[15] = "cmov",
		[16] = "pat",
		[17] = "pse36",
		[19] = "clfsh",
		[23] = "mmx",
		[24] = "fxsr",
		[25] = "sse",
		[26] = "sse2",
		[27] = "ss",
		[28] = "htt",
		[29] = "tm",
		[30] = "ia64",
		[31] = "pbe",
	}
	-- Extended feature flags in ECX
	local ecx_features = {
		[0] = "sse3",
		[1] = "pclmulqdq",
		[2] = "dtes64",
		[3] = "monitor",
		[4] = "ds_cpl",
		[5] = "vmx",
		[6] = "smx",
		[7] = "est",
		[8] = "tm2",
		[9] = "ssse3",
		[10] = "cnxt_id",
		[13] = "cmpxchg16b",
		[14] = "xtpr",
		[15] = "pdcm",
		[17] = "pcid",
		[18] = "dca",
		[19] = "sse4_1",
		[20] = "sse4_2",
		[21] = "x2apic",
		[22] = "movbe",
		[23] = "popcnt",
		[24] = "tsc_deadline",
		[25] = "aes",
		[26] = "xsave",
		[27] = "osxsave",
		[28] = "avx",
		[29] = "f16c",
		[30] = "rdrand",
	}

	-- Process EDX features
	for bit_pos, feature_name in pairs(edx_features) do
		if bit.band(d, bit.lshift(1, bit_pos)) ~= 0 then
			features[feature_name] = true
		end
	end

	-- Process ECX features
	for bit_pos, feature_name in pairs(ecx_features) do
		if bit.band(c, bit.lshift(1, bit_pos)) ~= 0 then
			features[feature_name] = true
		end
	end

	-- Calculate family and model
	local base_family = bit.rshift(bit.band(a, 0x00000F00), 8)
	local ext_family = bit.rshift(bit.band(a, 0x0FF00000), 20)
	local base_model = bit.rshift(bit.band(a, 0x000000F0), 4)
	local ext_model = bit.rshift(bit.band(a, 0x000F0000), 16)
	return {
		features = features,
		family = base_family + ext_family,
		model = (ext_model * 16) + base_model,
		stepping = bit.band(a, 0x0000000F),
		brand_id = bit.rshift(bit.band(b, 0x000000FF), 0),
		clflush_size = bit.rshift(bit.band(b, 0x0000FF00), 8) * 8,
		logical_processors = bit.rshift(bit.band(b, 0x00FF0000), 16),
		local_apic_id = bit.rshift(bit.band(b, 0xFF000000), 24),
	}
end

-- Query extended CPU features (Leaf 7)
local function query_extended_features()
	local a, b, c, d = cpuid(7, 0)
	local features = {}
	local ebx_features = {
		[0] = "fsgsbase",
		[1] = "ia32_tsc_adjust",
		[2] = "sgx",
		[3] = "bmi1",
		[4] = "hle",
		[5] = "avx2",
		[7] = "smep",
		[8] = "bmi2",
		[9] = "erms",
		[10] = "invpcid",
		[11] = "rtm",
		[12] = "pqm",
		[13] = "fpucs_fpuds",
		[14] = "mpx",
		[16] = "avx512f",
		[17] = "avx512dq",
		[18] = "rdseed",
		[19] = "adx",
		[20] = "smap",
		[21] = "avx512ifma",
		[23] = "clflushopt",
		[24] = "clwb",
		[26] = "avx512pf",
		[27] = "avx512er",
		[28] = "avx512cd",
		[29] = "sha",
		[30] = "avx512bw",
		[31] = "avx512vl",
	}
	local ecx_features = {
		[0] = "prefetchwt1",
		[1] = "avx512vbmi",
		[2] = "umip",
		[3] = "pku",
		[4] = "ospke",
		[5] = "waitpkg",
		[6] = "avx512vbmi2",
		[8] = "gfni",
		[9] = "vaes",
		[10] = "vpclmulqdq",
		[11] = "avx512vnni",
		[12] = "avx512bitalg",
		[14] = "avx512vpopcntdq",
	}

	-- Process EBX features
	for bit_pos, feature_name in pairs(ebx_features) do
		if bit.band(b, bit.lshift(1, bit_pos)) ~= 0 then
			features[feature_name] = true
		end
	end

	-- Process ECX features
	for bit_pos, feature_name in pairs(ecx_features) do
		if bit.band(c, bit.lshift(1, bit_pos)) ~= 0 then
			features[feature_name] = true
		end
	end

	return {features = features}
end

local function query_amd_cache_descriptors()
	local cache_info = {}
	local cache_types = {
		[1] = "Data",
		[2] = "Instruction",
		[3] = "Unified",
	}

	-- Try each cache level (ECX = 0,1,2,3 for L1D, L1I, L2, L3)
	for level = 0, 3 do
		local a, b, c, d = cpuid(0x8000001D, level)

		if a ~= 0 then -- Valid cache level
			local cache_type = bit.band(a, 0x1F)
			local cache_level = bit.rshift(bit.band(a, 0xE0), 5)
			local ways_encoded = bit.rshift(bit.band(a, 0x7FF000), 12)
			-- Ways calculation differs by cache level
			local ways

			if cache_level < 3 then
				ways = bit.lshift(1, ways_encoded - 1) -- L1 and L2: 2^(ways_encoded - 1)
			else
				ways = 16 -- L3 is fixed at 16-way for Ryzen 5000 series
			end

			local line_size = bit.band(b, 0xFFF) + 1
			local sets = c + 1

			-- For L3, we need to adjust the sets value
			if cache_level == 3 then
				-- Each CCX in Ryzen 5000 has 32MB L3, and sets should reflect this
				sets = sets * 2 -- Multiply by 2 to account for both CCXs
			end

			local partitions = 1
			local size = ways * partitions * line_size * sets
			local description = string.format(
				"L%d %s cache, %dKB, %d-way",
				cache_level,
				cache_types[cache_type] or "Unknown",
				size / 1024,
				ways
			)
			table.insert(
				cache_info,
				{
					code = string.format("L%d-%s", cache_level, cache_types[cache_type] or "Unknown"),
					description = description,
					type = cache_type,
					level = cache_level,
					size = size,
					ways = ways,
					line_size = line_size,
				}
			)
		end
	end

	return {cache_info = cache_info}
end

local function query_intel_cache_descriptors()
	local cache_types = {
		[0x06] = "L1 instruction cache, 8KB, 4-way",
		[0x08] = "L1 instruction cache, 16KB, 4-way",
		[0x0A] = "L1 data cache, 8KB, 2-way",
		[0x0C] = "L1 data cache, 16KB, 4-way",
		[0x22] = "L3 cache, 512KB, 4-way",
		[0x23] = "L3 cache, 1MB, 8-way",
		[0x25] = "L3 cache, 2MB, 8-way",
		[0x29] = "L3 cache, 4MB, 8-way",
		[0x2C] = "L1 data cache, 32KB, 8-way",
		[0x30] = "L1 instruction cache, 32KB, 8-way",
		[0x41] = "L2 cache, 128KB, 4-way",
		[0x42] = "L2 cache, 256KB, 4-way",
		[0x43] = "L2 cache, 512KB, 4-way",
		[0x44] = "L2 cache, 1MB, 4-way",
		[0x45] = "L2 cache, 2MB, 4-way",
		[0x46] = "L3 cache, 4MB, 4-way",
		[0x47] = "L3 cache, 8MB, 8-way",
		[0x48] = "L2 cache, 3MB, 12-way",
		[0x4E] = "L2 cache, 6MB, 24-way",
		[0x85] = "L2 cache, 2MB, 8-way",
		[0x86] = "L2 cache, 512KB, 4-way",
		[0x87] = "L2 cache, 1MB, 8-way",
	}
	local a, b, c, d = cpuid(2, 0)
	local descriptors = {}

	-- Process each register (skip first byte of EAX)
	local function process_register(value, skip_first)
		if value == 0 then return end

		local start = skip_first and 1 or 0

		for i = start, 3 do
			local descriptor = bit.band(bit.rshift(value, i * 8), 0xFF)

			if descriptor ~= 0 then
				descriptors[#descriptors + 1] = {
					code = string.format("0x%02X", descriptor),
					description = cache_types[descriptor] or "Unknown",
				}
			end
		end
	end

	process_register(a, true) -- Skip first byte of EAX
	process_register(b, false)
	process_register(c, false)
	process_register(d, false)
	return {cache_info = descriptors}
end

-- Query thermal and power management features (Leaf 6)
local function query_thermal_power_info()
	local a, b, c, d = cpuid(6, 0)
	return {
		power_info = {
			digital_thermal_sensor = bit.band(a, 1) ~= 0,
			intel_turbo_boost = bit.band(a, 2) ~= 0,
			arat = bit.band(a, 4) ~= 0,
			pln = bit.band(a, 8) ~= 0,
			ecmd = bit.band(a, 16) ~= 0,
			ptm = bit.band(a, 32) ~= 0,
			hwp = bit.band(a, 64) ~= 0,
			hwp_notification = bit.band(a, 128) ~= 0,
			hwp_activity_window = bit.band(a, 256) ~= 0,
			hwp_energy_performance = bit.band(a, 512) ~= 0,
			hwp_package_level = bit.band(a, 1024) ~= 0,
			temperature_target = bit.rshift(bit.band(b, 0xFF0000), 16),
			num_interrupt_thresholds = bit.band(b, 0x0F),
		},
	}
end

-- Query processor brand string (Leaves 0x80000002-0x80000004)
local function query_processor_brand()
	local max_extended_leaf = cpuid(0x80000000, 0)

	if max_extended_leaf >= 0x80000004 then
		local bytes = {}

		for leaf = 0x80000002, 0x80000004 do
			local a, b, c, d = cpuid(leaf, 0)

			for _, reg in ipairs({a, b, c, d}) do
				local str = bytes_to_string(reg)
				bytes[#bytes + 1] = str
			end
		end

		local result = table.concat(bytes)
		return {brand = result:match("^[%z]*(.-)%z*$") or result}
	end

	return {brand = "Unknown processor"}
end

-- Main function to gather all CPU information
local function query_complete_cpu_info()
	local info = {}
	local basic = query_basic_cpu_info()

	for _, key_values in pairs(
		{
			basic,
			query_cpu_features_and_version(),
			query_extended_features(),
			basic.vendor == "AuthenticAMD" and
			query_amd_cache_descriptors() or
			query_intel_cache_descriptors(),
			query_thermal_power_info(),
			query_processor_brand(),
		}
	) do
		for key, val in pairs(key_values) do
			info[key] = val
		end
	end

	return info
end

return query_complete_cpu_info
