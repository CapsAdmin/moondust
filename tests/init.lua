print("running tests..")

loadfile("tests/comparisons.lua")()
loadfile("tests/execute.lua")()

print("tests ran!")

print("running examples..")

loadfile("examples/dump_gas.lua")()
loadfile("examples/hello_world.lua")()
loadfile("examples/hello_world_alt.lua")()
loadfile("examples/labels.lua")()
loadfile("examples/vec3_length.lua")()

print("examples ran!")

print("test complete!")