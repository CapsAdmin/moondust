local x86_64 = require("x86_64")

for k,v in pairs(x86_64.encode("mov", {reg = "rax"}, {reg = "rdi"})) do
  print(k,v)
end