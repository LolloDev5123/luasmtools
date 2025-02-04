require'LAT'

if #arg == 0 then
    error("No input file specified!")
end
file = LAT.Lua51.Disassemble(io.open(arg[1], "rb"):read"*a")
print("; Disassembled to listing file")
print("; by Retrospect, a LASM fork 2025")
print""
print(LAT.Lua51.Listing(file))
