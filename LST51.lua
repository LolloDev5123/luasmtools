require'LAT'

if #arg == 0 then
    error("No input file specified!")
end
file = LAT.Lua51.Disassemble(io.open(arg[1], "rb"):read"*a")

LAT.Lua51.Listing(file)
