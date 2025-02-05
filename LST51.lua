require'LAT'

if #arg == 0 then
    error("No input file specified!")
end
file = io.open(arg[1], "rb"):read"*a"

LAT.Listing(file)
