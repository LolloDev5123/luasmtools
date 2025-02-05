LAT = { }

LAT.Lua51 = { }
local bit = require 'Lua51.bin'
LAT.Lua51.md5 = require 'Lua51.md5'
LAT.Lua51.bit = bit[1]
LAT.Lua51.DumpBinary = bit[2]
LAT.Lua51.GetNumberType = require 'Lua51.PlatformConfig'
LAT.Lua51.Verifier = require 'Lua51.Verifier'
LAT.Lua51.Chunk = require 'Lua51.Chunk'
LAT.Lua51.LuaFile = require 'Lua51.LuaFile'
local ins = require 'Lua51.Instruction'
LAT.Lua51.Instruction = ins[1]
LAT.Lua51.Local = ins[2]
LAT.Lua51.Constant = ins[3]
LAT.Lua51.Upvalue = ins[4]
LAT.Lua51.Disassemble = require 'Lua51.Disassembler'
LAT.Lua51.Dump = require 'Lua51.Dumper'
LAT.Lua51.Decompile = { }
LAT.Lua51.Decompile.LASM = require 'Lua51.Decompiler.LASM'
LAT.Lua51.Listing = require 'Lua51.Listing'

LAT.Lua51.Lexer = require 'Lua51.LasmParser.Lexer'
LAT.Lua51.Parser = require 'Lua51.LasmParser.Parser'


LAT.Disassemble = function(s)
    local c = s:sub(5, 1)
    if c:len() == 0 then error("Invalid bytecode header") end
    local b = string.byte(c)
    if b == 0x51 then
        return LAT.Lua51.Disassemble(s)
    else
        error("Invalid bytecode header")
    end
end

return LAT
