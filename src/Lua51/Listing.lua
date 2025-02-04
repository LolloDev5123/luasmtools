local function Dump(file)
    local _print = print
    local indent = 0
    local current_block = nil
    local key_padding = {}
    
    local function print(...)
        local t = {...}
        local line = table.concat(t, " ")
        _print(("    "):rep(indent) .. line)
    end
    
    local function start_block(name)
        print("."..name)
        indent = indent + 1
        current_block = name
        key_padding[name] = key_padding[name] or {}
    end
    
    local function end_block()
        indent = indent - 1
        print(".end")
        current_block = nil
    end
    
    local function kv(key, value, comment)
        local padding = key_padding[current_block][key] or 0
        local line = string.format(".%-"..padding.."s %s", key, value)
        if comment then
            line = line .. " ; " .. comment
        end
        print(line)
    end
    
    local function calculate_padding(block, keys)
        local max_len = 0
        for _, key in ipairs(keys) do
            if #key > max_len then
                max_len = #key
            end
        end
        key_padding[block] = {}
        for _, key in ipairs(keys) do
            key_padding[block][key] = max_len
        end
    end
    
    local function format_constant(const)
        if const.Type == "String" then
            return string.format("%q", const.Value)
        elseif const.Type == "Nil" then
            return "nil"
        else
            return tostring(const.Value)
        end
    end
    
    local function format_lua_string(s)
        return string.format("%q", s):gsub("\\\n", "\\n"):gsub("\027", "\\27")
    end
    
    local function dump_proto(f, is_main)
        local block_type = is_main and "main" or "proto"
        start_block(block_type)
        
        local keys = { "source", "lines", "upvalues", "params", "maxstack" }
        calculate_padding(block_type, keys)
        
        if f.Source and f.Source ~= "" then
            kv("source", format_lua_string(f.Source))
        end
        
        if f.FirstLine and f.LastLine then
            kv("lines", string.format("[%d, %d]", f.FirstLine, f.LastLine))
        end
        
        if f.UpvalueCount and f.UpvalueCount > 0 then
            kv("upvalues", tostring(f.UpvalueCount))
        end
        
        local params_str = tostring(f.ArgumentCount) .. (f.Vararg and "+" or "")
        kv("params", params_str)
        
        if f.MaxStackSize then
            kv("maxstack", tostring(f.MaxStackSize))
        end
        
        if f.Locals and f.Locals.Count > 0 then
            print("")
            for i = 1, f.Locals.Count do
                local l = f.Locals[i-1]
                if i <= f.ArgumentCount then
                    kv("param", format_lua_string(l.Name), i-1)
                else
                    kv("local", format_lua_string(l.Name), i-1 - f.ArgumentCount)
                end
            end
        end
        
        if f.Constants and f.Constants.Count > 0 then
            print("")
            for i = 1, f.Constants.Count do
                local const = f.Constants[i-1]
                kv("const", format_constant(const), i-1)
            end
        end
        
        if f.Upvalues and f.Upvalues.Count > 0 then
            print("")
            for i = 1, f.Upvalues.Count do
                local upv = f.Upvalues[i-1]
                kv("upval", upv.Name and format_lua_string(upv.Name) or tostring(i-1), i-1)
            end
        end
        
        if f.Protos and f.Protos.Count > 0 then
            print("")
            for i = 1, f.Protos.Count do
                dump_proto(f.Protos[i-1], false)
            end
        end
        
        if f.Instructions and f.Instructions.Count > 0 then
            print("")
            start_block("instr")
            print("; idx offset line opcode     a    b    c")
            for i = 1, f.Instructions.Count do
                local instr = f.Instructions[i-1]
                local offset = (i-1) * file.InstructionSize
                local offset_str = string.format("/x%03X/", offset)
                local idx = string.format("%03d", i)
                local line = instr.LineNumber or 0
                local opcode = instr.Opcode:upper()
                local a, b, c = "", "", "-"
                
                if instr.OpcodeType == "ABC" then
                    a, b, c = tostring(instr.A), tostring(instr.B), tostring(instr.C)
                elseif instr.OpcodeType == "ABx" then
                    a, b = tostring(instr.A), tostring(instr.Bx)
                elseif instr.OpcodeType == "AsBx" then
                    a, b = tostring(instr.A), tostring(instr.sBx)
                end
                
                local comment = ""
                if opcode == "GETGLOBAL" then
                    local const = f.Constants[instr.Bx]
                    comment = string.format("R%s := _G[%s]", a, const.Value)
                elseif opcode == "MOVE" then
                    comment = string.format("R%s := R%s", a, b)
                elseif opcode == "RETURN" then
                    comment = "return"
                end
                
                print(string.format("%s %s (%d) %-9s %4s %4s %4s    ; %s",
                    idx, offset_str, line, opcode, a, b, c, comment))
            end
            end_block()
        end
        
        end_block()
    end
    
    -- Dump header
    start_block("header")
    local header_keys = { "signature", "version", "format", "endianness", "int", "size_t", "instr", "number", "integral" }
    calculate_padding("header", header_keys)
    
    kv("signature", format_lua_string(file.Identifier))
    kv("version", tostring(file.Version))
    kv("format", file.Format == "official" and 0 or 1, string.lower(file.Format))
    local endian_val = file.BigEndian and 0 or 1
    kv("endianness", tostring(endian_val), endian_val == 1 and "little endian" or "big endian")
    kv("int", tostring(file.IntegerSize))
    kv("size_t", tostring(file.SizeT))
    kv("instr", tostring(file.InstructionSize))
    kv("number", tostring(file.NumberSize))
    local integral_val = file.IsFloatingPoint and 0 or 1
    kv("integral", tostring(integral_val), integral_val == 0 and "floating point" or "integral")
    end_block()
    
    -- Dump main function
    dump_proto(file.Main, true)
end

return Dump