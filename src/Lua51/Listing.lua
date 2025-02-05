local _VERSION = "v1.1"
local function Listing(file)

    local _print = print
    local start_time = os.clock()
    local indent = 0
    local current_block = nil
    local block_stack = {}
    local key_padding = {}
    local block_max_lengths = {}

    local function update_block_padding(block, line_length)
        if not block_max_lengths[block] then
            block_max_lengths[block] = 0
        end
        if line_length > block_max_lengths[block] then
            block_max_lengths[block] = line_length
        end
    end

    local buffer = {};

    local function print(...)
        local t = {...}
        local line = table.concat(t, " ")
        table.insert(buffer, ("    "):rep(indent) .. line)
    end

    local function LeftJustify(s, width) return s..string.rep(" ", width - string.len(s)) end
    local function RightJustify(s, width) return string.rep(" ", width - string.len(s))..s end

    local function start_block(name)
        print("."..name)
        indent = indent + 1
        current_block = name
        key_padding[name] = key_padding[name] or {}
        block_max_lengths[name] = 0
    end

    local function end_block()
        indent = indent - 1
        print(".end")
        current_block = nil
    end

    local function kv(key, value, comment)
        local padding = key_padding[current_block][key] or 0
        local line = string.format(".%-"..padding.."s %s", key, value)
        local line_length = #line
        
        update_block_padding(current_block, line_length)
        
        if comment then
            local padding_needed = block_max_lengths[current_block] - line_length + 1
            line = line .. string.rep(" ", padding_needed) .. "; " .. comment
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
        return ({string.format("%q", s):gsub("\\\n", "\\n"):gsub("\027", "\\27")})[1]
    end

    local function get_opcode_comment(instr, f, pc)
        local comment = ""
        local A = instr.A
        local B = instr.B
        local C = instr.C
        local Bx = instr.Bx
        local sBx = instr.sBx
        local FPF = 50 -- Fields Per Flush for SETLIST

        local max_idx = f.Instructions.Count
        local max_offset = (max_idx - 1) * file.InstructionSize
        local idx_width = math.floor(math.log10(max_idx)) + 1
        local offset_width = string.format("%X", max_offset):len()
        
        local function format_goto(target_pc)
            local target_idx = target_pc
            local target_offset = target_pc * file.InstructionSize
            return string.format("goto %0"..idx_width.."d /x%0"..offset_width.."X/", target_idx, target_offset)
        end

        local function get_local_name(reg)
            if reg < f.Locals.Count then
                local local_var = f.Locals[reg]
                if pc+1 >= local_var.StartPC and pc+1 <= local_var.EndPC then
                    return local_var.Name
                end
            end
            return nil
        end
    
        local function reg_str(reg)
            -- Avoid local names in debug that could confuse the opcode comments (R1 which is actually R4, etc.)
            return (get_local_name(reg) and not string.match(get_local_name(reg),"^[RKUJ]%d+$")) and get_local_name(reg) or ("R"..reg)
        end
    
        local function rk_str(x)
            return x >= 256 and format_constant(f.Constants[x - 256]) or reg_str(x)
        end
    
        local op = instr.Opcode
        if op == "MOVE" then
            comment = string.format("%s := %s", reg_str(A), reg_str(B))
        elseif op == "LOADK" then
            comment = string.format("%s := %s", reg_str(A), format_constant(f.Constants[Bx]))
        elseif op == "LOADBOOL" then
            comment = string.format("%s := %s", reg_str(A), B ~= 0 and "true" or "false")
            if C ~= 0 then comment = comment .. "; ".. format_goto(pc + 1) end
        elseif op == "LOADNIL" then
            if reg_str(A) ~= reg_str(B) then
                comment = string.format("%s, ..., %s := nil", reg_str(A), reg_str(B))
            else
                comment = string.format("%s := nil", reg_str(A))
            end
        elseif op == "GETUPVAL" then
            local uv = f.Upvalues[B]
            comment = string.format("%s := %s", reg_str(A), uv.Name or "U"..tostring(B))
        elseif op == "GETGLOBAL" then
            comment = string.format("%s := _G[%s]", reg_str(A), format_constant(f.Constants[Bx]))
        elseif op == "GETTABLE" then
            comment = string.format("%s := %s[%s]", reg_str(A), reg_str(B), rk_str(C))
        elseif op == "SETGLOBAL" then
            comment = string.format("_G[%s] := %s", format_constant(f.Constants[Bx]), reg_str(A))
        elseif op == "SETUPVAL" then
            local uv = f.Upvalues[B]
            comment = string.format("%s := %s", uv.Name or "U"..tostring(B), reg_str(A))
        elseif op == "SETTABLE" then
            comment = string.format("%s[%s] := %s", reg_str(A), rk_str(B), rk_str(C))
        elseif op == "NEWTABLE" then
            comment = string.format("%s := {} (array:%d, hash:%d)", reg_str(A), 2^B, 2^C)
        elseif op == "SELF" then
            comment = string.format("%s := %s; %s := %s[%s]",
                       reg_str(A+1), reg_str(B), reg_str(A), reg_str(B), rk_str(C))
        elseif op == "ADD" then
            comment = string.format("%s := %s + %s", reg_str(A), rk_str(B), rk_str(C))
        elseif op == "SUB" then
            comment = string.format("%s := %s - %s", reg_str(A), rk_str(B), rk_str(C))
        elseif op == "MUL" then
            comment = string.format("%s := %s * %s", reg_str(A), rk_str(B), rk_str(C))
        elseif op == "DIV" then
            comment = string.format("%s := %s / %s", reg_str(A), rk_str(B), rk_str(C))
        elseif op == "MOD" then
            comment = string.format("%s := %s %% %s", reg_str(A), rk_str(B), rk_str(C))
        elseif op == "POW" then
            comment = string.format("%s := %s ^ %s", reg_str(A), rk_str(B), rk_str(C))
        elseif op == "UNM" then
            comment = string.format("%s := -%s", reg_str(A), reg_str(B))
        elseif op == "NOT" then
            comment = string.format("%s := not %s", reg_str(A), reg_str(B))
        elseif op == "LEN" then
            comment = string.format("%s := #%s", reg_str(A), reg_str(B))
        elseif op == "CONCAT" then
            comment = string.format("%s := %s .. %s", reg_str(A), reg_str(B), reg_str(C))
        elseif op == "JMP" then
            comment = format_goto(pc + 1 + sBx)
        elseif op == "EQ" then
            comment = string.format("if (%s == %s) ~= %d then %s", rk_str(B), rk_str(C), A, format_goto(pc + 1))
        elseif op == "LT" then
            comment = string.format("if (%s < %s) ~= %d then %s", rk_str(B), rk_str(C), A, format_goto(pc + 1))
        elseif op == "LE" then
            comment = string.format("if (%s <= %s) ~= %d then %s", rk_str(B), rk_str(C), A, format_goto(pc + 1))
        elseif op == "TEST" then
            comment = string.format("if (%s) ~= %s then %s", reg_str(A), C ~= 0 and "true" or "false", format_goto(pc + 1))
        elseif op == "TESTSET" then
            comment = string.format("if (%s) ~= %s then %s else %s := %s",
                       reg_str(B), C ~= 0 and "true" or "false", format_goto(pc + 1), reg_str(A), reg_str(B))
        elseif op == "CALL" then
            local nargs = B-1
            local nres = C-1
            local args = {}
            for i=1, nargs do
                args[#args+1] = reg_str(A+1 + i-1)
            end
            
            local res_str = ""
            if nres > 0 then
                if reg_str(A) ~= reg_str(A+nres-1) then
                    res_str = string.format("%s, ..., %s := ", reg_str(A), reg_str(A+nres-1))
                else
                    res_str = string.format("%s := ", reg_str(A), reg_str(A+nres-1))
                end
            elseif nres < 0 then
                res_str = string.format("%s, ... := ", reg_str(A))
            end
            
            comment = string.format("%s%s(%s)", res_str, reg_str(A), table.concat(args, ", "))
        elseif op == "TAILCALL" then
            local args = {}
            for i=1, B-1 do args[#args+1] = reg_str(A+1+i-1) end
            comment = string.format("return %s(%s)", reg_str(A), table.concat(args, ", "))
        elseif op == "RETURN" then
            if B > 0 then
                local returns = {}
                for i=0, B-2 do returns[#returns+1] = reg_str(A+i) end
                comment = string.format("return %s", table.concat(returns, ", "))
            else comment = "return" end
        elseif op == "FORLOOP" then
            comment = string.format("%s += %s; if %s <= %s then %s", 
                       reg_str(A+1), reg_str(A+2), reg_str(A+1), reg_str(A), format_goto(pc + 1 + sBx))
        elseif op == "FORPREP" then
            comment = string.format("%s -= %s; %s", reg_str(A), reg_str(A+2), format_goto(pc + 1 + sBx))
        elseif op == "TFORLOOP" then
            local results = {}
            for i=3, 2+C do results[#results+1] = reg_str(A+i) end
            comment = string.format("%s := %s(%s, %s); if %s ~= nil then %s := %s else %s",
                       table.concat(results, ", "), reg_str(A), reg_str(A+1), reg_str(A+2),
                       reg_str(A+3), reg_str(A+2), reg_str(A+3), format_goto(pc + 1))
        elseif op == "SETLIST" then
            local start_idx = (C-1)*FPF + 1
            comment = string.format("%s[%d..%d] := %s..%s", 
                       reg_str(A), start_idx, start_idx+B-1, reg_str(A+1), reg_str(A+B))
        elseif op == "CLOSE" then
            comment = string.format("close up to %s", reg_str(A))
        elseif op == "CLOSURE" then
            local proto = f.Protos[Bx]
            local proto_name = proto.Name ~= "" and proto.Name or proto.Identifier
            comment = string.format("%s := closure(%s)", reg_str(A), proto_name)
            if proto.UpvalueCount > 0 then
                comment = comment .. string.format(" with %d upvalues", proto.UpvalueCount)
            end
        elseif op == "VARARG" then
            if B > 0 then
                comment = string.format("%s..%s = vararg", reg_str(A), reg_str(A+B-1))
            else
                comment = "vararg..."
            end
        end
    
        return comment
    end

    local function dump_instructions(f, file)
        start_block("instr")
        
        local max_idx = f.Instructions.Count
        local max_offset = (max_idx - 1) * file.InstructionSize
        local idx_width = math.floor(math.log10(max_idx)) + 1
        local offset_width = string.format("%X", max_offset):len()
        local line_width = 0
        for i = 1, f.Instructions.Count do
            local instr = f.Instructions[i-1]
            instr.LineNumber = nil
            line_width = math.max(line_width, instr.LineNumber or 0)
        end
        line_width = math.floor(math.log10(line_width)) + 1

        indent = indent - 1
        
        print(string.format(";%s%s %s %s%-9s  %s %s %s", (" "):rep(idx_width),
            string.format("%-"..idx_width.."s", "idx"):upper(),
            string.format("%-"..(offset_width + 3).."s", "offset"):upper(),
            (line_width > 0 and string.format("%-"..line_width.."s ", "line"):upper() or ""),
            "OPCODE", "A    ", "B    ", "C"))
        indent = indent + 1

        local function format_param(param_type, value)
            if param_type == 0 then -- Unused/Arbitrary
                return string.format(" %d", value)
            elseif param_type == 1 then -- Register
                return string.format("R%d", value)
            elseif param_type == 2 then -- Constant
                return string.format("K%d", value)
            elseif param_type == 3 then -- Constant/Register
                if value >= 256 then
                    return string.format("K%d", value - 256)
                else
                    return string.format("R%d", value)
                end
            elseif param_type == 4 then -- Upvalue
                return string.format("U%d", value)
            elseif param_type == 5 then -- Jump Distance
                return string.format("J%d", value)
            else
                return tostring(value)
            end
        end

        for i = 1, f.Instructions.Count do
            local instr = f.Instructions[i-1]
            local offset = (i-1) * file.InstructionSize
            local pc = i-1
            
            local idx_fmt = "%0"..idx_width.."d"
            local offset_fmt = "/x%0"..offset_width.."X/"
            local line_fmt = "(%0"..line_width.."d)"
            
            local idx = string.format(idx_fmt, i)
            local offset_str = string.format(offset_fmt, offset)
            local line = instr.LineNumber and string.format(line_fmt, instr.LineNumber or 0) or nil
            local comment = get_opcode_comment(instr, f, pc)

            local a, b, c = "", "", "-"
            local params = instr.OpcodeParams
            if instr.OpcodeType == "ABC" then
                a = format_param(params[1], instr.A)
                b = format_param(params[2], instr.B)
                c = format_param(params[3], instr.C)
            elseif instr.OpcodeType == "ABx" then
                a = format_param(params[1], instr.A)
                b = format_param(params[2], instr.Bx)
                c = " -"
            elseif instr.OpcodeType == "AsBx" then
                a = format_param(params[1], instr.A)
                b = format_param(params[2], instr.sBx)
                c = " -"
            end

            print(string.format("%s %s %s%-9s  %s  %s  %s    ; %s",
                idx, offset_str, (line and line.." " or ""), instr.Opcode:upper(), LeftJustify(a, 4), LeftJustify(b, 4), LeftJustify(c, 4), comment))
        end
        
        end_block()
    end

    local function dump_proto(f, is_main)
        local block_type = is_main and "main" or "proto"
        
        if not is_main then
            local proto_name = f.Name ~= "" and f.Name or f.Identifier

            local params = {}
            for i = 1, f.ArgumentCount do
                if f.Locals and (i-1) < f.Locals.Count then
                    local local_var = f.Locals[i-1]
                    params[#params + 1] = local_var.Name or "?"
                else
                    params[#params + 1] = "?"
                end
            end
            if f.Vararg then
                params[#params + 1] = "..."
            end
            local params_str = table.concat(params, ", ")

            local instr_count = f.Instructions and f.Instructions.Count or 0
            local proto_size = instr_count * file.InstructionSize

            print("; function " .. proto_name .. "(" .. params_str .. ") " .. proto_size .. " bytes")
        end

        start_block(block_type)
        
        local keys = { "source", "lines", "upvalues", "params", "maxstack" }
        calculate_padding(block_type, keys)
        
        if f.Name and f.Name ~= "" then
            kv("source", format_lua_string(f.Name))
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
                kv(i <= f.ArgumentCount and "param" or "local", format_lua_string(l.Name), (i-1))
            end
        end
        
        if f.Constants and f.Constants.Count > 0 then
            print("")
            for i = 1, f.Constants.Count do
                local const = f.Constants[i-1]
                kv("const", format_constant(const), (i-1))
            end
        end
        
        if f.Upvalues and f.Upvalues.Count > 0 then
            print("")
            for i = 1, f.Upvalues.Count do
                local upv = f.Upvalues[i-1]
                kv("upval", upv.Name and format_lua_string(upv.Name) or tostring(i-1), (i-1))
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
            dump_instructions(f, file)
        end
        
        end_block()
    end

    start_block("header")
    local header_keys = { "signature", "version", "format", "endianness", "int", "size_t", "instr", "number", "integral" }
    calculate_padding("header", header_keys)
    
    kv("signature", format_lua_string(file.Identifier))
    kv("version", string.format("0x%02x", file.Version))
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
    
    dump_proto(file.Main, true)
    
    local end_time = os.clock()

    local function timestamp()
        local date_table = os.date("*t")
        return string.format(
            "%04d %02d %02d %02d:%02d:%02d",
            date_table.year,
            date_table.month,
            date_table.day,
            date_table.hour,
            date_table.min,
            date_table.sec
        )
    end

    table.insert(buffer, 1, "") -- newline
    table.insert(buffer, 1, string.format("; md5 hash %s", file.Checksum))
    table.insert(buffer, 1, string.format("; generation time %.5fs", end_time-start_time))
    table.insert(buffer, 1, string.format("; timestamp %s", timestamp()))
    table.insert(buffer, 1, string.format("; source %s", file.Main.Name))

    table.insert(buffer, 1, "") -- newline
    
    table.insert(buffer, 1, string.format("; generated by Retrospect %s", _VERSION))
    table.insert(buffer, 1, "; lua 5.1 bytecode disassembly listing")
    _print(table.concat(buffer, "\n"))
end

return Listing