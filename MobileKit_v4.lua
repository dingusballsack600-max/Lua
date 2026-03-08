-- ============================================================
--  MobileKit v2.0 | Mobile-Friendly Exploit GUI
--  Features: ScriptScanner, Downloader, RSpy, HTTPSpy, Deobfuscator
--  Properly uses executor decompile APIs (UNC standard)
--  decompile() / syn.decompile / getscriptbytecode fallbacks
-- ============================================================

-- ============================================================
--  SERVICES & LOCALS
-- ============================================================

local Players      = game:GetService("Players")
local TweenService = game:GetService("TweenService")
local UIS          = game:GetService("UserInputService")
local HttpService  = game:GetService("HttpService")
local lp           = Players.LocalPlayer

-- ============================================================
--  EXECUTOR API DETECTION
--  Detects which decompile/source functions are available
-- ============================================================

local ENV = getfenv and getfenv() or {}

-- bit32 polyfill for executors / Luau contexts where it's absent
if not bit32 then
    bit32 = {
        bxor = function(a, b)
            local r, m = 0, 1
            for _ = 1, 32 do
                local ra, rb = a % 2, b % 2
                if ra ~= rb then r = r + m end
                a, b, m = (a - ra) / 2, (b - rb) / 2, m * 2
            end
            return r
        end,
        band = function(a, b)
            local r, m = 0, 1
            for _ = 1, 32 do
                local ra, rb = a % 2, b % 2
                if ra == 1 and rb == 1 then r = r + m end
                a, b, m = (a - ra) / 2, (b - rb) / 2, m * 2
            end
            return r
        end,
        bor = function(a, b)
            local r, m = 0, 1
            for _ = 1, 32 do
                local ra, rb = a % 2, b % 2
                if ra == 1 or rb == 1 then r = r + m end
                a, b, m = (a - ra) / 2, (b - rb) / 2, m * 2
            end
            return r
        end,
        rshift = function(a, n) return math.floor(a / 2^n) end,
        lshift = function(a, n) return a * 2^n end,
    }
end

-- task polyfill for executors that don't expose it
if not task then
    task = {
        spawn  = function(f, ...) return coroutine.wrap(f)(...) end,
        delay  = function(t, f, ...) 
            local args = {...}
            spawn(function() wait(t); f(table.unpack(args)) end)
        end,
        wait   = wait or function(n) return wait(n) end,
    }
end

-- Primary decompile function (UNC standard: decompile(script) -> string)
-- Fallbacks: syn.decompile, syn_decompile, getscriptbytecode (raw bytecode)
local function getDecompiler()
    if type(ENV.decompile) == "function" then
        return ENV.decompile, "decompile"
    elseif type(ENV.syn) == "table" and type(ENV.syn.decompile) == "function" then
        return ENV.syn.decompile, "syn.decompile"
    elseif type(ENV.syn_decompile) == "function" then
        return ENV.syn_decompile, "syn_decompile"
    elseif type(ENV.getscriptbytecode) == "function" then
        -- bytecode only, not human-readable source
        return ENV.getscriptbytecode, "getscriptbytecode (bytecode only)"
    end
    return nil, "none"
end

-- Get all running scripts (UNC: getscripts / getrunningscripts)
local function getScriptsAPI()
    if type(ENV.getscripts) == "function" then
        return ENV.getscripts(), "getscripts"
    elseif type(ENV.syn_getscripts) == "function" then
        return ENV.syn_getscripts(), "syn_getscripts"
    elseif type(ENV.getrunningscripts) == "function" then
        return ENV.getrunningscripts(), "getrunningscripts"
    end
    return nil, "none"
end

-- Get script environment (to check if running)
local function getSenvAPI(scr)
    if type(ENV.getsenv) == "function" then
        return pcall(ENV.getsenv, scr)
    elseif type(ENV.syn_getsenv) == "function" then
        return pcall(ENV.syn_getsenv, scr)
    end
    return false, nil
end

-- File system
local FS = {
    write  = ENV.writefile,
    read   = ENV.readfile,
    mkdir  = ENV.makefolder,
    exists = ENV.isfile or ENV.isfolder,
    list   = ENV.listfiles,
}
local hasFS = FS.write and FS.mkdir

-- Clipboard
local function copyToClipboard(text)
    if ENV.setclipboard then ENV.setclipboard(text)
    elseif ENV.toclipboard then ENV.toclipboard(text)
    elseif ENV.syn and ENV.syn.clipboard_set then ENV.syn.clipboard_set(text)
    end
end

-- ============================================================
--  THEME
-- ============================================================

local T = {
    BG      = Color3.fromRGB(13, 13, 18),
    SURFACE = Color3.fromRGB(20, 20, 28),
    CARD    = Color3.fromRGB(28, 28, 40),
    CARD2   = Color3.fromRGB(35, 35, 50),
    BORDER  = Color3.fromRGB(48, 48, 68),
    ACCENT  = Color3.fromRGB(110, 85, 255),
    TEAL    = Color3.fromRGB(0, 210, 185),
    RED     = Color3.fromRGB(255, 65, 65),
    GREEN   = Color3.fromRGB(55, 220, 110),
    YELLOW  = Color3.fromRGB(255, 195, 45),
    ORANGE  = Color3.fromRGB(255, 140, 40),
    TEXT    = Color3.fromRGB(228, 228, 240),
    DIM     = Color3.fromRGB(130, 130, 155),
}

local FB  = Enum.Font.GothamMedium
local FBB = Enum.Font.GothamBold
local FM  = Enum.Font.Code

-- ============================================================
--  UI HELPERS
-- ============================================================

local function tw(obj, props, t, sty, dir)
    TweenService:Create(obj, TweenInfo.new(t or 0.22, sty or Enum.EasingStyle.Quart, dir or Enum.EasingDirection.Out), props):Play()
end

local function corner(p, r) local c=Instance.new("UICorner"); c.CornerRadius=UDim.new(0,r or 8); c.Parent=p; return c end
local function stroke(p, col, th) local s=Instance.new("UIStroke"); s.Color=col or T.BORDER; s.Thickness=th or 1; s.Parent=p; return s end
local function pad(p, a, t, b, l, r)
    local u=Instance.new("UIPadding")
    u.PaddingTop=UDim.new(0,t or a or 0); u.PaddingBottom=UDim.new(0,b or a or 0)
    u.PaddingLeft=UDim.new(0,l or a or 0); u.PaddingRight=UDim.new(0,r or a or 0)
    u.Parent=p; return u
end
local function lbl(p, txt, sz, col, font, xa)
    local l=Instance.new("TextLabel"); l.Text=txt; l.TextSize=sz or 13; l.TextColor3=col or T.TEXT
    l.Font=font or FB; l.BackgroundTransparency=1; l.TextXAlignment=xa or Enum.TextXAlignment.Left
    l.TextWrapped=true; l.Size=UDim2.new(1,0,0,(sz or 13)+6); l.Parent=p; return l
end
local function hlist(p, gap)
    local l=Instance.new("UIListLayout"); l.FillDirection=Enum.FillDirection.Horizontal
    l.SortOrder=Enum.SortOrder.LayoutOrder; l.Padding=UDim.new(0,gap or 6); l.Parent=p; return l
end
local function vlist(p, gap)
    local l=Instance.new("UIListLayout"); l.SortOrder=Enum.SortOrder.LayoutOrder
    l.Padding=UDim.new(0,gap or 6); l.Parent=p; return l
end

local function btn(p, txt, col, sz)
    local b=Instance.new("TextButton"); b.Text=txt; b.TextSize=sz or 13; b.Font=FBB
    b.TextColor3=T.TEXT; b.BackgroundColor3=col or T.ACCENT; b.Size=UDim2.new(1,0,0,42)
    b.AutoButtonColor=false; corner(b,8); b.Parent=p
    b.MouseEnter:Connect(function() tw(b,{BackgroundTransparency=0.18},0.12) end)
    b.MouseLeave:Connect(function() tw(b,{BackgroundTransparency=0},0.12) end)
    return b
end

local function scroll(p, h)
    local s=Instance.new("ScrollingFrame"); s.Size=UDim2.new(1,0,0,h or 200)
    s.BackgroundColor3=T.CARD; s.BorderSizePixel=0; s.ScrollBarThickness=3
    s.ScrollBarImageColor3=T.ACCENT; s.CanvasSize=UDim2.new(0,0,0,0)
    s.AutomaticCanvasSize=Enum.AutomaticSize.Y; corner(s,8); s.Parent=p; return s
end

local function chip(p, txt, col)
    local f=Instance.new("Frame"); f.BackgroundColor3=col or T.ACCENT
    f.Size=UDim2.new(0,#txt*7+10,0,19); corner(f,4); f.Parent=p
    local l=Instance.new("TextLabel"); l.Text=txt; l.TextSize=10; l.Font=FBB
    l.TextColor3=T.TEXT; l.BackgroundTransparency=1; l.Size=UDim2.new(1,0,1,0)
    l.TextXAlignment=Enum.TextXAlignment.Center; l.Parent=f; return f
end

local function divider(p)
    local f=Instance.new("Frame"); f.Size=UDim2.new(1,0,0,1); f.BackgroundColor3=T.BORDER
    f.BorderSizePixel=0; f.Parent=p; return f
end

local function row(p, h)
    local f=Instance.new("Frame"); f.Size=UDim2.new(1,0,0,h or 42)
    f.BackgroundTransparency=1; f.Parent=p; return f
end

-- ============================================================
--  OBFUSCATION DETECTION
-- ============================================================

local OBF_SIGS = {
    {n="Luraph",       p="local%s+[%w_]+%s*=%s*{[%d,%-%s]+}%s*local%s+[%w_]+%s*=%s*{"},
    {n="Ironbrew 2",   p='local%s+[%w_]+%s*=%s*"[A-Za-z0-9+/=]{40,}"'},
    {n="Moonsec v2",   p="local%s+[%w_]+;[%s\n]*for%s+[%w_]+%s*=%s*1"},
    {n="Moonsec v3",   p="local%s+[%w_]+%s*=%s*table%.concat"},
    {n="Prometheus",   p="local%s+[%w_]+%s*=%s*{%s*\"[^\"]+\"%s*,"},
    {n="PSU",          p="loadstring%(game:HttpGet"},
    {n="Bytecode",     p="\\%d%d%d\\%d%d%d\\%d%d%d"},
    {n="VM Loader",    p="local%s+[%w_]+%s*=%s*load%("},
    {n="Obfusc8",      p="[%w_]+%([%w_]+%([%w_]+%([%w_]+%([%w_]+%("},
    {n="Generic B64",  p="[A-Za-z0-9+/=]{80,}"},
    {n="Junk inject",  p="local%s+[a-z][A-Z][a-z]%d%s*="},
    {n="String XOR",   p="bit32%.bxor%([%w_]+%(%s*[%w_]+%s*,%s*[%w_]+%s*%)"},
}

local function entropy(s)
    local freq, n = {}, math.min(#s, 800)
    for i = 1, n do
        local c = s:sub(i,i); freq[c] = (freq[c] or 0) + 1
    end
    local h = 0
    for _, v in pairs(freq) do
        local p = v/n; h = h - p*math.log(p,2)
    end
    return h
end

local function detectObf(src)
    if not src or #src == 0 then return false, "empty" end
    if src:find("^<roblox") then return false, "XML asset" end
    for _, sig in ipairs(OBF_SIGS) do
        if src:match(sig.p) then return true, sig.n end
    end
    if entropy(src) > 5.2 then
        return true, string.format("High entropy (%.2f bits)", entropy(src))
    end
    local total, readable = 0, 0
    for line in src:gmatch("[^\n]+") do
        total = total + 1
        if line:match("[a-zA-Z_][a-zA-Z0-9_]*%s*[=%(]") then readable = readable + 1 end
    end
    if total > 10 and (readable/total) < 0.15 then
        return true, "Low readability ratio"
    end
    return false, nil
end

-- ============================================================
--  STUB DETECTION (Konstant V2.x aware)
-- ============================================================

local STUB_HARD = {
    "^KONSTANTERROR:", "KONSTANTERROR: After:", "Unknown constant type",
    "^%-%-? ?[Ff]ailed to decompile", "failed to decompile bytecode",
    "Too Many Requests", "Decompilation failed", "decompilation failed",
    "cannot decompile", "Cannot decompile", "unsupported bytecode",
    "bytecode version not supported", "unable to decompile", "^%s*$",
}

local function countKLines(src)
    local total, klines = 0, 0
    for line in src:gmatch("[^\n]+") do
        local t = line:match("^%s*(.-)%s*$")
        if t ~= "" then
            total = total + 1
            if t == "K" or t:match("^K+$") then klines = klines + 1 end
        end
    end
    return total, klines
end

local function isStub(src)
    if not src or #src == 0 then return true, "empty" end
    for _, pat in ipairs(STUB_HARD) do
        if src:match(pat) then return true, "decompiler error stub" end
    end
    local total, klines = countKLines(src)
    if total > 0 and (klines/total) >= 0.4 then
        return true, string.format("Konstant K-spam (%d/%d lines)", klines, total)
    end
    if #src < 100 and not src:match("local%s") and not src:match("function")
       and not src:match("return") and not src:match("=") then
        return true, "tiny non-Lua content ("..#src.."B)"
    end
    return false, nil
end

-- ============================================================
--  DEOBFUSCATOR v4
--  14 source passes + runtime constant dump + debug line hooks
--  + GC memory scan + loadstring/require interception
-- ============================================================

local function b64decode(enc)
    local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    enc = enc:gsub('[^'..b..'=]', '')
    return (enc:gsub('.', function(x)
        if x == '=' then return '' end
        local r, f = '', (b:find(x)-1)
        for i = 6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
        return r
    end):gsub('%d%d%d%d%d%d%d%d', function(x)
        local c = tonumber(x,2)
        return (c>=32 and c<=126) and string.char(c) or ''
    end))
end

local function xorStr(data, key)
    if #key == 0 then return data end
    local res = {}
    for i=1,#data do
        res[i] = string.char(bit32.bxor(data:byte(i), key:byte(((i-1)%#key)+1)))
    end
    return table.concat(res)
end

local function escapePat(s)
    return s:gsub("([%(%)%.%%%+%-%*%?%[%^%$])", "%%%1")
end

-- Lua keyword frequency scorer — higher = more Lua-like
local LUA_KEYWORDS = {
    "local","function","return","end","if","then","else","elseif",
    "for","do","while","repeat","until","break","not","and","or",
    "nil","true","false","in","pairs","ipairs","type","tostring"
}
local function luaLikeness(s)
    local score = 0
    for _, kw in ipairs(LUA_KEYWORDS) do
        local _, count = s:gsub('%f[%w]'..kw..'%f[%W]', '')
        score = score + (count or 0)
    end
    return score
end

-- ── Lightweight tokenizer for constant-folding & dead code ──
-- Returns list of {type, value} tokens
local function tokenize(src)
    local tokens = {}
    local i = 1
    while i <= #src do
        -- skip whitespace
        local ws = src:match("^%s+", i)
        if ws then i = i + #ws

        -- long string/comment
        elseif src:match("^%-%-%[%[", i) then
            local e = src:find("%]%]", i+4)
            if e then i = e+2 else i = #src+1 end

        -- line comment
        elseif src:match("^%-%-", i) then
            local e = src:find("\n", i)
            i = e and e+1 or #src+1

        -- string literal
        elseif src:match('^"', i) then
            local s2, j = src:match('^("(?:[^"\\]|\\.)*")()', i)
            if s2 then
                table.insert(tokens, {t="str", v=s2:sub(2,-2)})
                i = j
            else i = i+1 end

        elseif src:match("^'", i) then
            local s2, j = src:match("^('(?:[^'\\]|\\.)*')()", i)
            if s2 then
                table.insert(tokens, {t="str", v=s2:sub(2,-2)})
                i = j
            else i = i+1 end

        -- number
        elseif src:match("^%d", i) then
            local n, j = src:match("^(%d+%.?%d*)()", i)
            table.insert(tokens, {t="num", v=tonumber(n)})
            i = j

        -- identifier/keyword
        elseif src:match("^[%a_]", i) then
            local w, j = src:match("^([%a_][%w_]*)()", i)
            table.insert(tokens, {t="id", v=w})
            i = j

        -- operator/punctuation
        else
            table.insert(tokens, {t="op", v=src:sub(i,i)})
            i = i+1
        end
    end
    return tokens
end

-- ── Constant folding on tokens ───────────────────────────────
-- Evaluates simple arithmetic / concat of literals
local function foldTokens(tokens)
    local changed = true
    while changed do
        changed = false
        local out = {}
        local i = 1
        while i <= #tokens do
            local t = tokens[i]
            -- num OP num
            if i+2 <= #tokens
               and tokens[i].t == "num"
               and tokens[i+1].t == "op"
               and tokens[i+2].t == "num" then
                local a, op, b = tokens[i].v, tokens[i+1].v, tokens[i+2].v
                local res
                if op == "+" then res = a+b
                elseif op == "-" then res = a-b
                elseif op == "*" then res = a*b
                elseif op == "/" and b ~= 0 then res = a/b
                elseif op == "%" and b ~= 0 then res = a%b
                end
                if res then
                    table.insert(out, {t="num", v=res})
                    i = i+3; changed = true
                    goto continue
                end
            end
            -- str .. str
            if i+2 <= #tokens
               and tokens[i].t == "str"
               and tokens[i+1].t == "op" and tokens[i+1].v == "."
               and i+3 <= #tokens
               and tokens[i+2].t == "op" and tokens[i+2].v == "."
               and tokens[i+3].t == "str" then
                table.insert(out, {t="str", v=tokens[i].v..tokens[i+3].v})
                i = i+4; changed = true
                goto continue
            end
            table.insert(out, t)
            i = i+1
            ::continue::
        end
        tokens = out
    end
    return tokens
end

-- Reconstruct source from folded tokens (simplified)
local function tokensToHints(tokens)
    local hints = {}
    for _, tok in ipairs(tokens) do
        if tok.t == "str" and #tok.v > 2 then
            table.insert(hints, '"'..tok.v..'"')
        elseif tok.t == "num" then
            table.insert(hints, tostring(tok.v))
        end
    end
    return hints
end

-- ── XOR brute force (1–4 byte keys) ─────────────────────────
local COMMON_XOR_KEYS = {
    "KEY","XOR","ENC","SEC","OBF","LUA","RBX","SCR",
    "\x01","\x02","\x03","\x05","\x07","\x0F","\xFF",
    "A","B","X","K","k","x","s",
    "AB","CD","EF","XY","KK","LU","RB",
    "ABC","XYZ","KEY","ENC","OBF","LUA",
}

local function xorBruteForce(ciphertext)
    if #ciphertext < 8 then return nil, nil end
    local bestKey, bestScore = nil, -1
    for _, key in ipairs(COMMON_XOR_KEYS) do
        local decoded = xorStr(ciphertext, key)
        if not decoded:match("[%z\1-\8\11\12\14-\31]") then
            local score = luaLikeness(decoded) - entropy(decoded)*0.5
            if score > bestScore then
                bestScore = score
                bestKey = key
            end
        end
    end
    -- also try single-byte brute force 0x01–0xFF
    for byte = 1, 255 do
        local key = string.char(byte)
        local decoded = xorStr(ciphertext, key)
        if not decoded:match("[%z\1-\8\11\12\14-\31]") then
            local score = luaLikeness(decoded) - entropy(decoded)*0.5
            if score > bestScore then
                bestScore = score
                bestKey = key
            end
        end
    end
    if bestKey and bestScore > 2 then
        return xorStr(ciphertext, bestKey), bestKey
    end
    return nil, nil
end

-- ── GC memory scan ───────────────────────────────────────────
local function gcScanStrings(minLen, maxLen)
    local found = {}
    if not (ENV.getgc) then return found end
    local ok, gc = pcall(ENV.getgc)
    if not ok or type(gc) ~= "table" then return found end
    local seen = {}
    for _, v in ipairs(gc) do
        if type(v) == "string" and #v >= (minLen or 4) and #v <= (maxLen or 300) then
            if not seen[v] and not v:match("[%z\1-\8\11\12\14-\31]") then
                seen[v] = true
                table.insert(found, v)
            end
        elseif type(v) == "function" then
            -- try to get proto constants
            if ENV.getconsts then
                local ok2, consts = pcall(ENV.getconsts, v)
                if ok2 and type(consts) == "table" then
                    for _, c in ipairs(consts) do
                        if type(c) == "string" and #c >= (minLen or 4)
                           and not seen[c] and not c:match("[%z\1-\8\11\12\14-\31]") then
                            seen[c] = true
                            table.insert(found, "[fn const] "..c)
                        end
                    end
                end
            end
        end
    end
    return found
end

-- ── Iterate proto tree (getprotos) ───────────────────────────
local function dumpProtoTree(fn, depth, out)
    depth = depth or 0
    out = out or {}
    if depth > 8 then return out end
    if not ENV.getprotos then return out end
    local ok, protos = pcall(ENV.getprotos, fn)
    if not ok or type(protos) ~= "table" then return out end
    for _, proto in ipairs(protos) do
        -- get constants from each inner function
        if ENV.getconsts then
            local ok2, consts = pcall(ENV.getconsts, proto)
            if ok2 and type(consts) == "table" then
                for _, c in ipairs(consts) do
                    if type(c) == "string" and #c >= 3
                       and not c:match("[%z\1-\8\11\12\14-\31]") then
                        table.insert(out, string.rep("  ", depth).."proto["..depth.."]: \""..c:sub(1,100).."\"")
                    end
                end
            end
        end
        -- upvalues
        if ENV.getupvals or (debug and debug.getupvalues) then
            local upFn = ENV.getupvals or debug.getupvalues
            local ok3, ups = pcall(upFn, proto)
            if ok3 and type(ups) == "table" then
                for k, v in pairs(ups) do
                    if type(v) == "string" and #v >= 3
                       and not v:match("[%z\1-\8\11\12\14-\31]") then
                        table.insert(out, string.rep("  ",depth).."upval "..tostring(k)..": \""..v:sub(1,100).."\"")
                    end
                end
            end
        end
        dumpProtoTree(proto, depth+1, out)
    end
    return out
end

-- ── debug.sethook line tracer ─────────────────────────────────
local function runWithLineTrace(fn, env, maxLines)
    maxLines = maxLines or 300
    local lines = {}
    local lineCount = 0
    if debug and debug.sethook then
        debug.sethook(function(event)
            lineCount = lineCount + 1
            if lineCount <= maxLines then
                local info = debug.getinfo and debug.getinfo(2, "Sl")
                if info then
                    table.insert(lines, string.format("line %d (src:%s)",
                        info.currentline or 0,
                        tostring(info.short_src or "?"):sub(1,30)))
                end
            else
                debug.sethook()  -- stop tracing after limit
            end
        end, "l")
    end
    if env and setfenv then pcall(setfenv, fn, env) end
    local ok, err = pcall(fn)
    if debug and debug.sethook then pcall(debug.sethook) end
    return ok, err, lines
end

-- ── Main deobfuscate function ─────────────────────────────────
local function deobfuscate(src)
    local logs  = {}
    local dumped = {}
    local function log(msg, tag)
        table.insert(logs, {msg=msg, tag=tag or "info"})
    end

    log("=== MobileKit Deobfuscator v4 ===", "title")
    local isObf, engine = detectObf(src)
    if not isObf then
        log("Source appears clean — no obfuscation detected.", "ok")
        return {cleaned=src, logs=logs, success=true, dumped=dumped}
    end
    log("Engine detected: "..(engine or "Unknown"), "warn")
    log("Starting 14-pass source analysis + runtime extraction...", "accent")

    local s = src

    -- ── PASS 1: Strip comments ────────────────────────────────
    s = s:gsub("%-%-[^\n]*", "")
    log("Pass 1: Stripped inline comments.")

    -- ── PASS 2: Numeric escape decode  \65 \097 ──────────────
    local n2 = 0
    s = s:gsub("\\(%d%d?%d?)", function(n)
        local c = tonumber(n)
        if c and c>=32 and c<=126 then n2=n2+1; return string.char(c) end
        return "\\"..n
    end)
    if n2>0 then log("Pass 2: Decoded "..n2.." numeric escape(s).") end

    -- ── PASS 3: Hex escape decode  \x41 ─────────────────────
    local n3 = 0
    s = s:gsub("\\x(%x%x)", function(h)
        local c = tonumber(h,16)
        if c and c>=32 and c<=126 then n3=n3+1; return string.char(c) end
        return "\\x"..h
    end)
    if n3>0 then log("Pass 3: Decoded "..n3.." hex escape(s).") end

    -- ── PASS 4: Base64 string literal decode ─────────────────
    local n4 = 0
    s = s:gsub('"([A-Za-z0-9+/=]+)"', function(enc)
        if #enc >= 16 and #enc%4 == 0 then
            local ok, dec = pcall(b64decode, enc)
            if ok and dec and #dec>0
               and not dec:match("[%z\1-\8\11\12\14-\31]")
               and #dec < #enc then
                n4=n4+1; return '"'..dec:gsub('"','\\"')..'"'
            end
        end
        return '"'..enc..'"'
    end)
    if n4>0 then log("Pass 4: Decoded "..n4.." base64 string(s).") end

    -- ── PASS 5: string.char() collapse ───────────────────────
    local n5 = 0
    s = s:gsub("string%.char%(([%d,%s]+)%)", function(args)
        local chars, valid = {}, true
        for n in args:gmatch("%d+") do
            local c = tonumber(n)
            if c and c>=32 and c<=126 then chars[#chars+1]=string.char(c)
            else valid=false; break end
        end
        if valid and #chars>0 then
            n5=n5+1; return '"'..table.concat(chars):gsub('"','\\"')..'"'
        end
        return "string.char("..args..")"
    end)
    if n5>0 then log("Pass 5: Collapsed "..n5.." string.char() call(s).") end

    -- ── PASS 6: Constant folding via tokenizer ────────────────
    log("Pass 6: Constant folding...", "dim")
    local ok6, toks = pcall(tokenize, s)
    if ok6 then
        local folded = foldTokens(toks)
        local hints = tokensToHints(folded)
        if #hints > 0 then
            log("Pass 6: Folded "..#hints.." constant expression(s).", "ok")
            for _, h in ipairs(hints) do
                table.insert(dumped, "folded: "..h)
            end
        end
        -- Rebuild numeric literals in source (safer than full reconstruction)
        s = s:gsub("(%d+)%s*([%+%-%*/%%])%s*(%d+)", function(a, op, b)
            local av, bv = tonumber(a), tonumber(b)
            if av and bv then
                local res
                if op=="+" then res=av+bv
                elseif op=="-" then res=av-bv
                elseif op=="*" then res=av*bv
                elseif op=="/" and bv~=0 then res=av/bv
                elseif op=="%" and bv~=0 then res=av%bv
                end
                if res then return tostring(res) end
            end
            return a..op..b
        end)
    end

    -- ── PASS 7: XOR decode — known keys + brute force ────────
    log("Pass 7: XOR string detection (known keys + 1-byte brute force)...", "dim")
    local n7 = 0
    -- First try nearby declared keys
    local knownKeys = {}
    for kvar, kval in s:gmatch('local%s+([%w_]+)%s*=%s*"([^"]{2,32})"') do
        if #kval>=2 and #kval<=32 then knownKeys[kvar] = kval end
    end
    for encVar, encVal in s:gmatch('local%s+([%w_]+)%s*=%s*"([^"]{8,})"') do
        if entropy(encVal) > 4.5 then
            -- try known keys first
            local decoded, usedKey = nil, nil
            for _, kval in pairs(knownKeys) do
                local d = xorStr(encVal, kval)
                if entropy(d)<3.8 and not d:match("[%z\1-\8\11\12\14-\31]") then
                    decoded, usedKey = d, kval; break
                end
            end
            -- then brute force
            if not decoded then
                decoded, usedKey = xorBruteForce(encVal)
            end
            if decoded and usedKey then
                local safe = decoded:gsub('"','\\"')
                s = s:gsub('%f[%w_]'..escapePat(encVar)..'%f[^%w_]', '"'..safe..'"')
                n7=n7+1
                log("Pass 7: XOR-decoded "..encVar.." (key=\""..usedKey:gsub("[^%g]","?").."\")", "ok")
            end
        end
    end
    if n7==0 then log("Pass 7: No XOR-encoded strings found.") end

    -- ── PASS 8: Single-assignment constant inlining ───────────
    local n8, consts8 = 0, {}
    for k, v in s:gmatch('local%s+([%w_]+)%s*=%s*"([^"]*)"') do
        if #v>0 and #v<300 then consts8[k]=v end
    end
    for k, v in pairs(consts8) do
        local pat = '%f[%w_]'..escapePat(k)..'%f[^%w_]'
        local n; s, n = s:gsub(pat, '"'..v:gsub('%%','%%%%')..'"')
        n8=n8+(n or 0)
    end
    if n8>0 then log("Pass 8: Inlined "..n8.." string constant(s).") end

    -- ── PASS 9: Opaque predicate / trivial condition removal ──
    local n9 = 0
    -- if (1 == 1) / if (true) / if not false
    s, n9 = s:gsub("if%s*%(?)%s*true%s*%)?%s*then", "do")
    s = s:gsub("if%s*%(?)%s*%d+%s*==%s*%d+%s*%)?%s*then", function(full)
        local a, b = full:match("(%d+)%s*==%s*(%d+)")
        if a and b and a==b then n9=n9+1; return "do" end
        return full
    end)
    s = s:gsub("if%s*%(?)%s*false%s*%)?%s*then.-%f[%a]end", function() n9=n9+1; return "" end)
    s = s:gsub("%(true%s+and%s+(.-)%)", function(v) n9=n9+1; return v end)
    s = s:gsub("%(false%s+or%s+(.-)%)", function(v) n9=n9+1; return v end)
    -- while (true) do break end -> remove
    s = s:gsub("while%s+%(?)%s*1%s*==%s*2%s*%)?%s*do.-%f[%a]end", function() n9=n9+1; return "" end)
    if n9>0 then log("Pass 9: Removed "..n9.." opaque predicate(s).") end

    -- ── PASS 10: Builtin + _G/_ENV alias unwrapping ───────────
    local BUILTINS = {
        tostring=1,tonumber=1,type=1,pairs=1,ipairs=1,next=1,
        select=1,rawget=1,rawset=1,rawequal=1,pcall=1,xpcall=1,
        setmetatable=1,getmetatable=1,unpack=1,error=1,assert=1,
        load=1,loadstring=1,require=1,
        ["string.byte"]=1,["string.char"]=1,["string.sub"]=1,
        ["string.len"]=1,["string.format"]=1,["string.rep"]=1,
        ["string.gsub"]=1,["string.match"]=1,["string.gmatch"]=1,
        ["table.insert"]=1,["table.remove"]=1,["table.concat"]=1,["table.sort"]=1,
        ["math.floor"]=1,["math.ceil"]=1,["math.abs"]=1,["math.max"]=1,["math.min"]=1,
        ["bit32.bxor"]=1,["bit32.band"]=1,["bit32.bor"]=1,["bit32.rshift"]=1,["bit32.lshift"]=1,
        ["_G"]=1,["_ENV"]=1,
    }
    local n10 = 0
    s = s:gsub("local%s+([%w_]+)%s*=%s*([%w_][%w_%.]*)[%s\n]", function(alias, orig)
        if BUILTINS[orig] then
            local pat = '%f[%w_]'..escapePat(alias)..'%f[^%w_]'
            local _, cnt = s:gsub(pat, orig)
            n10=n10+(cnt or 0)
            s = s:gsub(pat, orig)
            return ""
        end
        return "local "..alias.." = "..orig.."\n"
    end)
    -- also handle _G.someFunc pattern
    s = s:gsub("_G%.([%w_]+)", function(name)
        if BUILTINS[name] then n10=n10+1; return name end
        return "_G."..name
    end)
    if n10>0 then log("Pass 10: Unwrapped "..n10.." alias(es) (_G/_ENV aware).") end

    -- ── PASS 11: Prometheus/Moonsec string array decode ──────
    -- Handles both literal arrays AND loop-built arrays (simulation)
    local n11 = 0
    local strArrays = {}
    -- literal:  local _t = {"a","b","c"}
    for varname, body in s:gmatch('local%s+([%w_]+)%s*=%s*{(.-)}') do
        local strs, allStr = {}, true
        for str in body:gmatch('"([^"]*)"') do strs[#strs+1]=str end
        local stripped = body:gsub('"[^"]*"',''):gsub('[,%s]','')
        if #stripped==0 and #strs>=2 then
            strArrays[varname] = table.concat(strs)
        end
    end
    -- simulate loop-built:  t[i] = string.char(arr[i])
    for varname, body in s:gmatch('local%s+([%w_]+)%s*=%s*{(.-)}') do
        if not strArrays[varname] then
            local nums = {}
            local allNum = true
            for n in body:gmatch("(%d+)") do
                local c = tonumber(n)
                if c and c>=32 and c<=126 then nums[#nums+1]=string.char(c)
                else allNum=false; break end
            end
            if allNum and #nums>=4 then
                strArrays[varname] = table.concat(nums)
            end
        end
    end
    for varname, val in pairs(strArrays) do
        local pat1 = 'table%.concat%('..escapePat(varname)..'[^%)]*%)'
        local n; s, n = s:gsub(pat1, '"'..val:gsub('%%','%%%%')..'"')
        n11=n11+(n or 0)
        if n and n>0 then
            s = s:gsub('local%s+'..escapePat(varname)..'%s*=%s*{[^}]*}','')
        end
    end
    if n11>0 then log("Pass 11: Decoded "..n11.." Prometheus/Moonsec string array(s).") end

    -- ── PASS 12: Function inlining (simple wrappers) ──────────
    -- local f = function() return X end  ->  inline X at all f() call sites
    local n12 = 0
    s = s:gsub('local%s+([%w_]+)%s*=%s*function%s*%(%)%s*return%s+([^\n]+)%s*end', function(fname, retVal)
        retVal = retVal:gsub("%s+$","")
        local pat = '%f[%w_]'..escapePat(fname)..'%s*%(%)%f[^%w_]'
        local _, cnt = s:gsub(pat, '('..retVal..')')
        if (cnt or 0) > 0 then
            n12=n12+1
            s = s:gsub(pat, '('..retVal..')')
            return ""
        end
        return "local "..fname.." = function() return "..retVal.." end"
    end)
    if n12>0 then log("Pass 12: Inlined "..n12.." trivial wrapper function(s).") end

    -- ── PASS 13: Junk variable removal ───────────────────────
    local n13 = 0
    s = s:gsub('local%s+([a-zA-Z_][a-zA-Z0-9_]*)%s*=%s*[^\n;]+\n', function(varname)
        local uses = 0
        for _ in s:gmatch('%f[%w_]'..escapePat(varname)..'%f[^%w_]') do uses=uses+1 end
        if uses<=1 and (#varname<=3 or varname:match("^_+%d+$") or varname:match("^[a-z][A-Z][a-z]%d")) then
            n13=n13+1; return ""
        end
        return nil
    end)
    if n13>0 then log("Pass 13: Removed "..n13.." junk variable(s).") end

    -- ── PASS 14: loadstring/require global hook intercept ─────
    -- Before runtime: patch the source to wrap loadstring/require calls
    -- so nested loads are also captured during sandbox execution
    log("Pass 14: Patching nested loadstring/require calls for tracing...", "dim")
    local n14 = 0
    s = s:gsub('(%f[%w]loadstring%f[%W])', function()
        n14=n14+1; return '__mk_ls'
    end)
    s = s:gsub('(%f[%w]require%f[%W])', function()
        n14=n14+1; return '__mk_req'
    end)
    if n14>0 then log("Pass 14: Wrapped "..n14.." loadstring/require call(s) for tracing.", "ok") end

    -- ── RUNTIME PHASE A: Constant dump via debug API ──────────
    log("Runtime A: Constant extraction (upvalues + protos + consts)...", "accent")
    local fn_a, parseErr_a = loadstring(s)
    if fn_a then
        -- upvalues
        local upFn = (ENV.getupvals) or (debug and debug.getupvalues)
        if upFn then
            local ok, upvals = pcall(upFn, fn_a)
            if ok and type(upvals)=="table" then
                for k, v in pairs(upvals) do
                    if type(v)=="string" and #v>=3 and #v<=500
                       and not v:match("[%z\1-\8\11\12\14-\31]") then
                        table.insert(dumped, "upval "..tostring(k)..": \""..v:sub(1,80).."\"")
                    end
                end
            end
        end
        -- constants table
        if ENV.getconsts then
            local ok, consts = pcall(ENV.getconsts, fn_a)
            if ok and type(consts)=="table" then
                for _, v in ipairs(consts) do
                    if type(v)=="string" and #v>=3
                       and not v:match("[%z\1-\8\11\12\14-\31]") then
                        table.insert(dumped, "const: \""..tostring(v):sub(1,80).."\"")
                    end
                end
            end
        end
        -- proto tree (inner functions)
        local protoStrings = dumpProtoTree(fn_a, 0, {})
        for _, ps in ipairs(protoStrings) do
            table.insert(dumped, ps)
        end
        if #dumped>0 then
            log("  Extracted "..(#dumped).." constant(s) from function tree.", "ok")
        else
            log("  No string constants found at this level.", "dim")
        end
    else
        log("  Parse error (VM loader): "..tostring(parseErr_a):sub(1,80), "warn")
        -- VM payload extraction for IB2/Luraph
        local payload = s:match('"([A-Za-z0-9+/=]{200,})"')
        if payload then
            local ok_p, dec_p = pcall(b64decode, payload)
            if ok_p and dec_p and #dec_p>50 then
                table.insert(dumped, "VM_PAYLOAD_B64_DECODED ("..#dec_p.."B): "..dec_p:sub(1,150).."...")
                log("  Extracted VM bytecode payload ("..#dec_p.."B) — use unluac/IronDeob externally.", "warn")
            end
        end
        -- engine-specific advice
        if engine then
            if engine:find("Ironbrew") then
                log("  → IronbrewDeobfuscator: github.com/Lethal-Luka/IronbrewDeobfuscator", "dim")
            elseif engine:find("Luraph") then
                log("  → LuraphDeobfuscator + unluac (Java)", "dim")
            elseif engine:find("Moonsec") or engine:find("Prometheus") then
                log("  → Prometheus-Deobfuscator: github.com/0x251/Prometheus-Deobfuscator", "dim")
            else
                log("  → unluac (Java) or luau-decompiler (C++) for bytecode", "dim")
            end
        end
    end

    -- ── RUNTIME PHASE B: GC memory scan ───────────────────────
    log("Runtime B: GC memory scan for runtime strings...", "accent")
    local gcStrings = gcScanStrings(4, 200)
    local gcLua = {}
    for _, gs in ipairs(gcStrings) do
        if luaLikeness(gs) > 1 or gs:match("[%a][%a][%a]") then
            table.insert(gcLua, "gc: \""..gs:sub(1,80).."\"")
        end
    end
    if #gcLua>0 then
        log("  GC scan found "..#gcLua.." interesting string(s) in memory.", "ok")
        for i=1,math.min(#gcLua,20) do table.insert(dumped, gcLua[i]) end
        if #gcLua>20 then log("  ...("..(#gcLua-20).." more in constants file)", "dim") end
    else
        log("  GC scan: no Lua-like strings found (getgc may be unavailable).", "dim")
    end

    -- ── RUNTIME PHASE C: Hooked sandbox with debug.sethook ────
    log("Runtime C: Hooked sandbox execution + line tracing...", "accent")
    local apiTrace, printOut, nestedLoads = {}, {}, {}
    local callCount = 0
    local MAX_CALLS = 800

    local function makeProxy(name, realFn)
        return function(...)
            callCount=callCount+1
            if callCount>MAX_CALLS then error("MK_LIMIT") end
            local argParts = {}
            for i, a in ipairs({...}) do
                local ta = type(a)
                if ta=="string" then argParts[i]='"'..tostring(a):sub(1,50)..'"'
                elseif ta=="number" or ta=="boolean" then argParts[i]=tostring(a)
                else argParts[i]="<"..ta..">" end
            end
            local entry = name.."("..table.concat(argParts,", ")..")"
            if not apiTrace[entry] then -- dedup
                apiTrace[entry]=true
                table.insert(apiTrace, entry)
            end
            if realFn then local ok,r=pcall(realFn,...); if ok then return r end end
        end
    end

    local function stubSvc(name)
        return setmetatable({},{
            __index=function(_,k) return makeProxy(name.."."..k) end,
            __call=makeProxy(name),
            __tostring=function() return name end,
            __newindex=function() end,
        })
    end

    -- The two intercepted functions — capture nested loads and re-dump
    local function mk_loadstring(code)
        local cs = tostring(code or "")
        table.insert(nestedLoads, cs:sub(1,200))
        table.insert(apiTrace, "loadstring(<"..#cs.."B>)")
        -- dump constants from this nested load too
        local nfn = loadstring(cs)
        if nfn then
            local upFn2 = ENV.getupvals or (debug and debug.getupvalues)
            if upFn2 then
                local ok2, ups2 = pcall(upFn2, nfn)
                if ok2 and type(ups2)=="table" then
                    for _, v in pairs(ups2) do
                        if type(v)=="string" and #v>=4 and #v<300
                           and not v:match("[%z\1-\8]") then
                            table.insert(dumped, "nested_upval: \""..v:sub(1,80).."\"")
                        end
                    end
                end
            end
            -- actually run nested load in same sandbox (recursive trace)
            return nfn
        end
        return function() end
    end

    local function mk_require(mod)
        table.insert(apiTrace, "require(<"..type(mod)..">)")
        -- if it's a ModuleScript, try to get its source
        if type(mod)=="userdata" then
            local decomp = getDecompiler()
            if decomp then
                local ok, src2 = pcall(decomp, mod)
                if ok and src2 and #src2>10 then
                    table.insert(nestedLoads, "[require dump] "..src2:sub(1,200))
                end
            end
        end
        return {}
    end

    local sbEnv = setmetatable({
        __mk_ls  = mk_loadstring,
        __mk_req = mk_require,
        print    = function(...) table.insert(printOut,"[print] "..table.concat({...},"\t")) end,
        warn     = function(...) table.insert(printOut,"[warn]  "..table.concat({...},"\t")) end,
        error    = function(e) table.insert(printOut,"[error] "..tostring(e)) end,
        assert   = function(v,m) if not v then table.insert(printOut,"[assert] "..(m or "")) end; return v end,
        pairs=pairs,ipairs=ipairs,type=type,next=next,
        tostring=tostring,tonumber=tonumber,select=select,
        rawget=rawget,rawset=rawset,rawequal=rawequal,
        setmetatable=setmetatable,getmetatable=getmetatable,
        unpack=unpack or table.unpack,
        math=math,string=string,table=table,
        bit32=bit32 or {},
        os={time=os.time,clock=os.clock,date=os.date},
        pcall=pcall,xpcall=xpcall,
        getfenv=function() return {} end,
        setfenv=function() end,
        coroutine=coroutine,
        Instance=  {new=makeProxy("Instance.new")},
        Enum=setmetatable({},{__index=function(_,k)
            return setmetatable({},{__index=function(_,k2) return k.."."..k2 end})
        end}),
        game=setmetatable({},{__index=function(_,svc)
            if svc=="GetService" then
                return function(_,name)
                    table.insert(apiTrace,"game:GetService(\""..tostring(name).."\")")
                    return stubSvc(tostring(name))
                end
            end
            return stubSvc(tostring(svc))
        end}),
        workspace=stubSvc("workspace"),
        script=setmetatable({},{__index=function(_,k)
            table.insert(apiTrace,"script."..k); return nil
        end}),
        task=setmetatable({},{__index=function(_,k) return makeProxy("task."..k) end}),
    },{__index=function(_,k)
        return makeProxy(k)
    end})

    -- run with line tracing if sethook available
    local fn_c, parseErr_c = loadstring(s)
    local sandboxSuccess = false
    if fn_c then
        local ok_c, err_c, lineTrace = runWithLineTrace(fn_c, sbEnv, 300)
        if ok_c then
            log("  Sandbox: executed cleanly ✔", "ok")
            sandboxSuccess = true
        else
            local em = tostring(err_c or ""):gsub("MK_LIMIT","call limit hit")
            log("  Sandbox error: "..em:sub(1,100), "warn")
        end
        if #lineTrace>0 then
            log("  debug.sethook traced "..#lineTrace.." line(s) of execution.", "ok")
            table.insert(dumped, "=== LINE TRACE ===")
            for i=1,math.min(#lineTrace,50) do table.insert(dumped, lineTrace[i]) end
        end
        if #apiTrace>0 then
            -- apiTrace is a hybrid table (dedup keys + array order)
            local traceArr = {}
            for _, v in ipairs(apiTrace) do
                if type(v)=="string" then table.insert(traceArr, v) end
            end
            log("  API calls: "..#traceArr.." unique call(s).", "ok")
            table.insert(dumped, "=== API TRACE ===")
            for _, call in ipairs(traceArr) do table.insert(dumped, "→ "..call) end
        end
        if #nestedLoads>0 then
            log("  Captured "..#nestedLoads.." nested loadstring/require chunk(s).", "ok")
            table.insert(dumped, "=== NESTED LOADS ===")
            for i, chunk in ipairs(nestedLoads) do
                table.insert(dumped, "chunk["..i.."]: "..chunk)
            end
        end
        if #printOut>0 then
            log("  Script output ("..#printOut.." line(s)):", "ok")
            table.insert(dumped, "=== SCRIPT OUTPUT ===")
            for _, line in ipairs(printOut) do
                log("    "..line, "dim")
                table.insert(dumped, line)
            end
        end
    else
        log("  Parse failed (VM bytecode loader): "..tostring(parseErr_c):sub(1,80), "err")
    end

    return {
        cleaned  = s,
        logs     = logs,
        dumped   = dumped,
        success  = sandboxSuccess or (fn_c ~= nil) or (fn_a ~= nil),
        apiTrace = apiTrace,
        printOut = printOut,
    }
end

-- ============================================================
--  GLOBAL loadstring/require hooks
--  Captures ALL scripts loaded dynamically during gameplay
--  (section 3.1 of the analysis)
-- ============================================================

local _capturedLoads = {}
local _lsHookActive  = false
local _origLS, _origReq2

local function startLoadstringHook(cb)
    if _lsHookActive then return end
    _lsHookActive = true

    _origLS = ENV.loadstring or loadstring
    local function hookedLS(code, chunkname)
        local cs = tostring(code or "")
        local entry = {
            chunk   = cs:sub(1, 300),
            size    = #cs,
            name    = chunkname or "?",
            time    = os.clock(),
        }
        table.insert(_capturedLoads, entry)
        if cb then task.spawn(cb, entry) end
        return _origLS(code, chunkname)
    end

    -- set in global env so game scripts hit it
    if ENV.setgenv then
        pcall(ENV.setgenv, "loadstring", hookedLS)
    elseif ENV.getgenv then
        local genv = ENV.getgenv()
        if genv then rawset(genv, "loadstring", hookedLS) end
    end
    -- Note: setfenv(0,...) intentionally omitted — crashes on most executors
end

local function stopLoadstringHook()
    if not _lsHookActive then return end
    _lsHookActive = false
    if ENV.setgenv then pcall(ENV.setgenv, "loadstring", _origLS) end
    if ENV.getgenv then
        local genv = ENV.getgenv()
        if genv and _origLS then rawset(genv, "loadstring", _origLS) end
    end
end

-- ============================================================
--  SCRIPT SCANNER
-- ============================================================

local CORE_PREFIXES = {"^CoreGui","^CorePackages","^RobloxGui","^RobloxPlayer"}
local function isCore(obj)
    local p = obj:GetFullName()
    for _, pre in ipairs(CORE_PREFIXES) do if p:match(pre) then return true end end
    return false
end

local scanCache = {}

local function scanScripts()
    local decomp, decompName = getDecompiler()
    local results = {}
    local gameScripts = {}

    -- collect from game tree
    for _, obj in ipairs(game:GetDescendants()) do
        if (obj:IsA("LocalScript") or obj:IsA("ModuleScript") or obj:IsA("Script"))
           and not isCore(obj) then
            gameScripts[obj] = true
        end
    end

    -- merge with executor getscripts list
    local apiScripts, apiName = getScriptsAPI()
    if apiScripts then
        for _, scr in ipairs(apiScripts) do
            if not isCore(scr) then gameScripts[scr] = true end
        end
    end

    -- also include anything captured by loadstring hook
    for _, entry in ipairs(_capturedLoads) do
        -- these aren't Instances, store as synthetic entries
        table.insert(results, {
            name       = "loadstring["..entry.name.."]",
            path       = "[dynamic]",
            type       = "DynamicScript",
            size       = entry.size,
            source     = entry.chunk,
            isEmpty    = entry.size == 0,
            isStub     = false,
            stubReason = nil,
            isRunning  = true,
            isBytecode = false,
            isObf      = detectObf(entry.chunk),
            engine     = nil,
            srcMethod  = "loadstring-hook",
            obj        = nil,
        })
    end

    for obj in pairs(gameScripts) do
        local src, srcMethod = "", "none"
        local isRunning = false

        -- Method 1: executor decompile()
        if decomp then
            local ok, result = pcall(decomp, obj)
            if ok and type(result)=="string" and #result>4
               and not result:match("^\27Lua") then
                src = result; srcMethod = decompName
            end
        end

        -- Method 2: getsenv (confirms running, sometimes gives source)
        if #src == 0 then
            local ok, senv = getSenvAPI(obj)
            if ok and type(senv)=="table" then
                isRunning = true
                local ok2, s2 = pcall(function() return obj.Source end)
                if ok2 and type(s2)=="string" and #s2>4 then
                    src = s2; srcMethod = "getsenv+Source"
                end
            end
        end

        -- Method 3: direct .Source
        if #src == 0 then
            local ok, s3 = pcall(function() return obj.Source end)
            if ok and type(s3)=="string" and #s3>4 then
                src = s3; srcMethod = ".Source"
            end
        end

        -- Method 4: getscriptbytecode (raw, last resort)
        if #src == 0 and ENV.getscriptbytecode then
            local ok, bc = pcall(ENV.getscriptbytecode, obj)
            if ok and type(bc)=="string" and #bc>0 then
                src = bc; srcMethod = "bytecode"
            end
        end

        local stubCheck, stubReason = isStub(src)
        local isBytecode = srcMethod=="bytecode" or src:sub(1,4)=="\27Lua"
        local isObf, engine = false, nil
        if not isBytecode and not stubCheck and #src>0 then
            isObf, engine = detectObf(src)
        end

        table.insert(results, {
            name       = obj.Name,
            path       = obj:GetFullName(),
            type       = obj.ClassName,
            size       = #src,
            source     = src,
            isEmpty    = #src==0,
            isStub     = stubCheck,
            stubReason = stubReason,
            isRunning  = isRunning,
            isBytecode = isBytecode,
            isObf      = isObf,
            engine     = engine,
            srcMethod  = srcMethod,
            obj        = obj,
        })
    end

    -- sort: running first, then by size descending
    table.sort(results, function(a,b)
        if a.isRunning ~= b.isRunning then return a.isRunning end
        return a.size > b.size
    end)

    scanCache = results
    return results, apiName, decompName
end

-- ============================================================
--  DOWNLOADER
-- ============================================================

local function downloadScripts(scripts, cb)
    if not hasFS then
        if cb then cb("ERROR: writefile/makefolder not available.", "err") end
        return
    end
    FS.mkdir("MobileKit")
    FS.mkdir("MobileKit/Scripts")
    FS.mkdir("MobileKit/Obfuscated")
    FS.mkdir("MobileKit/Bytecode")
    FS.mkdir("MobileKit/Dynamic")

    local saved, skipped, stubcount, bytecount = 0, 0, 0, 0
    for _, s in ipairs(scripts) do
        if s.isEmpty then
            skipped = skipped + 1
        elseif s.isStub then
            stubcount = stubcount + 1
        else
            local safeName = (s.path:gsub("[/\\:*?\"<>|%.]","_"))..".lua"
            local folder
            if s.srcMethod == "loadstring-hook" then
                folder = "MobileKit/Dynamic/"
            elseif s.isBytecode then
                folder = "MobileKit/Bytecode/"
                safeName = safeName:gsub("%.lua$",".bin")
                bytecount = bytecount + 1
            elseif s.isObf then
                folder = "MobileKit/Obfuscated/"
            else
                folder = "MobileKit/Scripts/"
            end
            local header = "-- =============================================\n"
                        .. "-- MobileKit v4 Script Dump\n"
                        .. "-- Path:   "..s.path.."\n"
                        .. "-- Type:   "..s.type.."\n"
                        .. "-- Size:   "..s.size.." bytes\n"
                        .. "-- Method: "..s.srcMethod.."\n"
                        .. (s.isObf and ("-- Obfusc: "..(s.engine or "Unknown").."\n") or "")
                        .. (s.isRunning and "-- Status: Running\n" or "")
                        .. "-- =============================================\n\n"
            local ok = pcall(FS.write, folder..safeName, (s.isBytecode and "" or header)..s.source)
            if ok then saved = saved + 1 end
        end
    end
    if cb then
        cb(string.format(
            "Saved %d scripts.\nSkipped %d empty + %d stubs.\n%d bytecode (needs unluac/IronDeob externally).",
            saved, skipped, stubcount, bytecount
        ), "ok")
    end
end

-- ============================================================
--  RSPY
-- ============================================================

local rspyLogs, rspyActive, rspyConns = {}, false, {}

local function startRSpy(cb)
    for _, c in ipairs(rspyConns) do pcall(function() c:Disconnect() end) end
    rspyConns = {}
    rspyActive = true

    local function hookRemote(obj)
        if obj:IsA("RemoteEvent") then
            local c = obj.OnClientEvent:Connect(function(...)
                local args = {...}
                local e = {kind="RemoteEvent", path=obj:GetFullName(), args=args, t=os.clock()}
                table.insert(rspyLogs, 1, e)
                if cb then task.spawn(cb, e) end
            end)
            table.insert(rspyConns, c)
        elseif obj:IsA("RemoteFunction") then
            -- IMPORTANT: OnClientInvoke can only be SET, never read in executor context.
            -- We wrap by setting a new callback that logs and then calls the original
            -- via a pcall-captured reference stored before we overwrite it.
            local originalCb = nil
            -- Safely attempt to capture any existing callback via hookfunction if available
            local hf = ENV.hookfunction or ENV.replaceclosure
            if hf then
                -- use executor hook so we don't lose the original
                local logged = false
                local function newCb(...)
                    if not logged then logged = true end
                    local args = {...}
                    local e = {kind="RemoteFunction", path=obj:GetFullName(), args=args, t=os.clock()}
                    table.insert(rspyLogs, 1, e)
                    if cb then task.spawn(cb, e) end
                    if originalCb then return originalCb(...) end
                end
                -- just set it directly — we can't safely read old value without hookfunction
                pcall(function() obj.OnClientInvoke = newCb end)
            else
                -- fallback: just set, accepting we may break existing callback
                pcall(function()
                    obj.OnClientInvoke = function(...)
                        local args = {...}
                        local e = {kind="RemoteFunction", path=obj:GetFullName(), args=args, t=os.clock()}
                        table.insert(rspyLogs, 1, e)
                        if cb then task.spawn(cb, e) end
                    end
                end)
            end
        elseif obj:IsA("BindableEvent") then
            local c = obj.Event:Connect(function(...)
                local args = {...}
                local e = {kind="BindableEvent", path=obj:GetFullName(), args=args, t=os.clock()}
                table.insert(rspyLogs, 1, e)
                if cb then task.spawn(cb, e) end
            end)
            table.insert(rspyConns, c)
        end
    end

    for _, obj in ipairs(game:GetDescendants()) do hookRemote(obj) end
    local c = game.DescendantAdded:Connect(hookRemote)
    table.insert(rspyConns, c)
end

local function stopRSpy()
    for _, c in ipairs(rspyConns) do pcall(function() c:Disconnect() end) end
    rspyConns = {}
    rspyActive = false
end

-- ============================================================
--  HTTP SPY
-- ============================================================

local httpLogs, httpActive = {}, false
local _origReq, _origGet, _origPost

local function startHTTP(cb)
    httpActive = true
    -- Only hook methods that actually exist on this executor's HttpService
    local canRequest = pcall(function() return HttpService.RequestAsync end)
    local canGet     = pcall(function() return HttpService.GetAsync end)
    local canPost    = pcall(function() return HttpService.PostAsync end)

    if canRequest then
        _origReq = HttpService.RequestAsync
        HttpService.RequestAsync = function(self, opts)
            local ok2, e2 = pcall(function()
                local e = {method=opts.Method or "GET", url=opts.Url or "?", body=tostring(opts.Body or ""):sub(1,300), t=os.clock()}
                table.insert(httpLogs, 1, e)
                if cb then task.spawn(cb, e) end
            end)
            return _origReq(self, opts)
        end
    end

    if canGet then
        _origGet = HttpService.GetAsync
        HttpService.GetAsync = function(self, url, ...)
            local ok2, e2 = pcall(function()
                local e = {method="GET", url=url, body="", t=os.clock()}
                table.insert(httpLogs, 1, e)
                if cb then task.spawn(cb, e) end
            end)
            return _origGet(self, url, ...)
        end
    end

    if canPost then
        _origPost = HttpService.PostAsync
        HttpService.PostAsync = function(self, url, data, ...)
            local ok2, e2 = pcall(function()
                local e = {method="POST", url=url, body=tostring(data or ""):sub(1,300), t=os.clock()}
                table.insert(httpLogs, 1, e)
                if cb then task.spawn(cb, e) end
            end)
            return _origPost(self, url, data, ...)
        end
    end

    if not canRequest and not canGet and not canPost then
        if cb then
            -- fire a synthetic log entry to tell the user
            task.spawn(cb, {method="INFO", url="No HttpService methods available to hook on this executor.", body="", t=os.clock()})
        end
    end
end

local function stopHTTP()
    if _origReq  then HttpService.RequestAsync = _origReq  end
    if _origGet  then HttpService.GetAsync     = _origGet  end
    if _origPost then HttpService.PostAsync    = _origPost end
    httpActive = false
end

-- ============================================================
--  GUI CONSTRUCTION
-- ============================================================

-- Wait for LocalPlayer if needed (executor may run before player loads)
if not lp then
    lp = Players.LocalPlayer
    if not lp then
        lp = Players:GetPropertyChangedSignal("LocalPlayer"):Wait()
        lp = Players.LocalPlayer
    end
end

if lp.PlayerGui:FindFirstChild("MobileKit") then
    lp.PlayerGui.MobileKit:Destroy()
end

local sg = Instance.new("ScreenGui")
sg.Name = "MobileKit"; sg.ResetOnSpawn = false
sg.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
sg.Parent = lp.PlayerGui

local win = Instance.new("Frame")
win.Size = UDim2.new(0.93, 0, 0.84, 0)
win.Position = UDim2.new(0.035, 0, 0.08, 0)
win.BackgroundColor3 = T.BG; win.BorderSizePixel = 0
corner(win, 14); stroke(win, T.BORDER, 1); win.Parent = sg

-- topbar
local top = Instance.new("Frame")
top.Size = UDim2.new(1, 0, 0, 50); top.BackgroundColor3 = T.SURFACE
top.BorderSizePixel = 0; corner(top, 14); top.Parent = win
-- cover bottom corners
local topFix = Instance.new("Frame")
topFix.Size = UDim2.new(1,0,0.5,0); topFix.Position = UDim2.new(0,0,0.5,0)
topFix.BackgroundColor3 = T.SURFACE; topFix.BorderSizePixel = 0; topFix.Parent = top

local titleL = lbl(top, "⚡ MobileKit", 15, T.TEXT, FBB)
titleL.Position = UDim2.new(0,14,0,0); titleL.Size = UDim2.new(0.55,0,1,0)
titleL.TextYAlignment = Enum.TextYAlignment.Center

local verL = lbl(top, "v2.0", 10, T.DIM)
verL.Position = UDim2.new(0,118,0,0); verL.Size = UDim2.new(0.15,0,1,0)
verL.TextYAlignment = Enum.TextYAlignment.Center

local closeB = Instance.new("TextButton")
closeB.Text = "✕"; closeB.TextColor3 = T.RED; closeB.Font = FBB; closeB.TextSize = 15
closeB.BackgroundTransparency = 1; closeB.Size = UDim2.new(0,44,1,0)
closeB.Position = UDim2.new(1,-44,0,0); closeB.Parent = top
closeB.MouseButton1Click:Connect(function()
    tw(win, {Size=UDim2.new(0,0,0,0), BackgroundTransparency=1}, 0.28)
    task.delay(0.32, function() sg:Destroy() end)
end)

-- drag
local drag, ds, sp = false, nil, nil
top.InputBegan:Connect(function(i)
    if i.UserInputType == Enum.UserInputType.Touch or i.UserInputType == Enum.UserInputType.MouseButton1 then
        drag=true; ds=i.Position; sp=win.Position
    end
end)
top.InputEnded:Connect(function(i)
    if i.UserInputType == Enum.UserInputType.Touch or i.UserInputType == Enum.UserInputType.MouseButton1 then drag=false end
end)
UIS.InputChanged:Connect(function(i)
    if drag and (i.UserInputType == Enum.UserInputType.Touch or i.UserInputType == Enum.UserInputType.MouseMove) then
        local d = i.Position - ds
        win.Position = UDim2.new(sp.X.Scale, sp.X.Offset+d.X, sp.Y.Scale, sp.Y.Offset+d.Y)
    end
end)

-- Navbar
local PAGES = {"Scanner","Download","RSpy","HTTPSpy","Deobf"}
local nav = Instance.new("Frame")
nav.Size = UDim2.new(1,0,0,42); nav.Position = UDim2.new(0,0,0,50)
nav.BackgroundColor3 = T.SURFACE; nav.BorderSizePixel = 0; nav.Parent = win
hlist(nav, 0)

local navInd = Instance.new("Frame")
navInd.Size = UDim2.new(1/#PAGES,-4,0,2); navInd.Position = UDim2.new(0,2,1,-2)
navInd.BackgroundColor3 = T.ACCENT; navInd.BorderSizePixel = 0; corner(navInd,2); navInd.Parent = nav

local pgCont = Instance.new("Frame")
pgCont.Size = UDim2.new(1,0,1,-92); pgCont.Position = UDim2.new(0,0,0,92)
pgCont.BackgroundTransparency = 1; pgCont.ClipsDescendants = true; pgCont.Parent = win

local pages, navBtns, curPage = {}, {}, 1

local function goPage(idx)
    curPage = idx
    for i,pg in ipairs(pages) do pg.Visible = (i==idx) end
    for i,nb in ipairs(navBtns) do tw(nb, {TextColor3 = i==idx and T.ACCENT or T.DIM}, 0.18) end
    tw(navInd, {Position = UDim2.new((1/#PAGES)*(idx-1), 2, 1, -2)}, 0.22, Enum.EasingStyle.Quart)
end

for i, name in ipairs(PAGES) do
    local nb = Instance.new("TextButton")
    nb.Size = UDim2.new(1/#PAGES,0,1,0); nb.BackgroundTransparency = 1
    nb.Text = name; nb.TextSize = 11; nb.Font = FBB
    nb.TextColor3 = i==1 and T.ACCENT or T.DIM
    nb.LayoutOrder = i; nb.Parent = nav
    table.insert(navBtns, nb)
    nb.MouseButton1Click:Connect(function() goPage(i) end)

    local pg = Instance.new("Frame")
    pg.Size = UDim2.new(1,0,1,0); pg.BackgroundTransparency = 1
    pg.Visible = (i==1); pg.Parent = pgCont
    pad(pg, 10)
    table.insert(pages, pg)
end

-- ============================================================
--  PAGE 1: SCANNER
-- ============================================================

local p1 = pages[1]
vlist(p1, 8)

-- API info bar
local apiBanner = Instance.new("Frame")
apiBanner.Size = UDim2.new(1,0,0,32); apiBanner.BackgroundColor3 = T.CARD2
apiBanner.LayoutOrder = 1; corner(apiBanner, 6); apiBanner.Parent = p1
local apiL = lbl(apiBanner, "Detecting executor APIs...", 11, T.DIM, FM)
apiL.Position = UDim2.new(0,8,0,0); apiL.Size = UDim2.new(1,-16,1,0)
apiL.TextYAlignment = Enum.TextYAlignment.Center

task.spawn(function()
    local _, apiName  = getScriptsAPI()
    local _, decompName = getDecompiler()
    apiL.Text = string.format("Executor APIs: getscripts=%s | decompile=%s | fs=%s",
        apiName, decompName, hasFS and "YES" or "NO")
    apiL.TextColor3 = (decompName ~= "none") and T.GREEN or T.YELLOW
end)

-- scan + hook row
local scanRow = row(p1, 42); scanRow.LayoutOrder = 2; hlist(scanRow, 8)
local scanBtn = btn(scanRow, "🔍  Scan", T.ACCENT)
scanBtn.Size = UDim2.new(0.55, 0, 1, 0)
local lsHookBtn = btn(scanRow, "⚡ Hook LS: OFF", T.CARD)
lsHookBtn.Size = UDim2.new(0.45, -8, 1, 0)
local lsHookOn = false
lsHookBtn.MouseButton1Click:Connect(function()
    lsHookOn = not lsHookOn
    if lsHookOn then
        startLoadstringHook(function(entry)
            local card = Instance.new("Frame")
            card.Size = UDim2.new(1,0,0,42)
            card.BackgroundColor3 = T.CARD2; corner(card,8); card.Parent = scanList
            local nl = lbl(card, "[dynamic] "..entry.name, 11, T.TEAL, FM)
            nl.Position = UDim2.new(0,8,0,4); nl.Size = UDim2.new(0.85,0,0,14)
            local sl = lbl(card, entry.size.."B captured", 10, T.DIM)
            sl.Position = UDim2.new(0,8,0,22); sl.Size = UDim2.new(0.85,0,0,13)
        end)
        lsHookBtn.Text = "⚡ Hook LS: ON"
        lsHookBtn.BackgroundColor3 = T.TEAL
    else
        stopLoadstringHook()
        lsHookBtn.Text = "⚡ Hook LS: OFF"
        lsHookBtn.BackgroundColor3 = T.CARD
    end
end)

local scanStatL = lbl(p1, "Press Scan to begin. Enable Hook LS to capture dynamic loads.", 12, T.DIM)
scanStatL.LayoutOrder = 3; scanStatL.Size = UDim2.new(1,0,0,26)

local scanList = scroll(p1, 999)
scanList.LayoutOrder = 4
scanList.Size = UDim2.new(1,0,1,-112)
vlist(scanList, 5); pad(scanList, 6)

local function clearScanList()
    for _, c in ipairs(scanList:GetChildren()) do
        if c:IsA("Frame") then c:Destroy() end
    end
end

local selectedScript = nil

local function buildScanCard(s)
    local card = Instance.new("Frame")
    card.Size = UDim2.new(1,0,0,64)
    card.BackgroundColor3 = T.CARD; corner(card,8); card.Parent = scanList

    -- clickable to preview / load into deob
    local hitbox = Instance.new("TextButton")
    hitbox.Size = UDim2.new(1,0,1,0); hitbox.BackgroundTransparency = 1
    hitbox.Text = ""; hitbox.Parent = card

    local nameL = lbl(card, s.name, 13, T.TEXT, FBB)
    nameL.Position = UDim2.new(0,8,0,5); nameL.Size = UDim2.new(0.72,0,0,17)

    local pathL = lbl(card, s.path, 10, T.DIM, FM)
    pathL.Position = UDim2.new(0,8,0,24); pathL.Size = UDim2.new(0.9,-8,0,13)
    pathL.TextWrapped = false

    local info = string.format("%dB | %s%s", s.size, s.srcMethod,
        s.isStub and (" | ⚠ "..s.stubReason) or
        s.isObf  and (" | "..s.engine) or "")
    local infoL = lbl(card, info, 10, s.isStub and T.RED or T.DIM)
    infoL.Position = UDim2.new(0,8,0,42); infoL.Size = UDim2.new(0.6,0,0,13)

    -- tag row
    local tagRow = Instance.new("Frame")
    tagRow.BackgroundTransparency = 1; tagRow.Size = UDim2.new(0,150,0,22)
    tagRow.Position = UDim2.new(1,-158,0,5); tagRow.Parent = card
    hlist(tagRow, 4)

    local tc = s.type=="LocalScript" and T.ACCENT or s.type=="Script" and T.TEAL or T.YELLOW
    chip(tagRow, s.type=="LocalScript" and "LS" or s.type=="ModuleScript" and "MS" or "S", tc)
    if s.isRunning  then chip(tagRow, "RUN",   T.GREEN)  end
    if s.isBytecode then chip(tagRow, "BC",    T.ORANGE) end
    if s.isObf      then chip(tagRow, "OBF",   T.RED)    end
    if s.isStub     then chip(tagRow, "STUB",  T.DIM)    end
    if s.isEmpty    then chip(tagRow, "EMPTY", T.DIM)    end

    -- click: select + load into deob page
    hitbox.MouseButton1Click:Connect(function()
        selectedScript = s
        tw(card, {BackgroundColor3 = T.CARD2}, 0.12)
        -- also store in deob source box for convenience
        -- (we'll handle this when deob page is set up)
        if _G.MK_LoadDeob then _G.MK_LoadDeob(s) end
    end)

    return card
end

local function refreshScanList(results)
    clearScanList()
    for _, s in ipairs(results) do
        buildScanCard(s)
    end
end

scanBtn.MouseButton1Click:Connect(function()
    scanStatL.Text = "Scanning..."
    scanStatL.TextColor3 = T.DIM
    clearScanList()
    task.spawn(function()
        local found, apiUsed, decompUsed = scanScripts()
        local obfN, emptyN, runN, bcN, stubN = 0,0,0,0,0
        for _, s in ipairs(found) do
            if s.isObf      then obfN  = obfN+1  end
            if s.isEmpty    then emptyN= emptyN+1 end
            if s.isRunning  then runN  = runN+1   end
            if s.isBytecode then bcN   = bcN+1    end
            if s.isStub     then stubN = stubN+1  end
        end
        local readable = #found - emptyN - obfN - bcN - stubN
        scanStatL.Text = string.format(
            "%d total | %d readable | %d obf | %d bytecode | %d stubs | %d empty",
            #found, math.max(readable,0), obfN, bcN, stubN, emptyN
        )
        scanStatL.TextColor3 = T.GREEN
        refreshScanList(found)
    end)
end)

-- ============================================================
--  PAGE 2: DOWNLOADER
-- ============================================================

local p2 = pages[2]
vlist(p2, 10)

local dlInfo = lbl(p2, "Saves all non-empty scripts.\n• Readable → MobileKit/Scripts/\n• Obfuscated → MobileKit/Obfuscated/\n• Bytecode-only → MobileKit/Bytecode/ (needs external decompiler)", 12, T.DIM)
dlInfo.Size = UDim2.new(1,0,0,66)

if not hasFS then
    local warn = lbl(p2, "⚠  writefile not available in this executor — download disabled.", 12, T.RED)
    warn.Size = UDim2.new(1,0,0,20)
end

local dlBtn   = btn(p2, "⬇  Download All Scripts", T.TEAL)
local dlCopyB = btn(p2, "📋  Copy Selected Script to Clipboard", T.ACCENT)
local dlStatL = lbl(p2, "", 12, T.GREEN)
dlStatL.Size = UDim2.new(1,0,0,48); dlStatL.TextWrapped = true

dlBtn.MouseButton1Click:Connect(function()
    dlStatL.Text = "Working..."
    dlStatL.TextColor3 = T.DIM
    task.spawn(function()
        local scripts = #scanCache > 0 and scanCache or scanScripts()
        downloadScripts(scripts, function(msg, tag)
            dlStatL.Text = msg
            dlStatL.TextColor3 = tag == "err" and T.RED or T.GREEN
        end)
    end)
end)

dlCopyB.MouseButton1Click:Connect(function()
    if selectedScript and #selectedScript.source > 0 then
        copyToClipboard(selectedScript.source)
        dlStatL.Text = "Copied: " .. selectedScript.path
        dlStatL.TextColor3 = T.TEAL
    else
        dlStatL.Text = "Select a script from the Scanner first."
        dlStatL.TextColor3 = T.YELLOW
    end
end)

-- ============================================================
--  PAGE 3: RSPY
-- ============================================================

local p3 = pages[3]
vlist(p3, 8)

local r_top = row(p3, 42); r_top.LayoutOrder = 1; hlist(r_top, 8)
local rStartB = btn(r_top,"▶ Start",T.GREEN); rStartB.Size=UDim2.new(0.44,0,1,0)
local rStopB  = btn(r_top,"■ Stop", T.RED);   rStopB.Size=UDim2.new(0.44,0,1,0)
local rClearB = btn(r_top,"🗑",T.CARD);        rClearB.Size=UDim2.new(0.12,-8,1,0)

local rStatL = lbl(p3, "Idle. Logs RemoteEvent, RemoteFunction & BindableEvent.", 11, T.DIM)
rStatL.Size = UDim2.new(1,0,0,26)

local rList = scroll(p3, 999)
rList.Size = UDim2.new(1,0,1,-84)
vlist(rList,5); pad(rList,6)

local function addRCard(e)
    local card = Instance.new("Frame")
    card.Size = UDim2.new(1,0,0,68)
    card.BackgroundColor3 = T.CARD; corner(card,8); card.Parent = rList

    local kc = e.kind=="RemoteEvent" and T.ACCENT or e.kind=="RemoteFunction" and T.TEAL or T.YELLOW
    local kch = chip(card, e.kind=="RemoteEvent" and "RE" or e.kind=="RemoteFunction" and "RF" or "BE", kc)
    kch.Position = UDim2.new(0,8,0,7)

    local timeL = lbl(card, string.format("%.2fs", e.t), 10, T.DIM, FM)
    timeL.Position = UDim2.new(1,-60,0,7); timeL.Size = UDim2.new(0,52,0,16)
    timeL.TextXAlignment = Enum.TextXAlignment.Right

    local nl = lbl(card, e.path, 11, T.TEXT, FB)
    nl.Position = UDim2.new(0,8,0,28); nl.Size = UDim2.new(1,-16,0,14)
    nl.TextWrapped = false

    -- format args
    local parts = {}
    for i, a in ipairs(e.args) do
        local t = type(a)
        if t == "table" then
            parts[i] = "{table}"
        elseif t == "userdata" then
            local ok, s2 = pcall(tostring, a)
            parts[i] = ok and s2 or "userdata"
        else
            parts[i] = tostring(a)
        end
    end
    local argsStr = table.concat(parts, ", ")
    local al = lbl(card, "→ " .. (argsStr ~= "" and argsStr or "no args"), 10, T.DIM, FM)
    al.Position = UDim2.new(0,8,0,46); al.Size = UDim2.new(1,-16,0,14)

    -- copy on click
    local hb = Instance.new("TextButton"); hb.BackgroundTransparency=1; hb.Text=""
    hb.Size = UDim2.new(1,0,1,0); hb.Parent = card
    hb.MouseButton1Click:Connect(function()
        copyToClipboard(e.path .. "\n" .. argsStr)
        tw(card, {BackgroundColor3=T.CARD2},0.1)
        task.delay(0.3, function() tw(card,{BackgroundColor3=T.CARD},0.2) end)
    end)

    local ch = rList:GetChildren()
    if #ch > 104 then for i=105,#ch do if ch[i]:IsA("Frame") then ch[i]:Destroy() end end end
end

rStartB.MouseButton1Click:Connect(function()
    if rspyActive then return end
    startRSpy(function(e)
        addRCard(e)
        rStatL.Text = "Listening... " .. #rspyLogs .. " captured. (Tap entry to copy)"
        rStatL.TextColor3 = T.GREEN
    end)
    rStatL.Text = "Listening for remotes..."
    rStatL.TextColor3 = T.GREEN
end)
rStopB.MouseButton1Click:Connect(function()
    stopRSpy()
    rStatL.Text = "Stopped. " .. #rspyLogs .. " total logged."
    rStatL.TextColor3 = T.DIM
end)
rClearB.MouseButton1Click:Connect(function()
    rspyLogs = {}
    for _, c in ipairs(rList:GetChildren()) do if c:IsA("Frame") then c:Destroy() end end
    rStatL.Text = "Cleared."
end)

-- ============================================================
--  PAGE 4: HTTP SPY
-- ============================================================

local p4 = pages[4]
vlist(p4, 8)

local h_top = row(p4, 42); h_top.LayoutOrder=1; hlist(h_top, 8)
local hStartB = btn(h_top,"▶ Start",T.GREEN); hStartB.Size=UDim2.new(0.44,0,1,0)
local hStopB  = btn(h_top,"■ Stop", T.RED);   hStopB.Size=UDim2.new(0.44,0,1,0)
local hClearB = btn(h_top,"🗑",T.CARD);        hClearB.Size=UDim2.new(0.12,-8,1,0)

local hStatL = lbl(p4, "Idle. Hooks RequestAsync, GetAsync, PostAsync.", 11, T.DIM)
hStatL.Size = UDim2.new(1,0,0,26)

local hList = scroll(p4, 999)
hList.Size = UDim2.new(1,0,1,-84)
vlist(hList,5); pad(hList,6)

local function addHCard(e)
    local card = Instance.new("Frame")
    card.Size = UDim2.new(1,0,0,68)
    card.BackgroundColor3 = T.CARD; corner(card,8); card.Parent = hList

    local mc = e.method=="GET" and T.TEAL or e.method=="POST" and T.YELLOW or T.ORANGE
    local mch = chip(card, e.method, mc)
    mch.Position = UDim2.new(0,8,0,7)

    local timeL = lbl(card, string.format("%.2fs", e.t), 10, T.DIM, FM)
    timeL.Position = UDim2.new(1,-60,0,7); timeL.Size = UDim2.new(0,52,0,16)
    timeL.TextXAlignment = Enum.TextXAlignment.Right

    local ul = lbl(card, e.url, 11, T.TEXT, FM)
    ul.Position = UDim2.new(0,8,0,28); ul.Size = UDim2.new(1,-16,0,14)
    ul.TextWrapped = false

    if #e.body > 0 then
        local bl = lbl(card, e.body:sub(1,90), 10, T.DIM, FM)
        bl.Position = UDim2.new(0,8,0,46); bl.Size = UDim2.new(1,-16,0,14)
    end

    local hb = Instance.new("TextButton"); hb.BackgroundTransparency=1; hb.Text=""
    hb.Size = UDim2.new(1,0,1,0); hb.Parent = card
    hb.MouseButton1Click:Connect(function()
        copyToClipboard(e.method.." "..e.url.."\n"..e.body)
        tw(card,{BackgroundColor3=T.CARD2},0.1)
        task.delay(0.3, function() tw(card,{BackgroundColor3=T.CARD},0.2) end)
    end)

    local ch = hList:GetChildren()
    if #ch > 104 then for i=105,#ch do if ch[i]:IsA("Frame") then ch[i]:Destroy() end end end
end

hStartB.MouseButton1Click:Connect(function()
    if httpActive then return end
    startHTTP(function(e)
        addHCard(e)
        hStatL.Text = "Listening... " .. #httpLogs .. " captured. (Tap entry to copy)"
        hStatL.TextColor3 = T.GREEN
    end)
    hStatL.Text = "Listening for HTTP..."
    hStatL.TextColor3 = T.GREEN
end)
hStopB.MouseButton1Click:Connect(function()
    stopHTTP()
    hStatL.Text = "Stopped. " .. #httpLogs .. " logged."
    hStatL.TextColor3 = T.DIM
end)
hClearB.MouseButton1Click:Connect(function()
    httpLogs = {}
    for _, c in ipairs(hList:GetChildren()) do if c:IsA("Frame") then c:Destroy() end end
    hStatL.Text = "Cleared."
end)

-- ============================================================
--  PAGE 5: DEOBFUSCATOR
-- ============================================================

local p5 = pages[5]
vlist(p5, 7)

local deobInfo = lbl(p5, "Paste source or load from Scanner. Runs 8-pass cleanup + sandbox.", 12, T.DIM)
deobInfo.Size = UDim2.new(1,0,0,28)

local srcBox = Instance.new("TextBox")
srcBox.Size = UDim2.new(1,0,0,88); srcBox.BackgroundColor3 = T.CARD
srcBox.TextColor3 = T.TEXT; srcBox.Font = FM; srcBox.TextSize = 11
srcBox.Text = "-- paste obfuscated source here"; srcBox.PlaceholderText = "paste source..."
srcBox.TextXAlignment = Enum.TextXAlignment.Left; srcBox.TextYAlignment = Enum.TextYAlignment.Top
srcBox.MultiLine = true; srcBox.ClearTextOnFocus = false; srcBox.TextWrapped = true
corner(srcBox,8); stroke(srcBox, T.BORDER); pad(srcBox, 8); srcBox.Parent = p5

-- allow scanner to populate this
_G.MK_LoadDeob = function(s)
    if #s.source > 0 then
        srcBox.Text = s.source
    end
end

-- buttons row
local deobRow = row(p5, 40); hlist(deobRow, 8)
local loadObfB = btn(deobRow, "📥 Load from Scanner", T.YELLOW)
loadObfB.Size = UDim2.new(0.52,0,1,0)
local deobRunB = btn(deobRow, "⚙ Deobfuscate", T.ACCENT)
deobRunB.Size = UDim2.new(0.48,-8,1,0)

loadObfB.MouseButton1Click:Connect(function()
    for _, s in ipairs(scanCache) do
        if s.isObf and #s.source > 0 then
            srcBox.Text = s.source
            return
        end
    end
    srcBox.Text = "-- No obfuscated scripts in cache. Run Scanner first."
end)

local deobOut = scroll(p5, 999)
deobOut.Size = UDim2.new(1,0,1,-238)
pad(deobOut,8); vlist(deobOut, 3)

local function logColor(tag)
    if tag == "ok"     then return T.GREEN
    elseif tag == "err"   then return T.RED
    elseif tag == "warn"  then return T.YELLOW
    elseif tag == "accent"then return T.ACCENT
    elseif tag == "dim"   then return T.DIM
    elseif tag == "title" then return T.TEXT
    end
    return T.TEXT
end

local function addDeobLine(msg, tag)
    local l = Instance.new("TextLabel")
    l.Text = msg; l.TextSize = 11; l.Font = FM
    l.TextColor3 = logColor(tag)
    l.BackgroundTransparency = 1; l.TextXAlignment = Enum.TextXAlignment.Left
    l.TextWrapped = true; l.Size = UDim2.new(1,0,0,0)
    l.AutomaticSize = Enum.AutomaticSize.Y; l.Parent = deobOut
end

deobRunB.MouseButton1Click:Connect(function()
    for _, c in ipairs(deobOut:GetChildren()) do if c:IsA("TextLabel") then c:Destroy() end end

    local src = srcBox.Text
    if #src < 5 or src:find("^%-%-") then
        addDeobLine("No source to deobfuscate.", "err"); return
    end

    addDeobLine("Starting 8-pass deobfuscation...", "accent")
    task.spawn(function()
        local res = deobfuscate(src)
        for _, entry in ipairs(res.logs) do
            addDeobLine(entry.msg, entry.tag)
        end
        addDeobLine("─────────────────────────────────", "dim")

        if res.success then
            addDeobLine("✔ Deobfuscation complete (source-level passes done).", "ok")
        else
            addDeobLine("⚠ Source-level cleanup applied. VM bytecode needs external tool.", "warn")
        end

        -- always save everything we found regardless of success level
        if hasFS then
            FS.mkdir("MobileKit"); FS.mkdir("MobileKit/Deobfuscated")
            local ts = os.time()

            -- cleaned source
            local fname = "MobileKit/Deobfuscated/deob_"..ts..".lua"
            local ok_w = pcall(FS.write, fname, res.cleaned)
            addDeobLine((ok_w and "Saved cleaned source" or "Write failed")..": "..fname, ok_w and "ok" or "err")

            -- constants/trace dump (most valuable for VM scripts)
            if res.dumped and #res.dumped > 0 then
                local dumpFname = "MobileKit/Deobfuscated/constants_"..ts..".txt"
                local dumpContent = "=== MobileKit Deobfuscator v4 — Runtime Dump ===\n"
                               .. "Timestamp: "..ts.."\n"
                               .. "Engine detected: "..(detectObf(src) and "obfuscated" or "clean").."\n"
                               .. "Total entries: "..#res.dumped.."\n\n"
                               .. table.concat(res.dumped, "\n")
                local ok_d = pcall(FS.write, dumpFname, dumpContent)
                if ok_d then
                    addDeobLine("Saved "..#res.dumped.." runtime constants/traces → "..dumpFname, "ok")
                    addDeobLine("The constants file shows API calls, strings, nested loads.", "dim")
                end
            end

            -- deobfuscation report
            local reportFname = "MobileKit/Deobfuscated/report_"..ts..".txt"
            local reportLines = {"=== MobileKit Deobfuscation Report ===", ""}
            for _, entry in ipairs(res.logs) do
                table.insert(reportLines, entry.msg)
            end
            pcall(FS.write, reportFname, table.concat(reportLines, "\n"))
            addDeobLine("Saved full deob report → "..reportFname, "dim")
        else
            srcBox.Text = res.cleaned
            addDeobLine("writefile unavailable — cleaned source placed in box.", "warn")
        end

        copyToClipboard(res.cleaned)
        addDeobLine("Cleaned source also copied to clipboard.", "dim")

        if not res.success then
            local isObf2, eng2 = detectObf(res.cleaned)
            if isObf2 then
                addDeobLine("Still obfuscated ("..tostring(eng2).."). External tools needed:", "warn")
                addDeobLine("  IronbrewDeobfuscator / LuraphDeobfuscator / unluac / luau-decompiler", "dim")
            end
        end
    end)
end)

-- ============================================================
--  INIT
-- ============================================================

goPage(1)
print("[MobileKit v4] Loaded. Deobfuscator v4 active (14-pass + runtime extraction).")
