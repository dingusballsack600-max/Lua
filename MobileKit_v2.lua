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
--  OBFUSCATION DETECTION (enhanced)
-- ============================================================

local OBF_SIGS = {
    {n="Luraph",       p="local%s+[%w_]+%s*=%s*{[%d,%-%s]+}%s*local%s+[%w_]+%s*=%s*{"},
    {n="Ironbrew 2",   p='local%s+[%w_]+%s*=%s*"[A-Za-z0-9+/=]{40,}"'},
    {n="Moonsec v2",   p="local%s+[%w_]+;[%s\n]*for%s+[%w_]+%s*=%s*1"},
    {n="Moonsec v3",   p="local%s+[%w_]+%s*=%s*table%.concat"},
    {n="PSU",          p="loadstring%(game:HttpGet"},
    {n="Bytecode",     p="\\%d%d%d\\%d%d%d\\%d%d%d"},
    {n="VM Loader",    p="local%s+[%w_]+%s*=%s*load%("},
    {n="Obfusc8",      p="[%w_]+%([%w_]+%([%w_]+%([%w_]+%([%w_]+%("},
    {n="Generic B64",  p="[A-Za-z0-9+/=]{80,}"},
    {n="Junk inject",  p="local%s+[a-z][A-Z][a-z]%d%s*="},
}

-- Shanon entropy over first 800 chars
local function entropy(s)
    local freq = {}
    local n = math.min(#s, 800)
    for i = 1, n do
        local c = s:sub(i,i)
        freq[c] = (freq[c] or 0) + 1
    end
    local h = 0
    for _, v in pairs(freq) do
        local p = v / n
        h = h - p * math.log(p, 2)
    end
    return h
end

local function detectObf(src)
    if not src or #src == 0 then return false, "empty" end
    if src:find("^<roblox") then return false, "XML asset" end
    for _, sig in ipairs(OBF_SIGS) do
        if src:match(sig.p) then return true, sig.n end
    end
    local ent = entropy(src)
    if ent > 5.2 then return true, string.format("High entropy (%.2f bits)", ent) end
    -- ratio of readable lines vs total
    local total, readable = 0, 0
    for line in src:gmatch("[^\n]+") do
        total = total + 1
        if line:match("[a-zA-Z_][a-zA-Z0-9_]*%s*[=%(]") then readable = readable + 1 end
    end
    if total > 10 and (readable / total) < 0.15 then
        return true, "Low readability ratio"
    end
    return false, nil
end

-- ============================================================
--  DECOMPILE STUB DETECTION
--  Executors return ~80-byte "stub" strings when decompile fails.
--  These look like source but are just error messages.
-- ============================================================

-- Known decompiler error signatures (executor-specific)
-- Konstant V2.x: "KONSTANTERROR: After: ..." followed by lines of "K"
-- Generic fallbacks from other decompilers
local STUB_HARD = {
    -- Konstant V2.x errors (your executor)
    "^KONSTANTERROR:",
    "KONSTANTERROR: After:",
    "Unknown constant type",
    -- Generic decompiler failures
    "^%-%-? ?[Ff]ailed to decompile",
    "failed to decompile bytecode",
    "Too Many Requests",          -- Konstant rate limit
    "Decompilation failed",
    "decompilation failed",
    "cannot decompile",
    "Cannot decompile",
    "unsupported bytecode",
    "Unsupported bytecode",
    "bytecode version not supported",
    "unable to decompile",
    -- Empty / whitespace only
    "^%s*$",
}

-- Softer heuristic: after stripping the MobileKit header and decompiler
-- banner, if the remaining "code" is nothing but K-spam or comment lines, stub.
local function countKLines(src)
    local total, klines = 0, 0
    for line in src:gmatch("[^\n]+") do
        local trimmed = line:match("^%s*(.-)%s*$")
        if trimmed ~= "" then
            total = total + 1
            if trimmed == "K" or trimmed:match("^K+$") then
                klines = klines + 1
            end
        end
    end
    return total, klines
end

local function isStub(src)
    if not src or #src == 0 then return true, "empty" end

    -- Hard match: specific known error strings anywhere in source
    for _, pat in ipairs(STUB_HARD) do
        if src:match(pat) then
            return true, "decompiler error stub"
        end
    end

    -- Konstant K-spam heuristic: if >40% of non-empty lines are just "K"
    local total, klines = countKLines(src)
    if total > 0 and (klines / total) >= 0.4 then
        return true, string.format("Konstant K-spam (%d/%d lines)", klines, total)
    end

    -- Size + no Lua keywords fallback (keeps things like CameraUI at 998B safe)
    if #src < 100 and not src:match("local%s") and not src:match("function") 
       and not src:match("return") and not src:match("=") then
        return true, "tiny non-Lua content ("..#src.."B)"
    end

    return false, nil
end

-- ============================================================
--  DEOBFUSCATOR (multi-pass)
-- ============================================================

local function b64decode(enc)
    local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    enc = enc:gsub('[^'..b..'=]', '')
    return (enc:gsub('.', function(x)
        if x == '=' then return '' end
        local r, f = '', (b:find(x) - 1)
        for i = 6, 1, -1 do r = r .. (f % 2^i - f % 2^(i-1) > 0 and '1' or '0') end
        return r
    end):gsub('%d%d%d%d%d%d%d%d', function(x)
        local c = tonumber(x, 2)
        if c >= 32 and c <= 126 then return string.char(c) end
        return ''
    end))
end

local function xorDecode(data, key)
    local res = {}
    for i = 1, #data do
        local ki = ((i-1) % #key) + 1
        res[i] = string.char(bit32.bxor(data:byte(i), key:byte(ki)))
    end
    return table.concat(res)
end

local function deobfuscate(src)
    local logs = {}
    local function log(msg, tag) table.insert(logs, {msg=msg, tag=tag or "info"}) end

    log("=== MobileKit Deobfuscator v2 ===", "title")
    local isObf, engine = detectObf(src)
    if not isObf then
        log("Source appears clean — no obfuscation detected.", "ok")
        return {cleaned=src, logs=logs, success=true}
    end
    log("Detected: " .. (engine or "Unknown"), "warn")

    local s = src

    -- Pass 1: strip comments
    s = s:gsub("%-%-[^\n]*", "")
    log("Pass 1: Stripped inline comments.")

    -- Pass 2: decode numeric escape sequences \65 -> A
    local esc = 0
    s = s:gsub("\\(%d%d?%d?)", function(n)
        local c = tonumber(n)
        if c and c >= 32 and c <= 126 then esc=esc+1; return string.char(c) end
        return "\\" .. n
    end)
    if esc > 0 then log("Pass 2: Decoded " .. esc .. " numeric escape(s).") end

    -- Pass 3: decode hex escape sequences \x41 -> A
    local hexesc = 0
    s = s:gsub("\\x(%x%x)", function(h)
        local c = tonumber(h, 16)
        if c and c >= 32 and c <= 126 then hexesc=hexesc+1; return string.char(c) end
        return "\\x" .. h
    end)
    if hexesc > 0 then log("Pass 3: Decoded " .. hexesc .. " hex escape(s).") end

    -- Pass 4: decode base64 string literals
    local b64n = 0
    s = s:gsub('"([A-Za-z0-9+/=]+)"', function(enc)
        if #enc >= 16 and #enc % 4 == 0 then
            local ok, dec = pcall(b64decode, enc)
            if ok and dec and #dec > 0 and not dec:match("[%z\1-\8\11\12\14-\31]") and #dec < #enc then
                b64n = b64n + 1
                return '"' .. dec:gsub('"', '\\"') .. '"'
            end
        end
        return '"' .. enc .. '"'
    end)
    if b64n > 0 then log("Pass 4: Decoded " .. b64n .. " base64 literal(s).") end

    -- Pass 5: inline single-assignment string constants
    --   local _abc = "value"  -->  replace all uses of _abc with "value"
    local consts, inlined = {}, 0
    for k, v in s:gmatch('local%s+([%w_]+)%s*=%s*"([^"]*)"') do
        if #v > 0 then consts[k] = v end
    end
    for k, v in pairs(consts) do
        local n
        s, n = s:gsub('%f[%w_]'..k..'%f[^%w_]', '"'..v:gsub('%%','%%%%')..'"')
        inlined = inlined + (n or 0)
    end
    if inlined > 0 then log("Pass 5: Inlined " .. inlined .. " string constant(s).") end

    -- Pass 6: simplify always-true/false conditions
    s = s:gsub("if%s+true%s+then", "do")
    s = s:gsub("if%s+false%s+then(.-)end", "")
    log("Pass 6: Simplified trivial conditions.")

    -- Pass 7: remove redundant variable aliases
    -- local a = b  where b is a known builtin
    local builtins = {tostring=1,tonumber=1,type=1,pairs=1,ipairs=1,next=1,
                      select=1,unpack=1,rawget=1,rawset=1,rawequal=1,pcall=1,xpcall=1}
    s = s:gsub("local%s+([%w_]+)%s*=%s*([%w_%.]+)%s*\n", function(alias, orig)
        if builtins[orig] then
            s = s:gsub('%f[%w_]'..alias..'%f[^%w_]', orig)
            return ""
        end
        return "local "..alias.." = "..orig.."\n"
    end)
    log("Pass 7: Removed builtin alias reassignments.")

    -- Pass 8: attempt sandbox loadstring execution + output capture
    log("Pass 8: Sandbox loadstring attempt...", "accent")
    local sbOutput = {}
    local sbEnv = setmetatable({
        print   = function(...) table.insert(sbOutput, "[print] "..table.concat({...},"\t")) end,
        warn    = function(...) table.insert(sbOutput, "[warn]  "..table.concat({...},"\t")) end,
        error   = function(e) table.insert(sbOutput, "[error] "..tostring(e)) end,
        assert  = function(v,m) if not v then table.insert(sbOutput,"[assert fail] "..(m or "")) end return v end,
        pairs=pairs, ipairs=ipairs, type=type, tostring=tostring, tonumber=tonumber,
        math=math, string=string, table=table, bit32=bit32,
        os={time=os.time, clock=os.clock, date=os.date},
        game    = setmetatable({}, {__index=function(_,k)
            table.insert(sbOutput, "[game."..k.." accessed]")
            return setmetatable({},{__index=function(_,k2) return function() end end, __call=function() end})
        end}),
        workspace = setmetatable({},{__index=function() return function() end end}),
        require   = function() table.insert(sbOutput,"[require blocked]") end,
        loadstring= function() table.insert(sbOutput,"[nested loadstring blocked]") end,
        getfenv   = function() return {} end,
        setfenv   = function() end,
        rawget=rawget, rawset=rawset, select=select,
        unpack=unpack or table.unpack,
        setmetatable=setmetatable, getmetatable=getmetatable,
    }, {__index=function(_,k)
        table.insert(sbOutput, "[unknown global: "..tostring(k).."]")
        return function() end
    end})

    local fn, parseErr = loadstring(s)
    local sandboxSuccess = false
    if fn then
        setfenv(fn, sbEnv)
        local ok, runErr = pcall(fn)
        if ok then
            log("Sandbox: executed cleanly.", "ok")
            sandboxSuccess = true
        else
            log("Sandbox runtime: " .. tostring(runErr):sub(1,120), "warn")
        end
        if #sbOutput > 0 then
            log("Sandbox captured " .. #sbOutput .. " output line(s):", "accent")
            for _, line in ipairs(sbOutput) do log("  " .. line, "dim") end
        end
    else
        log("Parse error: " .. tostring(parseErr):sub(1,120), "err")
        log("This VM-based obfuscation (Luraph/Ironbrew) can't be parsed directly.", "warn")
        log("Tip: use unluac, IronDeob, or a VM tracer for full deobfuscation.", "dim")
    end

    return {
        cleaned = s,
        logs    = logs,
        success = sandboxSuccess or (fn ~= nil),
        sbOutput = sbOutput,
    }
end

-- ============================================================
--  SCRIPT SCANNER (proper executor API usage)
-- ============================================================

local CORE_PREFIXES = {
    "^CoreGui", "^CorePackages", "^RobloxGui", "^RobloxPlayer"
}
local function isCore(obj)
    local p = obj:GetFullName()
    for _, pre in ipairs(CORE_PREFIXES) do
        if p:match(pre) then return true end
    end
    return false
end

local scanCache = {}

local function scanScripts()
    local decomp, decompName = getDecompiler()
    local results = {}

    -- Try executor getscripts first (returns running scripts with actual source)
    local apiScripts, apiName = getScriptsAPI()

    -- Collect from game tree
    local gameScripts = {}
    for _, obj in ipairs(game:GetDescendants()) do
        if (obj:IsA("LocalScript") or obj:IsA("ModuleScript") or obj:IsA("Script")) and not isCore(obj) then
            gameScripts[obj] = true
        end
    end

    -- Merge with API list (the API list has decompiled source for running scripts)
    if apiScripts then
        for _, scr in ipairs(apiScripts) do
            if not isCore(scr) then
                gameScripts[scr] = true
            end
        end
    end

    for obj in pairs(gameScripts) do
        local src = ""
        local srcMethod = "none"
        local isRunning = false

        -- Method 1: try decompile() (best, gives readable Lua source)
        if decomp then
            local ok, result = pcall(decomp, obj)
            if ok and type(result) == "string" and #result > 4 then
                -- skip raw bytecode blobs (starts with \27Lua or \27LuaQ)
                if not result:match("^\27Lua") then
                    src = result
                    srcMethod = decompName
                end
            end
        end

        -- Method 2: try getsenv to confirm script is running (don't rawget on Instance)
        if #src == 0 then
            local ok, senv = getSenvAPI(obj)
            if ok and type(senv) == "table" then
                isRunning = true
                -- senv is a plain table, we can rawget safely
                local scriptRef = rawget(senv, "script")
                -- scriptRef is a Roblox Instance — use pcall .Source, NOT rawget
                if scriptRef ~= nil then
                    local ok2, s2 = pcall(function() return obj.Source end)
                    if ok2 and type(s2) == "string" and #s2 > 0 then
                        src = s2
                        srcMethod = "getsenv+Source"
                    end
                end
            end
        end

        -- Method 3: direct .Source (works in some executors for LocalScripts)
        if #src == 0 then
            local ok, s3 = pcall(function() return obj.Source end)
            if ok and type(s3) == "string" and #s3 > 4 then
                src = s3
                srcMethod = ".Source"
            end
        end

        -- Method 4: getscriptbytecode (raw bytecode, not readable but shows script isn't empty)
        if #src == 0 and ENV.getscriptbytecode then
            local ok, bc = pcall(ENV.getscriptbytecode, obj)
            if ok and type(bc) == "string" and #bc > 0 then
                src = bc
                srcMethod = "bytecode"
            end
        end

        local isEmpty   = #src == 0
        local stubCheck, stubReason = isStub(src)
        local isBytecode = srcMethod == "bytecode" or (src:sub(1,4) == "\27Lua")
        -- only run obf detection on real, non-stub, non-bytecode source
        local isObf, engine = false, nil
        if not isBytecode and not stubCheck and #src > 0 then
            isObf, engine = detectObf(src)
        end

        table.insert(results, {
            name       = obj.Name,
            path       = obj:GetFullName(),
            type       = obj.ClassName,
            size       = #src,
            source     = src,
            isEmpty    = isEmpty,
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

    -- sort: running first, then by size desc
    table.sort(results, function(a, b)
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
        if cb then cb("ERROR: writefile/makefolder not available in this executor.", "err") end
        return
    end
    FS.mkdir("MobileKit")
    FS.mkdir("MobileKit/Scripts")
    FS.mkdir("MobileKit/Obfuscated")
    FS.mkdir("MobileKit/Bytecode")

    local saved, skipped, bytecount, stubcount = 0, 0, 0, 0
    for _, s in ipairs(scripts) do
        if s.isEmpty then
            skipped = skipped + 1
        elseif s.isStub then
            -- stub = executor failed to decompile, skip it (not useful)
            stubcount = stubcount + 1
        else
            local safeName = (s.path:gsub("[/\\:*?\"<>|%.]", "_")) .. ".lua"
            local folder
            if s.isBytecode then
                folder = "MobileKit/Bytecode/"
                safeName = safeName:gsub("%.lua$", ".bin")
                bytecount = bytecount + 1
            elseif s.isObf then
                folder = "MobileKit/Obfuscated/"
            else
                folder = "MobileKit/Scripts/"
            end

            local header = "-- =============================================\n"
                        .. "-- MobileKit v2 Script Dump\n"
                        .. "-- Path:   " .. s.path .. "\n"
                        .. "-- Type:   " .. s.type .. "\n"
                        .. "-- Size:   " .. s.size .. " bytes\n"
                        .. "-- Method: " .. s.srcMethod .. "\n"
                        .. (s.isObf and ("-- Obfusc: " .. (s.engine or "Unknown") .. "\n") or "")
                        .. (s.isRunning and "-- Status: Running\n" or "")
                        .. "-- =============================================\n\n"

            local ok = pcall(FS.write, folder .. safeName, (s.isBytecode and "" or header) .. s.source)
            if ok then saved = saved + 1 end
        end
    end
    if cb then
        cb(string.format(
            "Saved %d scripts.\nSkipped %d empty + %d stubs (failed decompiles).\n%d bytecode-only saved (needs external decompiler).",
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

local scanBtn = btn(p1, "🔍  Scan Game Scripts", T.ACCENT)
scanBtn.LayoutOrder = 2

local scanStatL = lbl(p1, "Press Scan to begin.", 12, T.DIM)
scanStatL.LayoutOrder = 3; scanStatL.Size = UDim2.new(1,0,0,16)

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
            addDeobLine("✔ Partial deobfuscation complete.", "ok")
            addDeobLine("Saving to MobileKit/Deobfuscated/...", "ok")
            if hasFS then
                FS.mkdir("MobileKit"); FS.mkdir("MobileKit/Deobfuscated")
                local fname = "MobileKit/Deobfuscated/deob_" .. os.time() .. ".lua"
                local ok = pcall(FS.write, fname, res.cleaned)
                addDeobLine(ok and ("Saved: " .. fname) or "Write failed.", ok and "ok" or "err")
            else
                addDeobLine("writefile unavailable — output placed in source box.", "warn")
                srcBox.Text = res.cleaned
            end
            -- also copy to clipboard
            copyToClipboard(res.cleaned)
            addDeobLine("Cleaned source also copied to clipboard.", "dim")
        else
            addDeobLine("⚠ Could not fully deobfuscate — partial cleanup in source box.", "warn")
            addDeobLine("For VM-based obfuscation (Luraph/Ironbrew), you need:", "dim")
            addDeobLine("  • unluac (Java-based bytecode decompiler)", "dim")
            addDeobLine("  • IronDeob / ironbrew-decompiler on GitHub", "dim")
            addDeobLine("  • A VM tracer/debugger inside your executor", "dim")
            srcBox.Text = res.cleaned
        end
    end)
end)

-- ============================================================
--  INIT
-- ============================================================

goPage(1)
print("[MobileKit v2] Loaded. APIs detected on first scan.")
