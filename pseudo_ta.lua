-- A Wireshark LUA script to display pseudo TA Information

--- Fields that used to extract previous frame data
local f_wlan_ta = Field.new("wlan.ta")
local f_wlan_ra = Field.new("wlan.ra")
local f_wlan_type_subtype = Field.new("wlan.fc.type_subtype")

--- Define enable conditions
local conditions = {
    ["ACK"]         = true,
    ["RTS-CTS"]         = true,
    ["CTS-to-self"] = true,
}

--- Define a new protocol
local p_pseudoTA = Proto("p-ta", "Pseudo TA Information")

--- Fields in the new protocol
local F_ta = ProtoField.ether("p-ta.ta", "Transmitter Address")
local F_taStr = ProtoField.string("p-ta.taStr", "String of Transmitter Address with parentheses to indicate pseudo")
local F_isPseudo = ProtoField.bool("p-ta.isPseudo", "Is Pseudo")
local F_isPseudoStr = ProtoField.string("p-ta.isPseudoStr", "String to indicate pseudo")
local F_addr = ProtoField.ether("p-ta.addr", "TA & RA")

--- Registor new protocol fields
p_pseudoTA.fields = {F_ta, F_taStr, F_isPseudo, F_isPseudoStr, F_addr}

--- Since dissectors cannot access information of other frames, so maintain global tables to save things
local org_data = {}
local data = {}

--- Init function
local function reset_stats()
	org_data = {}
	org_data.ta = {}
	org_data.ra = {}
    org_data.type_subtype = {}
    org_data.n_ta = {}
    org_data.n_ra = {}

    data = {}
    data.ta = {}
    data.isPseudo = {}
    data.condition = {}
    data.addr = {}
end

function p_pseudoTA.init()
	reset_stats()
end

--- Main dissector function
function p_pseudoTA.dissector(buffer, pinfo, tree)
    --- Get the information of current frame
    local ta = f_wlan_ta()
    local ra = f_wlan_ra()
    local type_subtype = f_wlan_type_subtype()
    local num = pinfo.number

    --- Data init should only run once
    if not pinfo.visited then
        if ta then org_data.ta[num] = ta.value end
        if ra then org_data.ra[num] = ra.value end
        if type_subtype then org_data.type_subtype[num] = type_subtype.value end
        if (num > 0) and ta then org_data.n_ta[num-1] = ta.value end
        if (num > 0) and ra then org_data.n_ra[num-1] = ra.value end

        --- Init addr
        data.addr[num] = {}
        if org_data.ra[num] then
            data.addr[num][1] = org_data.ra[num]
        end

        --- check whether need to perform TA inferring
        data.isPseudo[num] = false
        
        --- Special Case: TA exists in current frame
        if org_data.ta[num] then
            data.isPseudo[num] = false
            data.ta[num] = org_data.ta[num]
            data.addr[num][#data.addr[num]+1] = org_data.ta[num]
        end

        --- 1. ACK
        if org_data.type_subtype[num] == 0x001d then
            assert(org_data.ra[num], "ACK frame should have RA value!")
            if (org_data.ra[num] == org_data.ta[num-1]) and (org_data.ra[num-1]) then
                data.isPseudo[num] = true
                data.condition[num] = "ACK"
                data.ta[num] = org_data.ra[num-1]
                data.addr[num][#data.addr[num]+1] = org_data.ra[num-1]
            end
        end

        --- CTS Related
        if org_data.type_subtype[num] == 0x001c then
            assert(org_data.ra[num], "CTS frame should have RA value!")
            --- 2. RTS-CTS
            if (org_data.type_subtype[num-1] == 0x001b) then
                if (org_data.ra[num] == org_data.ta[num-1]) and (org_data.ra[num-1]) then
                    data.isPseudo[num] = true
                    data.condition[num] = "RTS-CTS"
                    data.ta[num] = org_data.ra[num-1]
                    data.addr[num][#data.addr[num]+1] = org_data.ra[num-1]
                end
            --- 3. CTS-to-self
            else
                data.isPseudo[num] = true
                data.condition[num] = "CTS-to-self"
                data.ta[num] = org_data.ra[num]
            end
        end
    end

    if pinfo.visited then
        --- Trick for CTS-to-self, add RA in the next frame to the current frame addr
        --- Note: Only works for static pcap, live capture does not guarantee to perform 2-pass.
        if (org_data.type_subtype[num] == 0x001c) then
            assert(org_data.ra[num], "CTS frame should have RA value!")
            if (org_data.ra[num] == org_data.n_ta[num]) then
                data.addr[num][#data.addr[num]+1] = org_data.n_ra[num]
            end
        end
    end

    if data.ta[num] and (data.isPseudo[num] == true) and (conditions[data.condition[num]] == true) then
        tree:add(F_ta, data.ta[num]):append_text(' (Pseudo)'):set_generated()
        tree:add(F_taStr, '(' .. tostring(data.ta[num]) .. ')'):set_hidden():set_generated()
        tree:add(F_isPseudo, true):set_hidden():set_generated()
        tree:add(F_isPseudoStr, 'T'):set_hidden():set_generated()
    elseif data.ta[num] and (data.isPseudo[num] == false) then
        tree:add(F_ta, data.ta[num]):set_generated()
        tree:add(F_taStr, tostring(data.ta[num])):set_hidden():set_generated()
        tree:add(F_isPseudo, false):set_hidden():set_generated()
        tree:add(F_isPseudoStr, ''):set_hidden():set_generated()
    end
    for index, value in ipairs(data.addr[num]) do
        tree:add(F_addr, value):set_hidden():set_generated()
    end
end

--- Registor post-dissector
register_postdissector(p_pseudoTA)