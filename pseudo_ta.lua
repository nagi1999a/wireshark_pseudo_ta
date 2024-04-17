-- A Wireshark LUA script to display pseudo TA Information

local f_wlan_ta = Field.new("wlan.ta")
local f_wlan_ra = Field.new("wlan.ra")

local p_pseudoTA = Proto("p-ta", "Pseudo TA Information")

local F_ta = ProtoField.ether("p-ta.ta", "Transmitter Address")
local F_taStr = ProtoField.string("p-ta.taStr", "String of Transmitter Address with parentheses to indicate pseudo")
local F_isPseudo = ProtoField.bool("p-ta.isPseudo", "Is Pseudo")
local F_isPseudoStr = ProtoField.string("p-ta.isPseudoStr", "String to indicate pseudo")
local F_addr = ProtoField.ether("p-ta.addr", "TA & RA")

p_pseudoTA.fields = {F_ta, F_taStr, F_isPseudo, F_isPseudoStr, F_addr}

local f_ack = Field.new("wlan.fc.type_subtype")
local f_rts = Field.new("wlan.fc.type_subtype")
local valid_fields_f = {
    f_ack,
    f_rts,
}
local valid_fields_v = {
    0x001d,
    0x001c
}

local org_data = {}
local data = {}

local function reset_stats()
	org_data = {}
	org_data.ta = {}
	org_data.ra = {}

    data = {}
    data.ta = {}
    data.isPseudo = {}
    data.isValid = {}
    data.addr = {}
end

function p_pseudoTA.init()
	reset_stats()
end

function p_pseudoTA.dissector(buffer,pinfo,tree)

    local ta = f_wlan_ta()
    local ra = f_wlan_ra()
    local num = pinfo.number

    if not pinfo.visited then
        data.addr[num] = {}

        if ra then
            org_data.ra[num] = ra.value
            data.addr[num][#data.addr[num]+1] = ra.value
        end
        
        if ta then
            org_data.ta[num] = ta.value
            data.addr[num][#data.addr[num]+1] = ta.value
            data.ta[num] = ta.value
            data.isPseudo[num] = false
        elseif (num > 0) and (org_data.ta[num-1]) and (org_data.ra[num-1]) and (org_data.ra[num]) and (org_data.ra[num] == org_data.ta[num-1]) then
            data.addr[num][#data.addr[num]+1] = org_data.ra[num-1]
            data.ta[num] = org_data.ra[num-1]
            data.isPseudo[num] = true
        end

        data.isValid[num] = false
        for index, f_valid in ipairs(valid_fields_f) do
            local field = f_valid()
            if field and (field.value == valid_fields_v[index]) then
                data.isValid[num] = true
            end
        end
    end

    if pinfo.visited then
        if data.ta[num] and (data.isPseudo[num] == true) and (data.isValid[num]) then
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
    
end

register_postdissector(p_pseudoTA)