require 'luau'
require 'strings'
res = require('resources')
packets = require('packets')
pack = require('pack')
bit = require 'bit'

files = require('files')
file = T{}
file.compare = files.new('data/logs/comparison.log', true)

_addon.name = 'NPC Logger'
_addon.version = '0.1'
_addon.author = 'ibm2431'
_addon.commands = {'npclogger'}

logged_npcs = S{}
seen_names = S{}
npc_info = {}
npc_names = {}
npc_raw_names = {}
npc_looks = {}
npc_flags = {}
npc_speeds = {}
npc_speedsubs = {}
npc_animations = {}
npc_animationsubs = {}
npc_namevises = {}
npc_statuses = {}
npc_flagses = {}
npc_name_prefixes = {}
widescan_by_index = {}
widescan_info = {}
npc_ids_by_index = {}

loaded_sql_npcs = {}
loaded_table_npcs = {}
ordered_sql_ids = {}
num_sql_npcs = 0;
id_moved_keys = {} -- Based off captured Lua table

new_npcs = {}
        
basic_npc_info = {}
seen_masks = {
  [0x57] = {},
  [0x07] = {},
  [0x0F] = {}
}

-- =================================================
-- ==    Packet Formatting Functions              ==
-- == Shamelessly stolen from Arcon's PacketViwer ==
-- =================================================
string.hexformat_file = (function()
    -- Precompute hex string tables for lookups, instead of constant computation.
    local top_row = '        |  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F      | 0123456789ABCDEF\n    ' .. '-':rep((16+1)*3 + 2) .. '  ' .. '-':rep(16 + 6) .. '\n'

    local chars = {}
    for i = 0x00, 0xFF do
        if i >= 0x20 and i < 0x7F then
            chars[i] = i:char()
        else
            chars[i] = '.'
        end
    end
    chars[0x5C] = '\\\\'

    local line_replace = {}
    for i = 0x01, 0x10 do
        line_replace[i] = '    %%%%3X |' .. ' %.2X':rep(i) .. ' --':rep(0x10 - i) .. '  %%%%3X | ' .. '%%s\n'
    end
    local short_replace = {}
    for i = 0x01, 0x10 do
        short_replace[i] = '%s':rep(i) .. '-':rep(0x10 - i)
    end

    -- Receives a byte string and returns a table-formatted string with 16 columns.
    return function(str, byte_colors)
        local length = #str
        local str_table = {}
        local from = 1
        local to = 16
        for i = 0, ((length - 1)/0x10):floor() do
            local partial_str = {str:byte(from, to)}
            local char_table = {
                [0x01] = chars[partial_str[0x01]],
                [0x02] = chars[partial_str[0x02]],
                [0x03] = chars[partial_str[0x03]],
                [0x04] = chars[partial_str[0x04]],
                [0x05] = chars[partial_str[0x05]],
                [0x06] = chars[partial_str[0x06]],
                [0x07] = chars[partial_str[0x07]],
                [0x08] = chars[partial_str[0x08]],
                [0x09] = chars[partial_str[0x09]],
                [0x0A] = chars[partial_str[0x0A]],
                [0x0B] = chars[partial_str[0x0B]],
                [0x0C] = chars[partial_str[0x0C]],
                [0x0D] = chars[partial_str[0x0D]],
                [0x0E] = chars[partial_str[0x0E]],
                [0x0F] = chars[partial_str[0x0F]],
                [0x10] = chars[partial_str[0x10]],
            }
            local bytes = (length - from + 1):min(16)
            str_table[i + 1] = line_replace[bytes]
                :format(unpack(partial_str))
                :format(short_replace[bytes]:format(unpack(char_table)))
                :format(i, i)
            from = to + 1
            to = to + 0x10
        end
        return '%s%s':format(top_row, table.concat(str_table))
    end
end)()

-- ======================
-- == Helper Functions ==
-- ======================

-- Converts a string in base base to a number.
--------------------------------------------------
function string.todec(numstr, base)
    -- Create a table of allowed values according to base and how much each is worth.
    local digits = {}
    local val = 0
    for c in ('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'):gmatch('.') do
        digits[c] = val
        val = val + 1
        if val == base then
            break
        end
    end

    local index = base^(#numstr-1)
    local acc = 0
    for c in numstr:gmatch('.') do
        acc = acc + digits[c]*index
        index = index/base
    end

    return acc
end

-- Converts a byte string to a proper integer keeping endianness into account
--------------------------------------------------
function byte_string_to_int(x)
  x = string.todec(x, 16)
  x = bit.bswap(x)
  return x
end

-- =======================
-- == Logging Functions ==
-- =======================

-- Gets an NPC's name and stores it in a table
--------------------------------------------------
function get_npc_name(npc_id)
  local mob = false;
  local npc_name = '';
  mob = windower.ffxi.get_mob_by_id(npc_id);
  
  if (mob) then
    if (mob.name ~= '') then
      npc_names[npc_id] = string.gsub(mob.name, "'", "\'");
      npc_ids_by_index[mob.index] = npc_id;
    else
      npc_names[npc_id] = false;
    end
  else
    npc_names[npc_id] = 'NO_MOB';
  end
end

-- Logs basic NPC information to a table
----------------------------------------------
function get_basic_npc_info(data)
  local name = '';
  local polutils_name = '';
  local model_type = false;
  local individual_npc_info = {};
  
  local packet = packets.parse('incoming', data);
  local npc_id = packet['NPC'];
  
  if (npc_raw_names[npc_id] and npc_names[npc_id]) then
    -- This is a named mob using a hard-set model.
    -- Example: A friendly goblin in town, or a door.
    npc_type = "Simple NPC";
    name = npc_raw_names[npc_id];
    name = string.gsub(name, "'", "_");
    polutils_name = npc_names[npc_id];
    polutils_name = string.gsub(polutils_name, "'", "\\'");
    polutils_name = string.gsub(polutils_name, "\"", "\\\"");
  end
  
  if (npc_names[npc_id]) then
    -- The server didn't send a raw name to us, but
    -- Windower succeeded in getting an NPC name from the client.
    if (not npc_raw_names[npc_id]) then
      -- This is a named NPC whose appearance could be replicated by
      -- players if they wore the same equipment as the NPC.
      -- Example: Arpevion, T.K.
      npc_type = "Equipped NPC";
      polutils_name = npc_names[npc_id];
      polutils_name = string.gsub(polutils_name, "'", "\\'");
      polutils_name = string.gsub(polutils_name, "\"", "\\\"");
      name = string.gsub(polutils_name, " ", "_");
      name = string.gsub(name, "'", "_");
    end
  elseif (not npc_raw_names[npc_id]) then
    -- We can't trust Windower's Model field, so we'll determine
    -- what kind of NPC this is by looking at the width of our
    -- own looks field for the NPC that we recorded previously.
    -- A fully-equipped-type model is 20 bytes, or 40 characters.
    if (string.len(npc_looks[npc_id]) == 40) then
      -- This is an NPC used strictly in a CS, but doesn't have
      -- its own special appearance like storyline NPCs, so
      -- its appearance is built via equipment.
      -- Example: Filler NPCs walking around town during a CS,
      -- or unnamed Royal Knights who guard the king.
      npc_type = 'CS NPC';
      name = 'csnpc';
      polutils_name = '     ';
    else
      -- This is a completely unnamed mob with a simple appearance.
      -- It's probably a decoration of some kind.
      -- Example: The special decorations in towns during festivals.
      npc_type = 'Decoration';
      name = 'blank';
      polutils_name = '     ';
    end
  end
  
  individual_npc_info["NPC_ID"] = npc_id;
  individual_npc_info["Name"] = name;
  individual_npc_info["POLUtils_Name"] = polutils_name;
  individual_npc_info["NPC_Type"] = npc_type;
  individual_npc_info["Index"] = packet['Index'];
  individual_npc_info["X"] = packet['X'];
  individual_npc_info["Y"] = packet['Z']; -- Windower and DSP have these axis swapped vs each other
  individual_npc_info["Z"] = packet['Y'];
  individual_npc_info["R"] = packet['Rotation'];
  
  basic_npc_info[npc_id] = individual_npc_info;
  
  if (widescan_by_index[packet['Index']] and (not widescan_info[npc_id])) then
    widescan_info[npc_id] = widescan_by_index[packet['Index']];
    widescan_info[npc_id]['id'] = npc_id;
    write_widescan_info(npc_id);
  end
end

-- Returns a string of an NPC's basic info, to be printed when logging
----------------------------------------------
function basic_npc_info_string(npc_id)
  local npc_info = basic_npc_info[npc_id];
  return string.format(
    "NPC ID: %d\n  Name: %s\n  POLUtils_Name: %s\n  NPC Type: %s\n  XYZR: %.3f, %.3f, %.3f, %d\n",
    npc_info["NPC_ID"],
    npc_info["Name"],
    npc_info["POLUtils_Name"],
    npc_info["NPC_Type"],
    npc_info["X"],
    npc_info["Y"],
    npc_info["Z"],
    npc_info["R"]
  )
end

-- Converts a hex string to a proper-endianned integer
--------------------------------------------------
function hex_data_to_int(hex_string)
  local from_hex_representation = tonumber(hex_string, 16);
  local byte_swapped = bit.bswap(from_hex_representation);
  return tonumber(byte_swapped, 10);
end

-- Builds string for raw logging
--------------------------------------------------
function log_raw(npc_id, mask, data)
  local info_string = basic_npc_info_string(npc_id);
  local hex_data = data:hexformat_file();
  local mask = string.lpad(mask:binary(), "0", 8);
  local log_string = '%s  Mask: %s\n%s\n':format(info_string, mask, hex_data);
  file.full:append(log_string);
end

-- Builds a table for an NPC's info
--------------------------------------------------
function build_individual_npc_info(npc_id)
  local npc_info = basic_npc_info[npc_id];
  
  npc_info["Flag"] = npc_flags[npc_id];
  npc_info["Speed"] = npc_speeds[npc_id];
  npc_info["Speedsub"] = npc_speedsubs[npc_id];
  npc_info["Animation"] = npc_animations[npc_id];
  npc_info["Animation_Sub"] = npc_animationsubs[npc_id];
  npc_info["Namevis"] = npc_namevises[npc_id];
  npc_info["Status"] = npc_statuses[npc_id];
  npc_info["Flags"] = npc_flagses[npc_id];
  npc_info["Name_Prefix"] = npc_name_prefixes[npc_id];
  
  return npc_info;
end

-- Logs original packet data for an NPC into table
--------------------------------------------------
function log_packet_to_table(npc_id, data)
  local log_string = '';
  local npc_info = build_individual_npc_info(npc_id)
 
  log_string = log_string .. "    [".. tostring(npc_id) .."] = {";
  log_string = log_string .. string.format(
    "['id']=%d, ['name']=\"%s\", ['polutils_name']=\"%s\", ['npc_type']=\"%s\", ['index']=%d, ['x']=%.3f, ['y']=%.3f, ['z']=%.3f, ['r']=%d, ['flag']=%d, ['speed']=%d, ['speedsub']=%d, ['animation']=%d, ['animationsub']=%d, ['namevis']=%d, ['status']=%d, ['flags']=%d, ['name_prefix']=%d, ",
    npc_info["NPC_ID"],
    npc_info["Name"],
    npc_info["POLUtils_Name"],
    npc_info["NPC_Type"],
    npc_info["Index"],
    npc_info["X"],
    npc_info["Y"],
    npc_info["Z"],
    npc_info["R"],
    npc_info["Flag"],
    npc_info["Speed"],
    npc_info["Speedsub"],
    npc_info["Animation"],
    npc_info["Animation_Sub"],
    npc_info["Namevis"],
    npc_info["Status"],
    npc_info["Flags"],
    npc_info["Name_Prefix"]
  )
  if (npc_looks[npc_id]) then
    log_string = log_string .. "['look']=\"".. npc_looks[npc_id] .."\", ";
  end
  log_string = log_string .. "['raw_packet']=\"".. data:hex() .."\"";
  log_string = log_string .. "},\n"
  file.packet_table:append(log_string);
end

-- Reads an NPC SQL file and loads their values into a Lua table
--------------------------------------------------
function load_sql_into_table(zone)
  local id, name, polutils_name, r, x, y, z, flag, speed, speedsub, animation, animationsub, namevis, status, flags, look, name_prefix, required_expansion, widescan;
  local capture_string = "(%d+),(.*),(.*),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,']+),([^,']+),([^,']+),([^,]+),([^,']+),([^,]+),([^,]+)";
  
  local lines = files.readlines("data/current_sql/".. zone ..".sql")
  local loaded_npc = {}
  local num_loaded_npcs = 1
  for _,v in pairs(lines) do
    if (v) then
      v = string.gsub(v, ",'", ",");
      v = string.gsub(v, "',", ",");
      _, _, id, name, polutils_name, r, x, y, z, flag, speed, speedsub, animation, animationsub, namevis, status, flags, look, name_prefix, required_expansion, widescan = string.find(v, capture_string);
      loaded_npc = {}
      if (id) then
        loaded_npc['id'] = tonumber(id);
        loaded_npc['name'] = name;
        loaded_npc['polutils_name'] = polutils_name;
        loaded_npc['r'] = tonumber(r);
        loaded_npc['x'] = tonumber(x);
        loaded_npc['y'] = tonumber(y);
        loaded_npc['z'] = tonumber(z);
        loaded_npc['flag'] = tonumber(flag);
        loaded_npc['speed'] = speed;
        loaded_npc['speedsub'] = speedsub;
        loaded_npc['animation'] = tonumber(animation);
        loaded_npc['animationsub'] = tonumber(animationsub);
        loaded_npc['namevis'] = tonumber(namevis);
        loaded_npc['status'] = tonumber(status);
        loaded_npc['flags'] = tonumber(flags);
        loaded_npc['look'] = look;
        loaded_npc['name_prefix'] = tonumber(name_prefix);
        loaded_npc['widescan'] = widescan;
        loaded_npc['order'] = num_loaded_npcs;
        ordered_sql_ids[num_loaded_npcs] = tonumber(id);
        loaded_sql_npcs[tonumber(id)] = loaded_npc;
        num_loaded_npcs = num_loaded_npcs + 1;
      end
    end
  end
  num_sql_npcs = num_loaded_npcs;
end

-- Loads a table of NPC packets that NPC Logger logged itself.
--------------------------------------------------
function load_npc_packet_table(zone)
  local packet_table = require("data/tables/".. zone);
  local moved_id_key = '';
  loaded_table_npcs = table.sort(packet_table);
  -- Store a "hash" of the NPCs name, position, and look. We can use this to
  -- help see if an NPC was simply moved to a new ID (rather than being changed.)
  for k,v in pairs(loaded_table_npcs) do
    v['look'] = "0x".. string.rpad(v['look'], "0", 40)
    -- I didn't properly convert for endianness for first logging. Converting here for now.
    v['flag'] = byte_string_to_int(string.sub(v['raw_packet'], (0x18*2)+1, (0x1C*2)));
    v['flags'] = byte_string_to_int(string.sub(v['raw_packet'], (0x21*2)+1, (0x25*2)));
    moved_id_key = make_moved_id_key(v);
    id_moved_keys[moved_id_key] = k;
  end
end

-- Compares two NPC tables and returns false if there's no differences.
-- If there is a difference, will return the first one as a string.
--------------------------------------------------
function compare_npcs(sql_npc, npclogger_npc)
  local changed = false;
  local changes = '';
  local keys = {'polutils_name', 'x', 'y', 'z', 'animation', 'animationsub', 'status', 'flags', 'namevis', 'name_prefix', 'look'}
  -- A list of flags to avoid printing changes for if changing from one
  -- flag in the list to another in the list.
  local ignore_flags = S{1, 6, 7, 8, 14, 16, 21, 22, 29}
  for _,v in pairs(keys) do
    if (sql_npc[v] ~= npclogger_npc[v]) then
      changes = changes .. "'".. v .."': ".. sql_npc[v] .." changed to ".. npclogger_npc[v] .. " ";
      changed = true;
    end
  end
  if (sql_npc['flag'] ~= npclogger_npc['flag']) then
    if (changed) then
      changes = changes .. "'flag': ".. sql_npc['flag'] .." changed to ".. npclogger_npc['flag'] .. " ";
    elseif (not (ignore_flags[sql_npc['flag']] and ignore_flags[sql_npc['flag']])) then
      changes = changes .. "'flag': ".. sql_npc['flag'] .." changed to ".. npclogger_npc['flag'] .. " ";
      changed = true;
    end
  end
  if (changed) then
    if (sql_npc['r'] ~= npclogger_npc['r']) then
      changes = changes .. "'r': ".. sql_npc['r'] .." changed to ".. npclogger_npc['r'] .. " ";
    end
    return changes;
  else
    return changed;
  end
end

-- Makes a string key for use in checking if a NPC's ID was moved
--------------------------------------------------
function make_moved_id_key(table)
  local table_keys = {'polutils_name', 'x', 'y', 'z', 'r', 'animation', 'animationsub', 'status', 'flag', 'flags', 'namevis', 'name_prefix'}
  local key = '';
  for _,v in pairs(table_keys) do
    -- In here due to Bastok Markets? Bad ID is 17739777.
    key = key .. table[v];
  end
  return key;
end

-- Compares two loaded NPC tables (from target SQL, and NPC Logger's table).
--------------------------------------------------
function compare_npc_tables()
  local npc_comparison = '';
  local moved_id_key = '';
  local sql_line = '';
  local k = 0;
  for i = 1, (num_sql_npcs - 1) do -- Force traversing in current SQL list order.
    k = ordered_sql_ids[i];
    v = loaded_sql_npcs[k];
    if (loaded_table_npcs[k]) then
      moved_id_key = make_moved_id_key(v);
      npc_comparison = compare_npcs(loaded_sql_npcs[k], loaded_table_npcs[k]);
      if (npc_comparison) then
        if (false) then
        --if (id_moved_keys[moved_id_key] and (id_moved_keys[moved_id_key] ~= v['id'])) then
          -- We found an NPC with the same name, position, and look, but with a different ID.
          -- Print the probable new ID.
          
          file.compare:append("CHANGED: ".. k .."; ".. npc_comparison .."\n");
          file.compare:append("MOVED?: ".. k .."; to ".. id_moved_keys[moved_id_key] .."\n");
          sql_line = make_sql_insert_string(loaded_table_npcs[k]);
          file.compare:append(sql_line .."\n");
          --print("CHANGED: ".. k .."; ".. npc_comparison);
          --print("MOVED?: ".. k .."; to ".. id_moved_keys[moved_id_key])
        else
          if (not ((v['id'] >= 17744056) and (v['id'] <= 17744148))) then
            file.compare:append("CHANGED: ".. k .."; ".. npc_comparison .."\n");
          end
          sql_line = make_sql_insert_string(loaded_table_npcs[k]);
          file.compare:append(sql_line .."\n");
        end
      else
        -- print("VERIFIED: ".. k.."; ".. loaded_sql_npcs[k]['name']);
      end
    else
      file.compare:append("NOT FOUND: ".. k .."\n");
      --print("NOT FOUND: ".. k);
    end
  end
  file.compare:append("NEW NPCS: \n");
  -- Yes, we have to go through the new NPCs twice. The first time
  -- is to sort a list of keys, because Lua can't key sort.
  for k,v in pairs(loaded_table_npcs) do
    if (not loaded_sql_npcs[k]) then
      table.insert(new_npcs, k)
    end
  end
  table.sort(new_npcs)
  for _,v in pairs(new_npcs) do
    sql_line = make_sql_insert_string(loaded_table_npcs[v])
    file.compare:append(sql_line .."\n");
    --print("ADDED: ".. k .."; ".. loaded_table_npcs[k]['name']);
  end
end

-- Takes an NPC table and outputs and appropriate input statement
--------------------------------------------------
function make_sql_insert_string(npc)
  local sql_line = string.format(
    "INSERT INTO `npc_list` VALUES (%d,'%s','%s',%d,%.3f,%.3f,%.3f,%d,%d,%d,%d,%d,%d,%d,%d,%s,%d,%s,%d);",
    npc["id"],
    string.gsub(npc["name"], "'", "_"),
    string.gsub(npc["polutils_name"], "'", "\'"),
    npc["r"],
    npc["x"],
    npc["y"],
    npc["z"],
    npc["flag"],
    npc["speed"],
    npc["speedsub"],
    npc["animation"],
    npc["animationsub"],
    npc["namevis"],
    npc["status"],
    npc["flags"],
    npc['look'],
    npc["name_prefix"],
    'null',
    0
  )
  return sql_line;
end

-- Writes a mob's widescan info to a table log
--------------------------------------------------
function write_widescan_info(npc_id)
  local log_string = "    [".. tostring(npc_id) .."] = {";
  log_string = log_string .. string.format(
    "['id']=%d, ['name']=\"%s\", ['index']=%d, ['level']=%d",
    widescan_info[npc_id]['id'],
    widescan_info[npc_id]['name'],
    widescan_info[npc_id]['index'],
    widescan_info[npc_id]['level']
  )
  log_string = log_string .. "},\n"
  file.widescan:append(log_string);
end

function check_incoming_chunk(id, data, modified, injected, blocked)
  local packet = packets.parse('incoming', data)

  if (id == 0x00E) then
    local mask = packet['Mask'];
    if (seen_masks[mask] and (not seen_masks[mask][packet['NPC']])) then
      local npc_id = packet['NPC'];
      if ((packet['Name'] ~= '') and (not npc_raw_names[packet['NPC']]) and (not (mask == 0x57))) then
        -- Valid raw name we haven't seen yet is set.
        npc_raw_names[packet['NPC']] = packet['Name'];
      end
      if ((mask == 0x57) or (mask == 0x0F) or (mask == 0x07)) then
        windower.add_to_chat(7, "[NPC Logger] Logged NPC ID: " .. packet['NPC']);
        
        if (mask == 0x57) then
          -- Equipped model.
          npc_looks[packet['NPC']] = string.sub(data:hex(), (0x30*2)+1, (0x44*2));
        elseif ((mask == 0x0F) or (mask == 0x07)) then
          -- Basic/standard NPC model.
          npc_looks[packet['NPC']] = string.sub(data:hex(), (0x30*2)+1, (0x34*2));
        end
        
        npc_flags[npc_id] = byte_string_to_int(string.sub(data:hex(), (0x18*2)+1, (0x1C*2)));
        npc_speeds[npc_id] = tonumber(string.sub(data:hex(), (0x1C*2)+1, (0x1D*2)), 16);
        npc_speedsubs[npc_id] = tonumber(string.sub(data:hex(), (0x1D*2)+1, (0x1E*2)), 16);
        npc_animations[npc_id] = tonumber(string.sub(data:hex(), (0x1F*2)+1, (0x20*2)), 16);
        npc_animationsubs[npc_id] = tonumber(string.sub(data:hex(), (0x2A*2)+1, (0x2B*2)), 16);
        npc_namevises[npc_id] = tonumber(string.sub(data:hex(), (0x2B*2)+1, (0x2C*2)), 16);
        npc_statuses[npc_id] = tonumber(string.sub(data:hex(), (0x20*2)+1, (0x21*2)), 16);
        npc_flagses[npc_id] = byte_string_to_int(string.sub(data:hex(), (0x21*2)+1, (0x25*2)));
        npc_name_prefixes[npc_id] = tonumber(string.sub(data:hex(), (0x27*2)+1, (0x28*2)), 16);
        
        if (not basic_npc_info[npc_id]) then
          -- Give the game a second or two to load the mob into memory before using Windower functions.
          coroutine.schedule(function() get_npc_name(npc_id) end, 2);
          coroutine.schedule(function() get_basic_npc_info(data) end, 2.2);
        end
        coroutine.schedule(function() log_raw(packet['NPC'], packet['Mask'], data) end, 3);
        coroutine.schedule(function() log_packet_to_table(packet['NPC'], data) end, 3.2);
        seen_masks[mask][npc_id] = true;
      end
    end
  elseif (id == 0xF4) then
    local index, name, level = packet["Index"], packet["Name"], packet["Level"];
    if (not widescan_by_index[index]) then
      widescan_by_index[index] = {['index']=index,['name']=name,['level']=level};
      local npc_id = npc_ids_by_index[index];
      if (npc_id and (not widescan_info[npc_id])) then
        widescan_info[npc_id] = widescan_by_index[index];
        widescan_info[npc_id]['id'] = npc_id;
        write_widescan_info(npc_id);
      end
    end
  end
end

windower.register_event('zone change', function(new, old)
  local current_zone = res.zones[new].en;
  file.packet_table = files.new('data/tables/'.. current_zone ..'.lua', true)
  file.full = files.new('data/logs/'.. current_zone ..'.log', true)
  file.widescan = files.new('data/widescan/'.. current_zone ..'.log', true)
  widescan_by_index = {}
  widescan_info = {}
  npc_ids_by_index = {}
end)

windower.register_event('incoming chunk', check_incoming_chunk);
--load_sql_into_table("West Ronfaure");
--load_npc_packet_table("West Ronfaure");
--compare_npc_tables();