require 'luau'
res = require('resources')
packets = require('packets')
pack = require('pack')

_addon.name = 'IDView'
_addon.version = '0.1'
_addon.author = 'ibm2431'
_addon.commands = {'idview'}

function check_outgoing_chunk(id, data, modified, injected, blocked)
  local update_packet = packets.parse('outgoing', data)
  local log_string = "";
  local mob;
  local mob_name;
  if (junk_outgoing_packets[id] ~= true) then
    log_string = "Outgoing Packet: ";
    if (id == 0x05B) then
      -- Dialog Choice
      mob = windower.ffxi.get_mob_by_id(update_packet['Target']);
      if (mob) then mob_name = mob.name end;
      
      if (update_packet['Option Index'] ~= 0) then
        log_string = log_string .. '0x05B (Event Option), ';
        log_string = log_string .. 'NPC: ' .. update_packet['Target'];
        if (mob_name) then log_string = log_string .. ' ('.. mob.name ..')' end;
        log_string = log_string .. string.format(', Event: 0x%04X, ', update_packet['Menu ID']);
        log_string = log_string .. 'Option: '.. update_packet['Option Index'];
      else
        log_string = 'Event Release, NPC : '.. update_packet['Target'];
        if (mob_name) then log_string = log_string .. ' ('.. mob.name ..')' end;
        log_string = log_string .. string.format(', Event: 0x%04X, ', update_packet['Menu ID']);
      end
    end
    
    if (log_string ~= "Outgoing Packet: ") then
      windower.add_to_chat(7, "[ID View] " .. log_string)
    end
  end
end

function check_incoming_chunk(id, data, modified, injected, blocked)
  local update_packet = packets.parse('incoming', data)
  local log_string = "";
  local mob;
  local mob_name;
  if (junk_incoming_packets[id] ~= true) then
    log_string = "Incoming Packet: ";
    if (id == 0x036) then
      -- NPC Chat
      log_string = log_string .. '0x036 (NPC Chat), ';
      log_string = log_string .. 'Actor: ' .. update_packet['Actor'];
      mob = windower.ffxi.get_mob_by_id(update_packet['Actor']);
      if (mob) then mob_name = mob.name end;
      if (mob_name) then log_string = log_string .. ' ('.. mob.name ..')' end;
      log_string = log_string .. ', Message: '.. update_packet['Message ID'];
    elseif ((id == 0x032) or (id == 0x034)) then
      -- Event CS
      if (id == 0x032) then
        log_string = log_string .. '0x032 (CS Event), ';
      else
        log_string = log_string .. '0x034 (CS Event), ';
      end
      log_string = log_string .. 'NPC: ' .. update_packet['NPC'];
      mob = windower.ffxi.get_mob_by_id(update_packet['NPC']);
      if (mob) then mob_name = mob.name end;
      if (mob_name) then log_string = log_string .. ' ('.. mob.name ..')' end;
      log_string = log_string .. string.format(', Event: 0x%04X', update_packet['Menu ID']);
    end
    
    if (log_string ~= "Incoming Packet: ") then
      windower.add_to_chat(7, "[ID View] " .. log_string);
    end
  end
end

windower.register_event('outgoing chunk', check_outgoing_chunk);
windower.register_event('incoming chunk', check_incoming_chunk);