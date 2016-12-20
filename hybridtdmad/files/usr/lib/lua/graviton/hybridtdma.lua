#!/usr/bin/lua
-- HybridTDMA - Lua module for HMAC Hybrid TDMA/CSMA
-- based on https://github.com/szehl/ath9k-hmac
-- Copyright 2016 Vincent Wiemann <vincent.wiemann@ironai.com>
-- This is free software, licensed under the Apache 2.0 license.

local zmq = require "lzmq"
HybridTDMA = {}
HybridTDMA.__index = HybridTDMA

function HybridTDMA.init(interface, no_slots_in_superframe, slot_duration_ns,
                         local_mac_processor_port=1217,
                         hmac_binary_path='/bin/hybrid_tdma')
  -- The configuration of such a MAC is described by:
  -- :param no_slots_in_superframe: the total number of slots in a superframe
  -- :param slot_duration_ns: the time duration of each slot (microseconds)
  -- :param hmac_binary_path: path to the C++ userland HMAC daemon
  -- :param local_mac_processor_port: ZeroMQ port used for communication with HMAC daemon
  local selftp = {}
  setmetatable(selftp, HybridTDMA)
  selftp.interface = interface
  selftp.slot_count = no_slots_in_superframe
  selftp.slot_duration = slot_duration_ns
  selftp.acs = {}
  for i = 0, no_slots_in_superframe do
    acs[i]={}
  end
  selftp.hmac_binary_path = hmac_binary_path
  selftp.zmqport = local_mac_processor_port
  selftp.state = 0 -- not running
  return selftp
end

function HybridTDMA:setAccessPolicies(slot_nr, ac)
  -- Sets an access policy to a given slot in the superframe
  -- :param slot_nr: the slot id to which the access policy to apply
  -- :param ac: the access policy
  if slot_nr >= 0 and slot_nr < #self.acs then
    self.acs[slot_nr] = ac
    return true
  end
  return false
end

function HybridTDMA:getAccessPolicies(slot_nr)
  -- Get the access policy assigned to given slot.
  -- :param slot_nr: ID starting from 0.
  -- :return: AccessPolicy object
  if slot_nr >= 0 and slot_nr < #self.acs then
    return self.acs[slot_nr]
  end
  return false
end

function HybridTDMA:removeAccessPolicies(slot_nr)
  -- Block usage of time slot for all packets
  -- Removes the access policy assigned to given slot.
  -- :param slot_nr: ID starting from 0.
  return self:setAccessPolicies(slot_nr, {})
end

function HybridTDMA:setAllowAllAccessPolicy(slot_nr)
  -- Unblock usage of time slot for all packets
  local entry = {}
  entry['FF:FF:FF:FF:FF:FF'] = 255
  return self:setAccessPolicies(slot_nr, entry)
end

function HybridTDMA:addAccessPolicyToSbyDestMAC(slot_nr, dstHwAddr, tosArgs)
  -- Add destination mac address and list of ToS fields which is allowed to be transmitted in this time slot
  -- :param slot_nr: ID starting from 0.
  -- :param dstHwAddr: destination mac address
  -- :param tosArgs: list of ToS values to be allowed here
  local tid_map = 0
  local ac = self:getAccessPolicies(slot_nr)
  for i,v in ipairs(tosArgs) do
    local tos = bit.tobit(v)
    local skb_prio = bit.rshift(bit.band(tos, 30), 1)
    local tid = bit.band(skb_prio, 7)
    tid_map = bit.bor(tid_map, bit.tobit(math.pow(2, tid)))
  end
  ac[dstHwAddr] = tid_map
  return self:setAccessPolicies(slot_nr, ac)
end
 
function HybridTDMA:printCfg()
  -- Return the MAC configuration serialized as string.
  local ret=""
  for i = 0, self.slot_count do
    local ac = self:getAccessPolicies(i)
    ret += tostr(i) .. ':'
    for k, v in pairs(ac) do
      ret += k .. '/' .. tostr(v)
    end
  end
  print(ret)
end

function HybridTDMA:createCfgStr()
  local conf_str = ""
  for i, self.slot_count do
    local entries = self:getAccessPolicies(i)
    for k, v in pairs(entries) do
      if conf_str == "" then
        conf_str = tostr(i) .. "," .. k .. "," .. tostr(v)
      else
        conf_str += "#" .. tostr(i) .. "," .. k .. "," .. tostr(v)
      end
    end
  end
  return conf_str
end

function HybridTDMA:createAllowAllCfgStr()
  local conf_str = ""
  for i, self.slot_count do
    if conf_str == "" then
      conf_str = tostr(i) .. "," .. 'FF:FF:FF:FF:FF:FF' .. "," .. tostr(255)
    else
      conf_str += "#" .. tostr(i) .. "," .. 'FF:FF:FF:FF:FF:FF' .. "," .. tostr(255)
    end
  end
  return conf_str
end

function HybridTDMA:installMACProc()
  -- Installs the given hybrid MAC configuration
  if self.state == 1 then 
    print("HMAC is already running; use updateMACProc() to update at run-time")
    return false 
  end
  local conf_str = self:createCfgStr()
  local processArgs = self.hmac_binary_path .. " -d 0 -i" + tostr(self.interface) \
                      .. " -f" .. tostr(self.slot_duration) .. " -n" .. tostr(self.slot_count) .. " -c" .. conf_str
  print("Starting HMAC daemon with: " .. processArgs)
  io.popen(processArgs)
  self.state = 1
  return true
end

function HybridTDMA:updateMACProc()
  -- Updates the given hybrid MAC configuration at run-time with new configuration
  if self.state == 0 then 
    print("HMAC is not running, yet; start it first!")
    return false 
  end
  local conf_str = self:createCfgStr()
  if not self.hmac_ctrl_socket then
    local context = zmq.context()
    self.hmac_ctrl_socket = context:socket{zmq.REQ, linger = 0, \
                rcvtimeo = 1000; connect = "tcp://localhost:" .. tostr(self.zmqport); }
  end
  print("Send ctrl req message to HMAC:" .. conf_str)
  self.hmac_ctrl_socket:send(conf_str)
  local message = self.hmac_ctrl_socket:recv()
  print("Received ctrl reply message from HMAC: " .. message)
  return true
end

function HybridTDMA:uninstallMACProc()
  -- Updates the given hybrid MAC configuration at run-time with new configuration
  if self.state == 0 then 
    print("HMAC is already stopped")
    return true
  end
  local conf_str = self:createCfgStr()
  local terminate_str = 'TERMINATE'
  if not self.hmac_ctrl_socket then
    local context = zmq.context()
    self.hmac_ctrl_socket = context:socket{zmq.REQ, linger = 0, \
                rcvtimeo = 1000; connect = "tcp://localhost:" .. tostr(self.zmqport); }
  end
  print("Send ctrl req message to HMAC:" .. conf_str)
  self.hmac_ctrl_socket:send(conf_str)
  local message = self.hmac_ctrl_socket:recv()
  print("Received ctrl reply message from HMAC: " .. message)
  os.exec("sleep 2")
  print("Sending termination string")
  self.hmac_ctrl_socket:send(terminate_str)
  message = self.hmac_ctrl_socket:recv()
  print("Received ctrl reply message from HMAC: " .. message)
  self.state = 0
  return true
end

return HybridTDMA

