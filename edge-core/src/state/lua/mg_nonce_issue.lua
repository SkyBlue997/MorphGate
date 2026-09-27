-- mg_nonce_issue v1
-- KEYS[1]          = mg:n:{site}:{nonce_hex}
-- KEYS[1 + i]      = mg:rl:{site}:{limiter}:{kh}      issuance limiters, i >= 1 (may be none)
-- ARGV[1]          = nonce TTL in ms (>= 1)
-- ARGV[2]          = now_us ("0" = server clock)
-- ARGV[3 + 3(i-1)] = interval_us, ARGV[4 + 3(i-1)] = burst, ARGV[5 + 3(i-1)] = cost
-- returns {1, allowed, retry_after_us, tat_minus_now_us, ...} or {0} when the nonce was already used
if not redis.call('SET', KEYS[1], '1', 'NX', 'PX', tonumber(ARGV[1])) then
  return {0}
end
local now = tonumber(ARGV[2])
if now == 0 then
  local t = redis.call('TIME')
  now = tonumber(t[1]) * 1000000 + tonumber(t[2])
end
local out = {1}
local writes = {}
local all_allowed = true
for i = 2, #KEYS do
  local base = 3 + (i - 2) * 3
  local interval = tonumber(ARGV[base])
  local burst = tonumber(ARGV[base + 1])
  local cost = tonumber(ARGV[base + 2])
  local dvt = interval * burst
  local tat = tonumber(redis.call('GET', KEYS[i]) or '0')
  if tat < now then tat = now end
  local new_tat = tat + interval * cost
  local allow_at = new_tat - dvt
  if now < allow_at then
    all_allowed = false
    out[#out + 1] = 0
    out[#out + 1] = allow_at - now
    out[#out + 1] = tat - now
  else
    writes[#writes + 1] = {KEYS[i], new_tat}
    out[#out + 1] = 1
    out[#out + 1] = 0
    out[#out + 1] = new_tat - now
  end
end
if all_allowed then
  for _, w in ipairs(writes) do
    local ttl_ms = math.ceil((w[2] - now) / 1000)
    if ttl_ms < 1 then ttl_ms = 1 end
    redis.call('SET', w[1], string.format('%d', w[2]), 'PX', ttl_ms)
  end
end
return out
