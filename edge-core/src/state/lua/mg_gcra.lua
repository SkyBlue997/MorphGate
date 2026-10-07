-- mg_gcra v1
-- KEYS[i]           = mg:rl:{site}:{limiter}:{kh}
-- ARGV[1]           = now_us ("0" = use the server clock: TIME)
-- ARGV[2 + 4(i-1)]  = interval_us  (period_s * 1e6 / rate, floor)
-- ARGV[3 + 4(i-1)]  = burst        (>= 1)
-- ARGV[4 + 4(i-1)]  = cost         (>= 1)
-- ARGV[5 + 4(i-1)]  = write        (1 = store the new TAT when allowed, 0 = check only)
-- returns a flat array, 3 integers per key: allowed (1|0), retry_after_us, tat_minus_now_us
local now = tonumber(ARGV[1])
if now == 0 then
  local t = redis.call('TIME')
  now = tonumber(t[1]) * 1000000 + tonumber(t[2])
end
local out = {}
for i = 1, #KEYS do
  local base = 2 + (i - 1) * 4
  local interval = tonumber(ARGV[base])
  local burst = tonumber(ARGV[base + 1])
  local cost = tonumber(ARGV[base + 2])
  local write = tonumber(ARGV[base + 3])
  local dvt = interval * burst
  local tat = tonumber(redis.call('GET', KEYS[i]) or '0')
  if tat < now then tat = now end
  local new_tat = tat + interval * cost
  local allow_at = new_tat - dvt
  if now < allow_at then
    out[#out + 1] = 0
    out[#out + 1] = allow_at - now
    out[#out + 1] = tat - now
  else
    if write == 1 then
      local ttl_ms = math.ceil((new_tat - now) / 1000)
      if ttl_ms < 1 then ttl_ms = 1 end
      redis.call('SET', KEYS[i], string.format('%d', new_tat), 'PX', ttl_ms)
    end
    out[#out + 1] = 1
    out[#out + 1] = 0
    out[#out + 1] = new_tat - now
  end
end
return out
