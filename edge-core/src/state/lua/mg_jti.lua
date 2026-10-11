-- mg_jti v1
-- KEYS[1] = mg:jti:{site}:{kj}:{jti}
-- KEYS[2] = mg:jc:{site}:{kj}
-- ARGV[1] = per-key limit (600)
-- ARGV[2] = counter window in ms (60000)
-- ARGV[3] = jti TTL in s (40)
-- returns {0} fresh, {1} replay, {2} per-key quota exceeded (treated as a replay of this key only)
local n = tonumber(redis.call('GET', KEYS[2]) or '0') + 1
if n > tonumber(ARGV[1]) then
  return {2}
end
if n == 1 then
  redis.call('SET', KEYS[2], '1', 'PX', tonumber(ARGV[2]))
else
  redis.call('SET', KEYS[2], tostring(n), 'KEEPTTL')
end
if not redis.call('SET', KEYS[1], '1', 'NX', 'EX', tonumber(ARGV[3])) then
  return {1}
end
return {0}
