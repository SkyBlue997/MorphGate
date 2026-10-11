-- mg_verdict_put v1
-- KEYS[1] = mg:v:{site}:{type}:{key}
-- ARGV[1] = verdict JSON (EntityVerdict with source "nearline/<detector>")
-- ARGV[2] = TTL in ms (>= 1000)
-- ARGV[3] = risk of the new verdict (0..100)
-- ARGV[4] = now_ms
-- ARGV[5] = source of the new verdict ("nearline/<detector>")
-- returns 1 when written, 0 when an existing live verdict wins
local cur = redis.call('GET', KEYS[1])
if cur then
  local ok, v = pcall(cjson.decode, cur)
  if not ok or type(v) ~= 'table' then
    return 0
  end
  local exp = tonumber(v['expires_at_ms']) or 0
  if exp > tonumber(ARGV[4]) then
    local src = v['source']
    if type(src) ~= 'string' or string.sub(src, 1, 9) ~= 'nearline/' then
      return 0
    end
    if src ~= ARGV[5] and (tonumber(v['risk']) or 0) >= tonumber(ARGV[3]) then
      return 0
    end
  end
end
redis.call('SET', KEYS[1], ARGV[1], 'PX', tonumber(ARGV[2]))
return 1
