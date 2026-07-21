-- Pure Lua 5.3+ SHA-256 (NIST FIPS 180-4)
local sha256 = {}

local K = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
}

local MASK = 0xFFFFFFFF

local function rrot(x, n)
  x = x & MASK
  return ((x >> n) | (x << (32 - n))) & MASK
end

function sha256.digest(msg)
  local h0,h1,h2,h3,h4,h5,h6,h7 =
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19

  local len = #msg
  local bitlen = len * 8
  msg = msg .. "\128"
  while (#msg % 64) ~= 56 do
    msg = msg .. "\0"
  end
  -- 64-bit big-endian length (we only need the low 32 bits realistically, but do it right)
  local hi = math.floor(bitlen / 0x100000000) & MASK
  local lo = bitlen & MASK
  msg = msg .. string.pack(">I4I4", hi, lo)

  for chunkStart = 1, #msg, 64 do
    local w = {}
    for i = 0, 15 do
      w[i] = string.unpack(">I4", msg, chunkStart + i*4)
    end
    for i = 16, 63 do
      local w15, w2 = w[i-15], w[i-2]
      local s0 = rrot(w15,7) ~ rrot(w15,18) ~ (w15 >> 3)
      local s1 = rrot(w2,17) ~ rrot(w2,19) ~ (w2 >> 10)
      w[i] = (w[i-16] + s0 + w[i-7] + s1) & MASK
    end

    local a,b,c,d,e,f,g,h = h0,h1,h2,h3,h4,h5,h6,h7
    for i = 0, 63 do
      local S1 = rrot(e,6) ~ rrot(e,11) ~ rrot(e,25)
      local ch = (e & f) ~ ((~e) & g)
      local temp1 = (h + S1 + ch + K[i+1] + w[i]) & MASK
      local S0 = rrot(a,2) ~ rrot(a,13) ~ rrot(a,22)
      local maj = (a & b) ~ (a & c) ~ (b & c)
      local temp2 = (S0 + maj) & MASK
      h = g
      g = f
      f = e
      e = (d + temp1) & MASK
      d = c
      c = b
      b = a
      a = (temp1 + temp2) & MASK
    end

    h0 = (h0 + a) & MASK
    h1 = (h1 + b) & MASK
    h2 = (h2 + c) & MASK
    h3 = (h3 + d) & MASK
    h4 = (h4 + e) & MASK
    h5 = (h5 + f) & MASK
    h6 = (h6 + g) & MASK
    h7 = (h7 + h) & MASK
  end

  return string.pack(">I4I4I4I4I4I4I4I4", h0,h1,h2,h3,h4,h5,h6,h7)
end

return sha256
