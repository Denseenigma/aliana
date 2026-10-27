"""
qr.py - tiny dependency-free QR code generator (byte mode, error correction
level M, versions 1-10 -- plenty for a URL). Outputs an SVG string.

Follows the QR spec / Nayuki's reference implementation. Kept in-repo so the
Pi doesn't need an extra package and works fully offline.
"""

# Error-correction level M tables, index = version (0 unused)
_ECC_PER_BLOCK = [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26]
_NUM_BLOCKS = [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5]
_FORMAT_BITS_M = 0  # L=1, M=0, Q=3, H=2


def _raw_data_modules(ver):
    result = (16 * ver + 128) * ver + 64
    if ver >= 2:
        n = ver // 7 + 2
        result -= (25 * n - 10) * n - 55
        if ver >= 7:
            result -= 36
    return result


def _data_codewords(ver):
    return _raw_data_modules(ver) // 8 - _ECC_PER_BLOCK[ver] * _NUM_BLOCKS[ver]


# --- Reed-Solomon over GF(256), polynomial 0x11D ---

def _gf_mul(x, y):
    z = 0
    for i in reversed(range(8)):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z & 0xFF


def _rs_divisor(degree):
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            result[j] = _gf_mul(result[j], root)
            if j + 1 < degree:
                result[j] ^= result[j + 1]
        root = _gf_mul(root, 0x02)
    return result


def _rs_remainder(data, divisor):
    result = [0] * len(divisor)
    for b in data:
        factor = b ^ result.pop(0)
        result.append(0)
        for i, coef in enumerate(divisor):
            result[i] ^= _gf_mul(coef, factor)
    return result


# --- Matrix construction ---

class _Matrix:
    def __init__(self, ver):
        self.ver = ver
        self.size = ver * 4 + 17
        self.mod = [[False] * self.size for _ in range(self.size)]
        self.fn = [[False] * self.size for _ in range(self.size)]

    def set_fn(self, x, y, dark):
        self.mod[y][x] = dark
        self.fn[y][x] = True

    def draw_function_patterns(self):
        s = self.size
        for i in range(s):  # timing patterns
            self.set_fn(6, i, i % 2 == 0)
            self.set_fn(i, 6, i % 2 == 0)
        for cx, cy in ((3, 3), (s - 4, 3), (3, s - 4)):  # finders + separators
            for dy in range(-4, 5):
                for dx in range(-4, 5):
                    x, y = cx + dx, cy + dy
                    if 0 <= x < s and 0 <= y < s:
                        d = max(abs(dx), abs(dy))
                        self.set_fn(x, y, d not in (2, 4))
        pos = self._alignment_positions()
        n = len(pos)
        for i in range(n):
            for j in range(n):
                if (i == 0 and j == 0) or (i == 0 and j == n - 1) or (i == n - 1 and j == 0):
                    continue
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self.set_fn(pos[i] + dx, pos[j] + dy, max(abs(dx), abs(dy)) != 1)
        self.draw_format_bits(0)  # reserve; real bits drawn after masking
        if self.ver >= 7:
            rem = self.ver
            for _ in range(12):
                rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
            bits = self.ver << 12 | rem
            for i in range(18):
                dark = (bits >> i) & 1 != 0
                a, b = s - 11 + i % 3, i // 3
                self.set_fn(a, b, dark)
                self.set_fn(b, a, dark)

    def _alignment_positions(self):
        if self.ver == 1:
            return []
        n = self.ver // 7 + 2
        step = (self.ver * 4 + n * 2 + 1) // (n * 2 - 2) * 2
        result = [self.size - 7 - i * step for i in range(n - 1)] + [6]
        return list(reversed(result))

    def draw_format_bits(self, mask):
        data = _FORMAT_BITS_M << 3 | mask
        rem = data
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = (data << 10 | rem) ^ 0x5412
        bit = lambda i: (bits >> i) & 1 != 0
        s = self.size
        for i in range(6):
            self.set_fn(8, i, bit(i))
        self.set_fn(8, 7, bit(6))
        self.set_fn(8, 8, bit(7))
        self.set_fn(7, 8, bit(8))
        for i in range(9, 15):
            self.set_fn(14 - i, 8, bit(i))
        for i in range(8):
            self.set_fn(s - 1 - i, 8, bit(i))
        for i in range(8, 15):
            self.set_fn(8, s - 15 + i, bit(i))
        self.set_fn(8, s - 8, True)  # always-dark module

    def draw_codewords(self, data):
        s = self.size
        i = 0
        right = s - 1
        while right >= 1:
            if right == 6:
                right = 5
            for vert in range(s):
                for j in range(2):
                    x = right - j
                    upward = ((right + 1) & 2) == 0
                    y = (s - 1 - vert) if upward else vert
                    if not self.fn[y][x] and i < len(data) * 8:
                        self.mod[y][x] = (data[i >> 3] >> (7 - (i & 7))) & 1 != 0
                        i += 1
            right -= 2

    def apply_mask(self, mask):
        f = [
            lambda x, y: (x + y) % 2 == 0,
            lambda x, y: y % 2 == 0,
            lambda x, y: x % 3 == 0,
            lambda x, y: (x + y) % 3 == 0,
            lambda x, y: (x // 3 + y // 2) % 2 == 0,
            lambda x, y: x * y % 2 + x * y % 3 == 0,
            lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
            lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
        ][mask]
        for y in range(self.size):
            for x in range(self.size):
                if not self.fn[y][x] and f(x, y):
                    self.mod[y][x] = not self.mod[y][x]

    def penalty(self):
        """Simplified penalty (runs, 2x2 blocks, dark balance) for mask choice."""
        s, m, score = self.size, self.mod, 0
        for lines in (m, list(zip(*m))):
            for row in lines:
                run, prev = 0, None
                for v in row:
                    if v == prev:
                        run += 1
                    else:
                        if run >= 5:
                            score += run - 2
                        run, prev = 1, v
                if run >= 5:
                    score += run - 2
        for y in range(s - 1):
            for x in range(s - 1):
                if m[y][x] == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                    score += 3
        dark = sum(v for row in m for v in row)
        score += abs(dark * 20 - s * s * 10) // (s * s) * 10
        return score


def _encode(text):
    data = text.encode("utf-8")
    for ver in range(1, len(_ECC_PER_BLOCK)):
        cap_bits = _data_codewords(ver) * 8
        count_bits = 8 if ver <= 9 else 16
        if 4 + count_bits + len(data) * 8 <= cap_bits:
            break
    else:
        raise ValueError("text too long for QR version 10")

    bits = []
    def put(val, n):
        bits.extend((val >> i) & 1 for i in reversed(range(n)))
    put(0b0100, 4)
    put(len(data), count_bits)
    for b in data:
        put(b, 8)
    put(0, min(4, cap_bits - len(bits)))
    put(0, (8 - len(bits) % 8) % 8)
    pad = 0xEC
    while len(bits) < cap_bits:
        put(pad, 8)
        pad ^= 0xEC ^ 0x11
    codewords = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]

    # Split into blocks, add error correction, interleave
    nblocks, ecclen = _NUM_BLOCKS[ver], _ECC_PER_BLOCK[ver]
    raw = _raw_data_modules(ver) // 8
    nshort = nblocks - raw % nblocks
    shortlen = raw // nblocks
    div = _rs_divisor(ecclen)
    blocks, k = [], 0
    for i in range(nblocks):
        n = shortlen - ecclen + (0 if i < nshort else 1)
        dat = codewords[k:k + n]
        k += n
        ecc = _rs_remainder(dat, div)
        if i < nshort:
            dat = dat + [0]
        blocks.append(dat + ecc)
    final = []
    for i in range(len(blocks[0])):
        for j, blk in enumerate(blocks):
            if i != shortlen - ecclen or j >= nshort:
                final.append(blk[i])

    best = None
    for mask in range(8):
        m = _Matrix(ver)
        m.draw_function_patterns()
        m.draw_codewords(final)
        m.apply_mask(mask)
        m.draw_format_bits(mask)
        p = m.penalty()
        if best is None or p < best[0]:
            best = (p, m)
    return best[1].mod


def svg(text, dark="#000", light="#fff", border=3):
    """Returns an SVG string of a QR code for `text` (scales to its container)."""
    mod = _encode(text)
    n = len(mod) + border * 2
    path = "".join(
        f"M{x + border},{y + border}h1v1h-1z"
        for y, row in enumerate(mod) for x, v in enumerate(row) if v
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n} {n}" '
        f'shape-rendering="crispEdges"><rect width="{n}" height="{n}" fill="{light}"/>'
        f'<path d="{path}" fill="{dark}"/></svg>'
    )
