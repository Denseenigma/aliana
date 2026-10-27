"""
Builds Aliana's condensed UI fonts from open-licensed (SIL OFL 1.1) sources:
Latin-only subset, squeezed horizontally, renamed as the OFL requires for
modified versions.

  python3 tools/build_font.py <source .otf/.ttc> <out .otf> <scale_x> "<Family Name>"

What's in static/fonts was built with:
  Aliana Title -- /usr/share/fonts/opentype/noto/NotoSerifCJK-Black.ttc  0.72
  Aliana Sans  -- /usr/share/fonts/opentype/inter/Inter-Bold.otf          0.78
(Debian packages fonts-noto-cjk and fonts-inter)
"""
import sys
from fontTools.ttLib import TTFont, TTCollection
from fontTools import subset
from fontTools.pens.t2CharStringPen import T2CharStringPen
from fontTools.pens.transformPen import TransformPen

SRC, OUT, SCALE_X, FAMILY = sys.argv[1], sys.argv[2], float(sys.argv[3]), sys.argv[4]
PSNAME = FAMILY.replace(" ", "") + "-Regular"

font = TTCollection(SRC).fonts[0] if SRC.endswith(".ttc") else TTFont(SRC)
source_name = font["name"].getDebugName(4)

# Keep only what the UI needs: printable ASCII + a few symbols
chars = "".join(chr(c) for c in range(0x20, 0x7F)) + \
    "…—–·↻■ ’‘“”°→"
opts = subset.Options()
opts.layout_features = ["kern", "liga", "tnum"]
opts.hinting = False
opts.desubroutinize = True
opts.name_IDs = ["*"]
opts.notdef_outline = True
sub = subset.Subsetter(opts)
sub.populate(text=chars)
sub.subset(font)

# Squeeze every glyph horizontally (outlines + advance widths)
cff = font["CFF "].cff
top = cff[cff.fontNames[0]]
cs = top.CharStrings
gs = font.getGlyphSet()
hmtx = font["hmtx"].metrics
for name in list(cs.keys()):
    adv, lsb = hmtx[name]
    pen = T2CharStringPen(round(adv * SCALE_X), gs)
    gs[name].draw(TransformPen(pen, (SCALE_X, 0, 0, 1, 0, 0)))
    cs[name] = pen.getCharString(private=cs[name].private, globalSubrs=cs[name].globalSubrs)
    hmtx[name] = (round(adv * SCALE_X), round(lsb * SCALE_X))

# Rename (OFL: modified versions must not use the original/reserved names)
name = font["name"]
for rec in list(name.names):
    if rec.nameID in (1, 2, 3, 4, 6, 16, 17, 18, 21, 22, 25):
        name.removeNames(nameID=rec.nameID)
name.setName(FAMILY, 1, 3, 1, 0x409)
name.setName("Regular", 2, 3, 1, 0x409)
name.setName(f"{FAMILY} Regular; derived from {source_name}", 3, 3, 1, 0x409)
name.setName(FAMILY, 4, 3, 1, 0x409)
name.setName(PSNAME, 6, 3, 1, 0x409)
name.setName(f"Condensed Latin subset of {source_name}, modified for the Aliana project. "
             "Licensed under the SIL Open Font License 1.1.", 10, 3, 1, 0x409)
top.FullName = FAMILY
top.FamilyName = FAMILY
cff.fontNames = [PSNAME]
if "STAT" in font:
    del font["STAT"]
font["OS/2"].xAvgCharWidth = round(font["OS/2"].xAvgCharWidth * SCALE_X)
font["OS/2"].usWidthClass = 3  # condensed
font.save(OUT)
print("wrote", OUT, "from", source_name)
