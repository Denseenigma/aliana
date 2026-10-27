"""Builds static/fonts/AlianaTitle.otf: a Latin-only, horizontally condensed
cut of Noto Serif CJK JP Black (SIL OFL 1.1), renamed per the OFL."""
import sys
from fontTools.ttLib import TTCollection
from fontTools import subset
from fontTools.pens.t2CharStringPen import T2CharStringPen
from fontTools.pens.transformPen import TransformPen

SRC, OUT, SCALE_X = sys.argv[1], sys.argv[2], float(sys.argv[3])

font = TTCollection(SRC).fonts[0]  # Noto Serif CJK JP Black

# Keep only what the UI needs: printable ASCII + a few symbols
chars = "".join(chr(c) for c in range(0x20, 0x7F)) + "…—–·↻■ ’‘“”"
opts = subset.Options()
opts.layout_features = ["kern", "liga"]
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
    new = pen.getCharString(private=cs[name].private, globalSubrs=cs[name].globalSubrs)
    cs[name] = new
    hmtx[name] = (round(adv * SCALE_X), round(lsb * SCALE_X))
if "kern" in font or "GPOS" in font:
    pass  # kerning values stay in font units; slight looseness is fine at UI sizes

# Rename (OFL: modified versions must not use the original/reserved names)
FAMILY = "Aliana Title"
name = font["name"]
for rec in list(name.names):
    if rec.nameID in (1, 3, 4, 6, 16, 17, 18, 21, 22):
        name.removeNames(nameID=rec.nameID)
name.setName(FAMILY, 1, 3, 1, 0x409)
name.setName("Regular", 2, 3, 1, 0x409)
name.setName(f"{FAMILY} Regular; derived from Noto Serif CJK JP Black", 3, 3, 1, 0x409)
name.setName(FAMILY, 4, 3, 1, 0x409)
name.setName("AlianaTitle-Regular", 6, 3, 1, 0x409)
name.setName("Condensed Latin subset of Noto Serif CJK JP Black, modified for the Aliana project. "
             "Licensed under the SIL Open Font License 1.1.", 10, 3, 1, 0x409)
top.FullName = FAMILY
top.FamilyName = FAMILY
top.rawDict["FullName"] = FAMILY
cff.fontNames = ["AlianaTitle-Regular"]
font["OS/2"].xAvgCharWidth = round(font["OS/2"].xAvgCharWidth * SCALE_X)
font["OS/2"].usWidthClass = 3  # condensed
font.save(OUT)
print("wrote", OUT)
