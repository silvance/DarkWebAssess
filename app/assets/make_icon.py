"""Generate the application icon (shield + watchful eye) as a multi-size .ico.

Theme: dark-web threat intelligence — a shield (security/monitoring) with an
eye (watching for threats), in the tool's navy + cyan palette. Run:
    python app/assets/make_icon.py
Produces app/assets/icon.ico (+ icon.png preview).
"""
from pathlib import Path
from PIL import Image, ImageDraw

NAVY = (13, 27, 42)        # background
NAVY2 = (22, 50, 74)       # shield fill
CYAN = (0, 212, 255)       # accent
CYAN_DK = (0, 150, 190)

S = 256
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

# Rounded-square background.
d.rounded_rectangle([6, 6, S - 6, S - 6], radius=44, fill=NAVY, outline=CYAN_DK, width=4)

# Shield silhouette (flat top, straight sides, pointed bottom).
shield = [(60, 60), (196, 60), (196, 126), (128, 212), (60, 126)]
d.polygon(shield, fill=NAVY2, outline=CYAN)
# Thicken the shield outline by re-stroking the edges.
for i in range(len(shield)):
    a = shield[i]
    b = shield[(i + 1) % len(shield)]
    d.line([a, b], fill=CYAN, width=9, joint="curve")

# Eye — a lens (almond) with a bold pupil, centered in the shield.
cx, cy = 128, 118
# Almond/lens via two arcs → approximate with an ellipse outline.
d.ellipse([cx - 46, cy - 26, cx + 46, cy + 26], fill=NAVY, outline=CYAN, width=8)
# Iris + pupil.
d.ellipse([cx - 22, cy - 22, cx + 22, cy + 22], fill=CYAN)
d.ellipse([cx - 10, cy - 10, cx + 10, cy + 10], fill=NAVY)
# Catch-light highlight.
d.ellipse([cx + 2, cy - 14, cx + 10, cy - 6], fill=(230, 250, 255))

# Small "scan" ticks under the eye to suggest signal/monitoring.
for i, x in enumerate((104, 118, 132, 146)):
    h = (10, 18, 14, 8)[i]
    d.line([(x, 168), (x, 168 + h)], fill=CYAN_DK, width=5)

out_dir = Path(__file__).resolve().parent
img.save(out_dir / "icon.png")
img.save(
    out_dir / "icon.ico",
    sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
)
print("wrote", out_dir / "icon.ico", "and icon.png")
