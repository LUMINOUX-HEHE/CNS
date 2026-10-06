#!/usr/bin/env python3
"""
gen_architecture.py — render the Trust Orchestrator architecture as a PNG.

Pure standard library + Pillow (no matplotlib / graphviz). Draws a layered
diagram: clients -> gateway -> trust engine (research/l0..l5) -> storage &
crypto, with the transparency log and recovery path called out.

    python3 tools/gen_architecture.py
    # writes docs/architecture.png

Colours follow the project's monochrome ops-console theme; a single red
accent marks the detection/recovery path.
"""

import os
from PIL import Image, ImageDraw, ImageFont

# ---------------------------------------------------------------- palette
BG = "#0a0a0a"
PANEL = "#111111"
PANEL2 = "#161616"
LINE = "#2a2a2a"
EDGE = "#4a4a4a"
TEXT = "#f5f5f5"
DIM = "#9ca3af"
FAINT = "#6b7280"
ACCENT = "#ffffff"
RED = "#e5484d"

W, H = 1500, 1060
IMG = Image.new("RGB", (W, H), BG)
D = ImageDraw.Draw(IMG)


def _font(size, bold=False):
    """Best-effort monospace/sans font; falls back to PIL's default."""
    names = (
        ["DejaVuSans-Bold.ttf", "arialbd.ttf", "seguisb.ttf"]
        if bold
        else ["DejaVuSans.ttf", "arial.ttf", "segoeui.ttf"]
    )
    for n in names:
        try:
            return ImageFont.truetype(n, size)
        except OSError:
            continue
    return ImageFont.load_default()


F_TITLE = _font(30, bold=True)
F_SUB = _font(14)
F_LAYER = _font(13, bold=True)
F_BOX = _font(14, bold=True)
F_SMALL = _font(12)
F_TINY = _font(11)


def rrect(x0, y0, x1, y1, r, fill, outline, width=1):
    D.rounded_rectangle([x0, y0, x1, y1], radius=r, fill=fill, outline=outline, width=width)


def center_text(cx, cy, text, font, fill):
    b = D.textbbox((0, 0), text, font=font)
    D.text((cx - (b[2] - b[0]) / 2, cy - (b[3] - b[1]) / 2 - b[1]), text, font=font, fill=fill)


def box(x, y, w, h, title, sub=None, fill=PANEL, outline=LINE, tcol=TEXT):
    rrect(x, y, x + w, y + h, 8, fill, outline)
    if sub:
        center_text(x + w / 2, y + h / 2 - 9, title, F_BOX, tcol)
        center_text(x + w / 2, y + h / 2 + 10, sub, F_SMALL, DIM)
    else:
        center_text(x + w / 2, y + h / 2, title, F_BOX, tcol)


def arrow(x0, y0, x1, y1, color=EDGE, width=2, head=7):
    D.line([x0, y0, x1, y1], fill=color, width=width)
    # downward / upward / horizontal arrowhead
    if y1 > y0 and x0 == x1:
        D.polygon([(x1, y1), (x1 - head, y1 - head), (x1 + head, y1 - head)], fill=color)
    elif y1 < y0 and x0 == x1:
        D.polygon([(x1, y1), (x1 - head, y1 + head), (x1 + head, y1 + head)], fill=color)
    elif x1 > x0 and y0 == y1:
        D.polygon([(x1, y1), (x1 - head, y1 - head), (x1 - head, y1 + head)], fill=color)
    else:
        D.polygon([(x1, y1), (x1 - head, y1 - head), (x1 - head, y1 + head)], fill=color)


def band(x, y, w, h, label):
    rrect(x, y, x + w, y + h, 12, PANEL2, LINE)
    D.text((x + 14, y + 10), label, font=F_LAYER, fill=FAINT)


# ---------------------------------------------------------------- header
D.text((40, 34), "Trust Orchestrator", font=F_TITLE, fill=TEXT)
D.text(
    (40, 74),
    "Go stdlib-only trust engine  ·  REST gateway + React console  ·  RFC 9162 transparency  ·  FROST recovery",
    font=F_SUB,
    fill=DIM,
)

# ================================================================ clients
band(40, 112, 1420, 118, "CLIENTS")
box(70, 152, 250, 56, "React console", "Vite + TS, embedded in binary")
box(350, 152, 250, 56, "curl / REST", "Bearer token, RBAC")
box(630, 152, 250, 56, "Python / Java SDK", "thin REST clients")
box(910, 152, 250, 56, "to-tool / to-council", "CLI: keygen, bench, recover")
box(1190, 152, 240, 56, "to-watchdog", "per-cycle scores")
for cx in (320, 600, 880, 1160):
    arrow(cx, 210, cx, 246)

# ================================================================ gateway
band(40, 244, 1420, 150, "GATEWAY  (cmd/gateway)")
box(70, 284, 300, 88, "REST API + RBAC", "route/auth/org-scope · idempotency LRU")
box(390, 284, 300, 88, "Multi-tenancy", "file-per-tenant, sealed (AES-GCM)")
box(710, 284, 300, 88, "Webhooks", "durable outbox (fsync, retries)")
box(1030, 284, 400, 88, "Config (TO_PROFILE)", "fail-closed prod secrets + timeouts")

for cx in (220, 540, 860, 1230):
    arrow(cx, 394, cx, 430)

# ================================================================ engine
band(40, 428, 1420, 300, "TRUST ENGINE  (research/)")
# l0 row
box(70, 468, 250, 66, "l0  core", "timeline · CT log · crypto")
box(340, 468, 250, 66, "l1  identity", "CA, rotation, revocation")
box(610, 468, 250, 66, "l2  transport", "mTLS, wire protocol")
box(880, 468, 250, 66, "l3  detection", "watchdogs, CUSUM, fusion")
box(1150, 468, 280, 66, "l4 / l5  fleet", "orchestration, policy")

# engine detail row
box(70, 566, 320, 130, "", None)
D.text((84, 578), "Timeline (append-only hash chain)", font=F_SMALL, fill=TEXT)
for i, t in enumerate([
    "Ed25519-signed events, ParentHash links",
    "fold -> trust state (never delete)",
    "recovery forks + key rotation epochs",
]):
    D.text((84, 604 + i * 22), "· " + t, font=F_TINY, fill=DIM)

box(410, 566, 320, 130, "", None)
D.text((424, 578), "CT log (RFC 9162)", font=F_SMALL, fill=TEXT)
for i, t in enumerate([
    "incremental Merkle frontier, O(log n)",
    "signed tree heads + inclusion proofs",
    "consistency proofs; persisted ctlog.json",
]):
    D.text((424, 604 + i * 22), "· " + t, font=F_TINY, fill=DIM)

box(750, 566, 330, 130, "", None)
D.text((764, 578), "Detection (FR2.3)", font=F_SMALL, fill=TEXT)
for i, t in enumerate([
    "5 watchdogs, CUSUM p-value exp(-2dS/σ²)",
    "quorum 3/5 below threshold = DETECTED",
    "one Byzantine node can't trigger/block",
]):
    D.text((764, 604 + i * 22), "· " + t, font=F_TINY, fill=DIM)

box(1100, 566, 330, 130, "", None)
D.text((1114, 578), "Crypto primitives", font=F_SMALL, fill=TEXT)
for i, t in enumerate([
    "Ed25519 signatures / key rotation",
    "FROST threshold + DKG (council)",
    "vault: envelope KEK/DEK (3-of-5)",
]):
    D.text((1114, 604 + i * 22), "· " + t, font=F_TINY, fill=DIM)

# ================================================================ storage
band(40, 746, 1420, 120, "STORAGE & DEPLOY")
box(70, 786, 280, 62, "tenant timelines", "timeline.json (sealed)")
box(370, 786, 280, 62, "CT frontier", "ctlog.json snapshot")
box(670, 786, 280, 62, "backups", "bundle + restore")
box(970, 786, 460, 62, "Docker · Helm · Terraform · systemd", "deploy/")

# ================================================================ side paths
# detection -> recovery (red)
rrect(1180, 980, 1460, 1030, 10, "#1a0e0e", RED)
D.text((1196, 992), "DETECTED -> council recover", font=F_SMALL, fill=RED)
D.text((1196, 1010), "FROST handoff verified -> fork", font=F_TINY, fill=RED)
arrow(1300, 870, 1300, 980, color=RED, width=2)

# transparency callout
rrect(40, 900, 700, 1030, 10, PANEL, LINE)
D.text((58, 912), "Transparency guarantee", font=F_SMALL, fill=TEXT)
for i, t in enumerate([
    "Every event is a signed link in an append-only hash chain.",
    "The Merkle log commits to all history; anyone can verify",
    "inclusion/consistency without trusting the gateway.",
    "Log key signs STHs; gossip detects split-brain / rewrites.",
]):
    D.text((58, 936 + i * 20), "· " + t, font=F_TINY, fill=DIM)

# footer
D.text((40, 1034), "github.com/LUMINOUX-HEHE/CNS", font=F_TINY, fill=FAINT)
D.text((1260, 1034), "docs/architecture.png", font=F_TINY, fill=FAINT)

os.makedirs("docs", exist_ok=True)
out = os.path.join("docs", "architecture.png")
IMG.save(out)
print("wrote", out, IMG.size)