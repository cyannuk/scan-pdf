"""Generates the encrypted test fixtures in test/fixtures/ with qpdf (via pikepdf).

qpdf is an independent implementation of PDF encryption, so the fixtures check the decryptor
against real-world output rather than against our own encoder. Salts and IVs are random:
regenerating changes the bytes but not the expected scan results.

    python3 -m venv .venv && .venv/bin/pip install pikepdf && .venv/bin/python scripts/make-fixtures.py
"""

from pathlib import Path

import pikepdf
from pikepdf import Array, Dictionary, Encryption, Name, ObjectStreamMode, String

OUT = Path(__file__).resolve().parent.parent / "test" / "fixtures"


def link(pdf: pikepdf.Pdf, uri: str) -> pikepdf.Object:
    action = Dictionary(S=Name.URI, URI=String(uri))
    return pdf.make_indirect(Dictionary(Type=Name.Annot, Subtype=Name.Link, Rect=[0, 0, 10, 10], A=action))


def build(payload: bool) -> pikepdf.Pdf:
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(200, 200))
    page = pdf.pages[0]
    page.Contents = pdf.make_stream(b"BT 20 100 Td (Hello) Tj ET")
    annots = [link(pdf, "https://example.com/")]
    if payload:
        # JS in a string (encrypted as a string) and in a stream (encrypted as a stream)
        js = String("var s = unescape('%u0c0c%u0c0c'); eval(s);")
        pdf.Root.OpenAction = pdf.make_indirect(Dictionary(S=Name.JavaScript, JS=js))
        named = pdf.make_indirect(Dictionary(S=Name.JavaScript, JS=pdf.make_stream(b"util.printf('%45000f', 0);")))
        pdf.Root.Names = Dictionary(JavaScript=Dictionary(Names=Array([String("a"), named])))
        annots += [link(pdf, "javascript:app.alert(1)"), link(pdf, "file://evil/share/x")]
    page.Annots = Array(annots)
    return pdf


FIXTURES = [
    # name, payload, object streams, encryption
    ("r6-objstm", True, True, Encryption(owner="owner", user="", R=6)),
    ("r6-objstm-clean", False, True, Encryption(owner="owner", user="", R=6)),
    ("r6", True, False, Encryption(owner="owner", user="", R=6)),
    ("r6-password", True, True, Encryption(owner="owner", user="user", R=6)),
    ("r5", True, False, Encryption(owner="owner", user="", R=5)),
    ("r4-aes-objstm", True, True, Encryption(owner="owner", user="", R=4, aes=True)),
    ("r4-rc4-nometa", True, False, Encryption(owner="owner", user="", R=4, aes=False, metadata=False)),
    ("r3", True, False, Encryption(owner="owner", user="", R=3, aes=False, metadata=False)),
    ("r2", True, False, Encryption(owner="owner", user="", R=2, aes=False, metadata=False)),
]

OUT.mkdir(parents=True, exist_ok=True)
for name, payload, objstm, enc in FIXTURES:
    mode = ObjectStreamMode.generate if objstm else ObjectStreamMode.disable
    build(payload).save(OUT / f"{name}.pdf", encryption=enc, object_stream_mode=mode)
    print(name)
