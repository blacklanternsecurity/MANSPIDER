import pytest
from pathlib import Path
from man_spider.lib.parser.parser import extract_document, is_text_file, extract_text_file

TESTDATA = Path(__file__).parent.parent / "testdata"


@pytest.mark.parametrize(
    "filename",
    [
        "test.docx",
        "test.pdf",
        "test.xlsx",
        "test.png",
        "test.doc",
        "test.xls",
    ],
)
def test_extract_password(filename):
    """Extract text from document/binary formats via xberg and verify Password123 is found."""
    content = extract_document(str(TESTDATA / filename))
    assert content is not None, f"No content extracted from {filename}"
    assert "Password123" in content, f"Password123 not found in {filename}: {content[:200]}"


def test_ocr_dark_background():
    """
    Regression test: light text on a dark background must still OCR correctly.
    A previous extraction backend returned empty content for these images (its
    binarization wiped light-on-dark glyphs), which is why we moved to xberg.
    See issue #119.
    """
    content = extract_document(str(TESTDATA / "test-darkbg.png"))
    assert content is not None, "No content extracted from dark-background image"
    assert "Password123" in content, f"Password123 not found in dark-background image: {content[:200]}"


@pytest.mark.parametrize(
    "filename",
    [
        "test-ascii.txt",
        "test-utf8.txt",
        "test-utf8-bom.txt",
        "test-utf16le.txt",
        "test-utf16be.txt",
        "test-utf16-bom.txt",
        "test-latin1.txt",
        "test-cp1252.txt",
    ],
)
def test_extract_text_encodings(filename):
    """Extract text from various encodings using charset-normalizer."""
    filepath = TESTDATA / filename
    assert is_text_file(str(filepath)), f"{filename} should be detected as text file"
    content = extract_text_file(str(filepath))
    assert content is not None, f"Failed to extract text from {filename}"
    assert "Password123" in content, f"Password123 not found in {filename}: {content[:200]}"
