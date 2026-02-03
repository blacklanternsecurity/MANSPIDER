import asyncio
import pytest
from pathlib import Path
from kreuzberg import extract_file, ExtractionConfig, OcrConfig
from man_spider.lib.parser.parser import is_text_file, extract_text_file

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
    """Extract text from test files and verify Password123 is found."""
    filepath = TESTDATA / filename
    config = None
    if filename.endswith((".png", ".jpg", ".jpeg")):
        config = ExtractionConfig(ocr=OcrConfig(backend="tesseract", language="eng"))
    result = asyncio.run(extract_file(str(filepath), config=config))
    assert "Password123" in result.content, f"Password123 not found in {filename}: {result.content[:200]}"


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
