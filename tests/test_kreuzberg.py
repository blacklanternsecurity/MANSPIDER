import asyncio
import pytest
from pathlib import Path
from kreuzberg import extract_file, ExtractionConfig, OcrConfig

TESTDATA = Path(__file__).parent.parent / "testdata"


@pytest.mark.parametrize("filename", [
    "test.docx",
    "test.pdf",
    "test.xlsx",
    "test.png",
    "test.doc",
    "test.xls",
])
def test_extract_password(filename):
    """Extract text from test files and verify Password123 is found."""
    filepath = TESTDATA / filename
    config = None
    if filename.endswith((".png", ".jpg", ".jpeg")):
        config = ExtractionConfig(ocr=OcrConfig(backend="tesseract", language="eng"))
    result = asyncio.run(extract_file(str(filepath), config=config))
    assert "Password123" in result.content, f"Password123 not found in {filename}: {result.content[:200]}"
