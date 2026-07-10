import pdfplumber
import sys

def dump_text(pdf_path, out_path):
    with pdfplumber.open(pdf_path) as pdf:
        with open(out_path, 'w', encoding='utf-8') as out_f:
            for i, page in enumerate(pdf.pages):
                out_f.write(f"\n--- PAGE {i+1} ---\n")
                text = page.extract_text()
                if text:
                    out_f.write(text)

if __name__ == "__main__":
    pdfs = ['CTR_ZIG_DISCOVERY_PHASE.PDF', 'CTR_ZIG_PHASE_ONE.PDF', 'CTR_ZIG_PHASE_TWO.PDF']
    for p in pdfs:
        dump_text(p, p + ".txt")
    print("Dumped text successfully.")
