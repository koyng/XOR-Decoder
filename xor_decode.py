#!/usr/bin/env python3
"""Ghidra 디컴파일 XOR 디코딩 루틴을 바이너리에 적용해 결과 바이트를 계산한다.

사용법:
  python xor_decode.py decomp.txt target.bin --image-base 0x100000
  (target.bin 이 ELF이면 pyelftools 로 가상주소->파일오프셋 매핑, 없으면 --raw 로 평면 이미지 취급)

decomp.txt : 붙여넣은 디컴파일 텍스트를 저장한 파일
--image-base : Ghidra 표시주소 - 실제 가상주소 (PIE ELF 기본 0x100000)
"""
import argparse
import re
import sys

LINE_RE = re.compile(r"^\s*(\w+)\s*=\s*(.+?)\s*;\s*$")
DAT_RE = re.compile(r"^DAT_([0-9a-fA-F]+)$")


def parse_int(s):
    s = s.strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s)


class Memory:
    def __init__(self, path, image_base, raw):
        self.image_base = image_base
        self.data = open(path, "rb").read()
        self.segments = []  # (vaddr, filesz, offset)
        self.raw = raw
        if not raw:
            try:
                from elftools.elf.elffile import ELFFile
                with open(path, "rb") as f:
                    elf = ELFFile(f)
                    for seg in elf.iter_segments():
                        if seg["p_type"] == "PT_LOAD":
                            self.segments.append(
                                (seg["p_vaddr"], seg["p_filesz"], seg["p_offset"]))
            except Exception as e:  # pyelftools 없음/ELF 아님
                print(f"[경고] ELF 파싱 실패({e}); 평면 이미지로 처리", file=sys.stderr)
                self.raw = True

    def read(self, ghidra_addr):
        va = ghidra_addr - self.image_base
        if self.raw:
            off = va
        else:
            for base, size, off0 in self.segments:
                if base <= va < base + size:
                    off = off0 + (va - base)
                    break
            else:
                return 0  # .bss 등 파일에 없는 영역은 0
        if 0 <= off < len(self.data):
            return self.data[off]
        return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("decomp")
    ap.add_argument("binary")
    ap.add_argument("--image-base", type=lambda x: int(x, 0), default=0x100000)
    ap.add_argument("--raw", action="store_true", help="바이너리를 평면 이미지로 취급")
    args = ap.parse_args()

    mem = Memory(args.binary, args.image_base, args.raw)
    written = {}   # 주소 -> 값 (실행 중 덮어쓴 바이트)
    local = {}     # local_xx 변수

    def get(tok):
        tok = tok.strip()
        tok = re.sub(r"^\(\w+\)", "", tok).strip()  # (undefined1) 캐스트 제거
        m = DAT_RE.match(tok)
        if m:
            a = int(m.group(1), 16)
            return written[a] if a in written else mem.read(a)
        if tok in local:
            return local[tok]
        return parse_int(tok)

    def store(name, val):
        val &= 0xFF
        m = DAT_RE.match(name)
        if m:
            written[int(m.group(1), 16)] = val
        else:
            local[name] = val

    for line in open(args.decomp, encoding="utf-8", errors="ignore"):
        m = LINE_RE.match(line)
        if not m:
            continue
        dst, rhs = m.groups()
        if rhs.startswith("~"):
            val = ~get(rhs[1:])
        elif "^" in rhs:
            a, b = rhs.split("^", 1)
            val = get(a) ^ get(b)
        else:
            val = get(rhs)
        store(dst, val)

    # 연속 구간으로 묶어서 출력
    addrs = sorted(written)
    runs, start, prev = [], None, None
    for a in addrs:
        if start is None:
            start = prev = a
        elif a == prev + 1:
            prev = a
        else:
            runs.append((start, prev))
            start = prev = a
    if start is not None:
        runs.append((start, prev))

    for s, e in runs:
        bs = bytes(written[a] for a in range(s, e + 1))
        print(f"\n[{s:08x}-{e:08x}] {len(bs)} bytes")
        print("hex :", bs.hex(" "))
        print("ascii:", "".join(chr(b) if 32 <= b < 127 else "." for b in bs))


if __name__ == "__main__":
    main()
