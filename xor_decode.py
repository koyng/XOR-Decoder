#!/usr/bin/env python3
import argparse
import re
import sys

LINE_RE = re.compile(r"^\s*([\w.]+)\s*=\s*(.+?)\s*;\s*$")
DAT_RE = re.compile(r"^DAT_([0-9a-fA-F]+)$")
# Ghidra가 4/8바이트 변수의 일부 바이트만 쓸 때 쓰는 표기: DAT_xxxxxx._N_1_ (N번째 바이트, 1바이트)
SUBFIELD_RE = re.compile(r"^DAT_([0-9a-fA-F]+)\._(\d+)_(\d+)_$")


def resolve_addr(tok):
    """DAT_xxxxxx 또는 DAT_xxxxxx._N_1_ 형태를 실제 주소(int)로 변환. 해당 없으면 None."""
    m = SUBFIELD_RE.match(tok)
    if m:
        base = int(m.group(1), 16)
        off = int(m.group(2))
        return base + off
    m = DAT_RE.match(tok)
    if m:
        return int(m.group(1), 16)
    return None


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
        addr = resolve_addr(tok)
        if addr is not None:
            return written[addr] if addr in written else mem.read(addr)
        if tok in local:
            return local[tok]
        return parse_int(tok)

    def store(name, val):
        val &= 0xFF
        addr = resolve_addr(name)
        if addr is not None:
            written[addr] = val
        else:
            local[name] = val

    skipped = 0
    for lineno, line in enumerate(open(args.decomp, encoding="utf-8", errors="ignore"), 1):
        m = LINE_RE.match(line)
        if not m:
            continue
        dst, rhs = m.groups()
        try:
            if rhs.startswith("~"):
                val = ~get(rhs[1:])
            elif "^" in rhs:
                a, b = rhs.split("^", 1)
                val = get(a) ^ get(b)
            else:
                val = get(rhs)
            store(dst, val)
        except (ValueError, KeyError) as e:
            # XOR 디코딩 체인과 무관한 변수(lVar1 등)가 섞여 있으면 그 줄만 건너뛴다
            skipped += 1
            print(f"[스킵] {lineno}행: {line.strip()}  ({e})", file=sys.stderr)

    if skipped:
        print(f"[경고] 총 {skipped}줄을 해석하지 못해 건너뛰었습니다.", file=sys.stderr)

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
