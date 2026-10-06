import argparse

PAGE = 0x1000
LOAD_MNEM = {"ldrb", "ldurb"}
STORE_MNEM = {"strb", "sturb"}
XOR_MNEM = {"eor", "mvn"}


def align_down(x, page=PAGE):
    return x & ~(page - 1)


def align_up(x, page=PAGE):
    return (x + page - 1) & ~(page - 1)


# ── ELF 로딩 ──────────────────────────────────────────────────────────────
def load_elf(path):
    from elftools.elf.elffile import ELFFile
    f = open(path, "rb")
    elf = ELFFile(f)
    return elf


def get_segments(elf):
    return [(s["p_vaddr"], s["p_filesz"], s["p_memsz"], s["p_offset"])
            for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]


def get_text_section(elf):
    sec = elf.get_section_by_name(".text")
    if sec is None:
        raise ValueError(".text 섹션을 찾을 수 없습니다")
    return sec["sh_addr"], sec.data()


def get_symtab_functions(elf):
    funcs = []
    for secname in (".symtab", ".dynsym"):
        sec = elf.get_section_by_name(secname)
        if sec is None:
            continue
        for sym in sec.iter_symbols():
            if sym["st_info"]["type"] == "STT_FUNC" and sym["st_value"] != 0 and sym["st_size"] > 0:
                funcs.append((sym["st_value"], sym["st_size"], sym.name or "?"))
    seen, out = set(), []
    for addr, size, name in sorted(funcs):
        if addr in seen:
            continue
        seen.add(addr)
        out.append((addr, size, name))
    return out


# ── 1단계: 함수 목록 + 후보 스코어링 ──────────────────────────────────────
def find_prologue_functions(text_addr, text_bytes):
    import capstone as cs
    md = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)
    starts = []
    for insn in md.disasm(text_bytes, text_addr):
        if insn.mnemonic == "stp" and "x29, x30, [sp" in insn.op_str and "!" in insn.op_str:
            starts.append(insn.address)
    starts.append(text_addr + len(text_bytes))
    funcs = []
    for i in range(len(starts) - 1):
        addr = starts[i]
        funcs.append((addr, starts[i + 1] - addr, f"FUN_{addr:x}"))
    return funcs


def list_all_functions(elf):
    sym_funcs = get_symtab_functions(elf)
    sym_by_addr = {addr: (size, name) for addr, size, name in sym_funcs}
    text_addr, text_bytes = get_text_section(elf)
    heuristic_funcs = find_prologue_functions(text_addr, text_bytes)

    funcs = []
    for addr, size, name in heuristic_funcs:
        if addr in sym_by_addr:
            sym_size, sym_name = sym_by_addr[addr]
            funcs.append((addr, sym_size or size, sym_name))
        else:
            funcs.append((addr, size, name))
    heur_addrs = {a for a, _, _ in heuristic_funcs}
    for addr, size, name in sym_funcs:
        if addr not in heur_addrs:
            funcs.append((addr, size, name))
    funcs.sort()
    return funcs


def score_function(code_bytes, vaddr, max_len=0x4000):
    import capstone as cs
    md = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)
    total = loads = stores = xors = 0
    for insn in md.disasm(code_bytes[:max_len], vaddr):
        total += 1
        if insn.mnemonic in LOAD_MNEM:
            loads += 1
        elif insn.mnemonic in STORE_MNEM:
            stores += 1
        elif insn.mnemonic in XOR_MNEM:
            xors += 1
        if insn.mnemonic == "ret":
            break
    hits = loads + stores + xors
    return {"total": total, "hits": hits, "ratio": hits / total if total else 0}


def find_candidates(elf, data, min_hits, min_ratio, top):
    segs = get_segments(elf)

    def vaddr_to_bytes(vaddr, size):
        for base, filesz, memsz, off in segs:
            if base <= vaddr < base + filesz:
                start = off + (vaddr - base)
                return data[start:start + size]
        return b""

    funcs = list_all_functions(elf)
    print(f"[정보] 함수 {len(funcs)}개 탐지. 패턴 스캔 중...")

    results = []
    for addr, size, name in funcs:
        code = vaddr_to_bytes(addr, min(size, 0x4000) or 0x200)
        if not code:
            continue
        s = score_function(code, addr)
        if s["hits"] >= min_hits and s["ratio"] >= min_ratio:
            results.append((addr, name, s))

    results.sort(key=lambda r: r[2]["hits"], reverse=True)
    return results[:top]


# ── 2단계: 후보 함수 실제 실행(에뮬레이션) ───────────────────────────────
def run_emulation(data, segs, func_vaddr, timeout_us, max_insn):
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UcError
    from unicorn.arm64_const import (
        UC_ARM64_REG_SP, UC_ARM64_REG_LR,
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
        UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
    )

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    bounds = []
    for vaddr, filesz, memsz, off in segs:
        start = align_down(vaddr)
        end = align_up(vaddr + memsz)
        size = end - start
        uc.mem_map(start, size)
        chunk = bytearray(size)
        file_bytes = data[off: off + filesz]
        rel = vaddr - start
        chunk[rel:rel + len(file_bytes)] = file_bytes
        uc.mem_write(start, bytes(chunk))
        bounds.append((start, size))

    snapshot = {start: bytes(uc.mem_read(start, size)) for start, size in bounds}

    STACK_ADDR, STACK_SIZE = 0x7f0000000000, 0x100000
    RETURN_ADDR = 0x7f1000000000
    uc.mem_map(STACK_ADDR, STACK_SIZE)
    uc.mem_map(align_down(RETURN_ADDR), PAGE)
    uc.reg_write(UC_ARM64_REG_SP, STACK_ADDR + STACK_SIZE - 0x1000)
    uc.reg_write(UC_ARM64_REG_LR, RETURN_ADDR)
    for reg in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7):
        uc.reg_write(reg, 0)

    status = "정상 종료"
    try:
        uc.emu_start(func_vaddr, RETURN_ADDR, timeout=timeout_us, count=max_insn)
    except UcError as e:
        status = f"중단됨: {e}"

    changed = {}
    for start, size in bounds:
        cur = uc.mem_read(start, size)
        orig = snapshot[start]
        for i in range(size):
            if cur[i] != orig[i]:
                changed[start + i] = cur[i]
    return status, changed


def group_runs(changed):
    addrs = sorted(changed)
    if not addrs:
        return []
    runs, start, prev = [], addrs[0], addrs[0]
    for a in addrs[1:]:
        if a == prev + 1:
            prev = a
        else:
            runs.append((start, prev))
            start = prev = a
    runs.append((start, prev))
    return runs


def to_ascii(bs):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in bs)


# ── 메인 ──────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--image-base", type=lambda x: int(x, 0), default=0x100000)
    ap.add_argument("--min-hits", type=int, default=10)
    ap.add_argument("--min-ratio", type=float, default=0.25)
    ap.add_argument("--top", type=int, default=30)
    ap.add_argument("--timeout-ms", type=int, default=2000)
    ap.add_argument("--max-insn", type=int, default=2_000_000)
    ap.add_argument("--out", default="decoded_strings.txt")
    args = ap.parse_args()

    elf = load_elf(args.binary)
    data = open(args.binary, "rb").read()
    segs = get_segments(elf)

    candidates = find_candidates(elf, data, args.min_hits, args.min_ratio, args.top)
    print(f"[정보] 디코딩 후보 함수 {len(candidates)}개. 각 함수를 실행해서 결과를 추출합니다...\n")

    out_lines = []
    for addr, name, score in candidates:
        gaddr = addr + args.image_base
        status, changed = run_emulation(data, segs, addr, args.timeout_ms * 1000, args.max_insn)
        runs = group_runs(changed)
        if not runs:
            continue
        header = f"\n=== 함수 {name} (0x{gaddr:08x}) [{status}] ==="
        print(header)
        out_lines.append(header)
        for s, e in runs:
            bs = bytes(changed[a] for a in range(s, e + 1))
            ascii_str = to_ascii(bs)
            line = f"  [0x{s + args.image_base:08x}] {ascii_str}"
            print(line)
            out_lines.append(line)

    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines) + "\n")
    print(f"\n[저장] 결과를 {args.out} 에 저장했습니다.")


if __name__ == "__main__":
    main()
