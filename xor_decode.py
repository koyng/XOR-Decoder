import argparse
import sys

PAGE = 0x1000


def align_down(x, page=PAGE):
    return x & ~(page - 1)


def align_up(x, page=PAGE):
    return (x + page - 1) & ~(page - 1)


def load_elf(path):
    from elftools.elf.elffile import ELFFile
    data = open(path, "rb").read()
    with open(path, "rb") as f:
        elf = ELFFile(f)
        segs = []
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                segs.append({
                    "vaddr": seg["p_vaddr"],
                    "memsz": seg["p_memsz"],
                    "filesz": seg["p_filesz"],
                    "offset": seg["p_offset"],
                })
    return data, segs


def run(so_path, func_vaddr, timeout_us, max_insn, arg_regs):
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UcError
    from unicorn.arm64_const import (
        UC_ARM64_REG_SP, UC_ARM64_REG_LR,
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
        UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
    )

    data, segs = load_elf(so_path)
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    bounds = []
    for seg in segs:
        start = align_down(seg["vaddr"])
        end = align_up(seg["vaddr"] + seg["memsz"])
        size = end - start
        uc.mem_map(start, size)
        chunk = bytearray(size)
        file_bytes = data[seg["offset"]: seg["offset"] + seg["filesz"]]
        rel = seg["vaddr"] - start
        chunk[rel:rel + len(file_bytes)] = file_bytes
        uc.mem_write(start, bytes(chunk))
        bounds.append((start, size))

    snapshot = {start: bytes(uc.mem_read(start, size)) for start, size in bounds}

    STACK_ADDR = 0x7f0000000000
    STACK_SIZE = 0x100000
    RETURN_ADDR = 0x7f1000000000  # 여기로 복귀하면 함수가 끝난 것으로 간주

    uc.mem_map(STACK_ADDR, STACK_SIZE)
    sp = STACK_ADDR + STACK_SIZE - 0x1000
    uc.mem_map(align_down(RETURN_ADDR), PAGE)

    uc.reg_write(UC_ARM64_REG_SP, sp)
    uc.reg_write(UC_ARM64_REG_LR, RETURN_ADDR)
    regs = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
            UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7]
    for i, reg in enumerate(regs):
        uc.reg_write(reg, arg_regs[i] if i < len(arg_regs) else 0)

    status = "정상 종료 (ret)"
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


def print_runs(changed, image_base):
    addrs = sorted(changed)
    if not addrs:
        print("바뀐 바이트가 없습니다 (함수가 다른 로직이거나, 실행이 초반에 중단됐을 수 있습니다).")
        return
    start = prev = addrs[0]
    runs = []
    for a in addrs[1:]:
        if a == prev + 1:
            prev = a
        else:
            runs.append((start, prev))
            start = prev = a
    runs.append((start, prev))

    for s, e in runs:
        bs = bytes(changed[a] for a in range(s, e + 1))
        gs, ge = s + image_base, e + image_base
        print(f"\n[{gs:08x}-{ge:08x}] {len(bs)} bytes")
        print("hex  :", bs.hex(" "))
        print("ascii:", "".join(chr(b) if 32 <= b < 127 else "." for b in bs))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("func_addr", help="Ghidra 상 함수 시작 주소, 예: 0x0011b658")
    ap.add_argument("--image-base", type=lambda x: int(x, 0), default=0x100000)
    ap.add_argument("--timeout-ms", type=int, default=2000)
    ap.add_argument("--max-insn", type=int, default=2_000_000)
    ap.add_argument("--arg", action="append", default=[],
                     help="x0,x1,... 에 넣을 값 (16진수). 여러 번 지정 가능, 순서대로 x0,x1,...")
    args = ap.parse_args()

    ghidra_addr = int(args.func_addr, 16)
    func_vaddr = ghidra_addr - args.image_base
    arg_regs = [int(a, 16) for a in args.arg]

    status, changed = run(args.binary, func_vaddr, args.timeout_ms * 1000, args.max_insn, arg_regs)
    print(f"[실행 결과] {status}")
    print(f"[변경된 바이트 수] {len(changed)}")
    print_runs(changed, args.image_base)


if __name__ == "__main__":
    main()
