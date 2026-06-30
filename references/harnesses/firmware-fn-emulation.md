# Firmware Function Emulation Harness

Run **one exported function** from a firmware binary on controlled inputs —
without booting the whole image or reaching a live device. Use this to produce
Stage-C observable evidence for a self-contained routine (crypto primitive,
checksum, parser, token/key derivation, bounds check) by proving it maps
`input → output` exactly as your exploit model assumes, or by driving it to a
crash. External library/PLT calls the function makes are stubbed or hooked.

Two methods. Prefer p-code emulation (no extra dependency beyond Ghidra, already
present); use Unicorn for native-speed or when p-code coverage is incomplete.

Both emulate **extracted, non-network code**, so wrap them with
`scripts/sandbox.sh` — and on a host with no isolation backend, degraded mode is
acceptable here (resource/wall limits only):

```bash
SANDBOX_DEGRADED_OK=1 scripts/sandbox.sh <workspace> -- python3 emulate_fn.py <bin> <func>
```

## Method 1 — Ghidra P-code emulation (pyghidra `EmulatorHelper`)

No dependency beyond Ghidra. Resolves the function from the analyzed program,
sets up registers/stack, writes inputs to scratch memory, runs to the return
address, and reads the result register. See `pyghidra.md` for `GHIDRA_INSTALL_DIR`
and launcher usage.

```python
# emulate_fn.py — run via: pyghidra emulate_fn.py <binary> <func_name>
import sys, pyghidra
pyghidra.start()
binary, func_name = sys.argv[1], sys.argv[2]

with pyghidra.open_program(binary) as flat:
    program = flat.getCurrentProgram()
    from ghidra.app.emulator import EmulatorHelper

    func = [f for f in program.getFunctionManager().getFunctions(True)
            if f.getName() == func_name][0]
    emu = EmulatorHelper(program)
    sp_reg = emu.getStackPointerRegister()
    pc_reg = emu.getPCRegister()

    # Stack in a scratch region; input bytes in another.
    STACK = 0x20000000
    INBUF = 0x30000000
    emu.writeRegister(sp_reg, STACK)
    emu.writeRegister(pc_reg, func.getEntryPoint().getOffset())

    data = bytes.fromhex(sys.argv[3]) if len(sys.argv) > 3 else b"A" * 64
    emu.writeMemory(emu.getProgram().getAddressFactory()
                    .getDefaultAddressSpace().getAddress(INBUF), data)

    # First integer-argument register, per ABI (ARM: r0, x86-64: RDI, MIPS: a0).
    arg0 = {"ARM": "r0", "AARCH64": "x0", "x86": "RDI", "MIPS": "a0"}
    proc = program.getLanguage().getProcessor().toString()
    emu.writeRegister(arg0.get(proc, "r0"), INBUF)

    # Stop when the function returns to the sentinel we placed as the return addr.
    RET = 0xDEADBEEF
    emu.writeStackValue(0, 8, RET)            # return slot for ARM/x86 calling convs
    emu.setBreakpoint(emu.getProgram().getAddressFactory()
                      .getDefaultAddressSpace().getAddress(RET))

    monitor = pyghidra.dummy_monitor() if hasattr(pyghidra, "dummy_monitor") else None
    ok = emu.run(monitor)
    ret_reg = {"ARM": "r0", "AARCH64": "x0", "x86": "RAX", "MIPS": "v0"}
    result = emu.readRegister(ret_reg.get(proc, "r0"))
    print(f"INPUT={data.hex()} RET={hex(int(str(result)))} stopped={ok}")
```

**Hooking external calls:** when execution reaches a PLT/import stub the emulator
cannot resolve, set a breakpoint at the call site, write the modeled return value
into the result register, and advance PC past the call. Document each stub in the
finding `evidence` so the assumption is auditable.

## Method 2 — Unicorn Engine caller (`uv tool install`/`pip install unicorn`)

Native-speed CPU emulation across ARM/MIPS/x86/AArch64. Map the code page and a
stack, write inputs, emulate from the function entry to a sentinel return
address, and hook unmapped calls (PLT) to skip or stub them. If `unicorn` is not
present, fall back to Method 1.

```python
# Requires: uv tool install unicorn   (or: pip install unicorn capstone)
from unicorn import *
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_SP, UC_ARM_REG_PC, UC_ARM_REG_LR

CODE_BASE, STACK_BASE, IN_BASE = 0x10000, 0x200000, 0x300000
func_off = 0x...        # offset of the function in the mapped image (from Ghidra)
code = open("firmware.bin", "rb").read()

mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
mu.mem_map(CODE_BASE, 0x100000); mu.mem_write(CODE_BASE, code)
mu.mem_map(STACK_BASE, 0x10000); mu.mem_map(IN_BASE, 0x10000)

payload = b"A" * 64
mu.mem_write(IN_BASE, payload)
mu.reg_write(UC_ARM_REG_SP, STACK_BASE + 0x8000)
mu.reg_write(UC_ARM_REG_R0, IN_BASE)           # arg0 = input pointer
RET = CODE_BASE + len(code) + 0x10             # unmapped sentinel
mu.reg_write(UC_ARM_REG_LR, RET)

# Skip any call that lands outside the mapped code (PLT/import) by returning to LR.
def on_unmapped(uc, access, addr, size, value, ud):
    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR)); return True
mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, on_unmapped)

try:
    mu.emu_start(CODE_BASE + func_off, RET)
except UcError as e:
    print("CRASH", e, "pc=", hex(mu.reg_read(UC_ARM_REG_PC)))   # crash = observable effect
print("RET r0 =", hex(mu.reg_read(UC_ARM_REG_R0)))
```

## Recording evidence

A function-emulation result is a valid Stage-C observable effect (see
`finding-validation/stages.md`). Put concrete, reproducible facts in the finding
`evidence` array, e.g.:

- `"emulated decrypt_token(): input 41414141… → output deadbeef…, confirms fixed XOR key 0x5a (Method 1, pyghidra p-code)"`
- `"emulated parse_header() with len=0xffffffff → UcError WRITE_UNMAPPED at pc=0x10a4c, out-of-bounds write reachable from the length field"`

State which method and any stubbed calls. If neither emulator is available,
record the gap (`capabilities.json`) and downgrade the finding to `confirmed`
rather than claiming an unverified effect.
