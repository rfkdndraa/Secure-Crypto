# SecureCrypto — Ascon-AEAD128 IP core (NIST SP 800-232)

RTL for the Hackathon Chip 2026 proposal *SecureCrypto: IP Core Ascon-AEAD128 dengan Isolasi Kunci dan Proteksi terhadap Side-Channel serta Fault Injection*.
Plain Verilog-2001. The same RTL runs in Quartus Prime (DE10-Nano), Icarus/Verilator (simulation) and Yosys → LibreLane (ASIC, IIC-OSIC-TOOLS).

## What was verified here

| Check | Tool | Result |
| --- | --- | --- |
| All 1,089 official Ascon-AEAD128 KAT vectors (ascon-c `LWC_AEAD_KAT_128_128.txt`), encrypt **and** decrypt, through the bus interface | Icarus Verilog 12 | PASS, variants A, B, C |
| Tampered tag → decryption fails, no plaintext readable | Icarus | PASS |
| Key window reads return 0 and are logged; locked slot refuses writes | Icarus | PASS |
| Fault injection: A and B release a wrong tag; C detects it and releases nothing (also in the last finalization round) | Icarus | PASS |
| Masking active: share 1 non-zero and different between identical runs | Icarus | PASS |
| Nonce policy, lifecycle lock, zeroize, decrypt-buffer overflow | Icarus | PASS |
| Board top + on-board self-test (KEY/SW/LED behaviour) | Icarus | PASS, all variants |
| Lint, all variants | Verilator 5.020 `-Wall` | clean |
| Synthesizable, no latches, `check -assert` | Yosys 0.33 | PASS |

**Not run here:** Quartus Prime (fitter, timing, real ALM count) and LibreLane place-and-route. Run them yourself (commands below) before you put numbers in the proposal.

## Files

```text
rtl/
  sc_ascon_round.v     Ascon round: unmasked (1 cycle) and DOM-masked (2 phases)
  sc_ascon_core.v      Ascon-AEAD128 sponge: init, AD, enc/dec, finalization, injector
  sc_prng.v            mask / key-generation PRNG (demo grade)
  securecrypto.v       IP top: Avalon-MM slave, key manager, policies, duplication check
  sc_selftest.v        on-board self-test sequencer (Avalon-MM master)
  sc_selftest_rom.v    self-test program (generated from the official KAT)
  de10nano_top.v       DE10-Nano stand-alone top (buttons, switches, LEDs, GPIO)
tb/
  tb_securecrypto.v    IP testbench (KAT + security tests)
  tb_de10nano.v        board-level testbench
  gen_vectors.py       KAT file -> tb/kat.hex (cross-checked with pyascon)
  gen_selftest.py      KAT file -> rtl/sc_selftest_rom.v
  kat.hex              generated vectors
quartus/
  securecrypto.qpf     project with revisions sc_a, sc_b, sc_c
  sc_a.qsf sc_b.qsf sc_c.qsf   device, files, VARIANT, PIN ASSIGNMENTS
  securecrypto.sdc     50 MHz clock constraint
  securecrypto_hw.tcl  Platform Designer component (for the HPS demo)
asic/
  securecrypto_{a,b,c}.v   fixed-parameter macro tops
  config_{a,b,c}.json      LibreLane configs
  run_yosys.sh             synthesis + area report with any liberty file
```

## Pin assignment (DE10-Nano)

Pins checked against Terasic's *DE10-Nano User Manual* (Tables 3-5 to 3-10). All 3.3-V LVTTL.

| Port | Pin | Function |
| --- | --- | --- |
| `FPGA_CLK1_50` | PIN_V11 | 50 MHz clock |
| `KEY[0]` | PIN_AH17 | run self-test (press = low) |
| `KEY[1]` | PIN_AH16 | reset |
| `SW[0]` | PIN_Y24 | add fault-injection step |
| `SW[1]` | PIN_W24 | add illegal key-read step |
| `LED[0]` | PIN_W15 | PASS |
| `LED[1]` | PIN_AA24 | FAIL |
| `LED[2]` | PIN_V16 | FAULT detected (variant C) |
| `LED[3]` | PIN_V15 | key-access VIOLATION |
| `LED[4]` | PIN_AF26 | running (blinks) |
| `LED[5]` | PIN_AE26 | LAB build (injector present) |
| `GPIO_0[0]` | PIN_V12 | scope trigger: permutation running |
| `GPIO_0[1]` | PIN_E8 | operation done |

LED[6] and LED[7] exist on the board but are not used. I could not read their pin rows reliably from the manual, so they are left out rather than guessed.

## Build and run

Simulation (Icarus Verilog):

```sh
python3 tb/gen_vectors.py LWC_AEAD_KAT_128_128.txt pyascon tb/kat.hex   # only if regenerating
for v in 0 1 2; do
  iverilog -g2005 -P tb_securecrypto.VARIANT=$v -o sim$v rtl/*.v tb/tb_securecrypto.v
  vvp -n sim$v +VEC=tb/kat.hex | grep RESULT
  iverilog -g2005 -P tb_de10nano.VARIANT=$v -o board$v rtl/*.v tb/tb_de10nano.v
  vvp -n board$v | grep RESULT
done
```

DE10-Nano, stand-alone (no HPS needed):

```sh
cd quartus
quartus_sh --flow compile securecrypto -c sc_c        # or sc_a / sc_b
quartus_pgm -m jtag -o "p;output_files_sc_c/sc_c.sof@2"   # FPGA is device 2 in the chain; confirm with jtagconfig
```

Press KEY[0]. LED[0] = all KAT checks passed. Turn SW[0] on and press again: A/B light FAIL only (a wrong tag was released); C lights FAIL + FAULT (nothing was released).

ASIC, inside IIC-OSIC-TOOLS (IHP SG13G2):

```sh
cd asic
librelane --pdk ihp-sg13g2 --manual-pdk --pdk-root $PDK_ROOT config_c.json
# quick area check without place-and-route:
./run_yosys.sh $PDK_ROOT/ihp-sg13g2/libs.ref/sg13g2_stdcell/lib/sg13g2_stdcell_typ_1p20V_25C.lib c
```

`--pdk`, `--manual-pdk` and `--pdk-root` are LibreLane CLI options. Check the LibreLane version in your image; older images ship OpenLane 2 (`openlane` command), which takes the same JSON keys. For sky130, use `--pdk sky130A`.

## Synthesis estimates (Yosys — not sign-off)

| | A (unmasked) | B (masked) | C (masked + duplicated) |
| --- | --- | --- | --- |
| Cyclone V, whole board top incl. self-test (`synth_intel_alm`) | 7.2 k ALUT, 4.4 k FF | 10.7 k ALUT, 6.9 k FF | 15.8 k ALUT, 9.8 k FF |
| IHP SG13G2 cell area, ASIC macro (64-byte decrypt buffer) | 0.28 mm² | 0.52 mm² | 0.82 mm² |
| IHP SG13G2 cell area, bare core only | 0.080 mm² | 0.289 mm² | 2 × 0.289 mm² |
| Clock cycles per 16-byte block (absorb + 8 rounds + 1) | 10 | 18 | 18 |
| Clock cycles for init / finalization (12 rounds + 1) | 13 / 13 | 25 / 25 | 25 / 25 |
| Core-limited throughput at 50 MHz (no bus overhead) | ≈ 80 MB/s | ≈ 44 MB/s | ≈ 44 MB/s |

DE10-Nano capacity: 41,910 ALMs; one ALM holds up to two ALUTs. Use the Quartus fitter report for the proposal table. IHP figures are cell area before placement; the die is roughly that area divided by the 40 % utilization in the config.

## Register map

32-bit Avalon-MM slave, word addressed, read latency 1. From the HPS: byte address = `0xFF200000` (lightweight bridge) + base offset + 4 × word.

| Word | Name | Access | Content |
| --- | --- | --- | --- |
| 0 | ID | R | `0x534301vv`, vv = variant |
| 1 | CTRL | W | [0] start · [1] decrypt · [2] has_AD · [3] key slot · [4] nonce must increase · [8] abort · [9] zeroize (also keys) · [10] generate slot-0 key · [11] lock slot 1 · [12] clear flags |
| 2 | STATUS | R | [0] busy · [1] block ready · [2] done · [3] tag OK · [4] fault · [5] violation · [6] nonce error · [7] protocol error · [8] fault lock · [9] lifecycle locked · [10] lab build · [11] slot0 valid · [12] slot1 valid · [13] slot1 locked · [14] injector armed · [17:16] variant |
| 3 | BLK | W | [4:0] bytes in final block (0–15) · [8] is AD · [9] last. Writing it submits DIN |
| 4–7 | NONCE | W | 128-bit nonce |
| 8–11 | DIN | W | input block |
| 12–15 | DOUT | R | last ciphertext block (encrypt only; reads 0 when decrypting) |
| 16–19 | TAG_IN | W | expected tag, write before starting a decryption |
| 20–23 | TAG_OUT | R | tag after encryption (never shown for decryption) |
| 24–27 | KEY_WR | W | slot-1 key, write-only |
| 28–31 | KEY_RD | R | always 0, every read is logged as a violation |
| 32 | SEED | W | XORed into the PRNG (cannot set its state) |
| 33 | FAULT_CFG | W | lab only: [0] enable · [11:4] round · [14:12] word · [21:16] bit |
| 34 / 35 | FAULT_CNT / VIOL_CNT | R | counters |
| 36 | CYCLES | R | clock cycles the core spent computing in the last operation |
| 37 | LIFECYCLE | R/W | write `0x4C4F434B` ("LOCK"): injector off until power cycle |
| 38 / 39 | OUT_CNT / DBUF_LEN | R | output blocks / decrypted bytes |
| 64–127 | DBUF | R | decrypted plaintext; readable only after the tag verified |

**Byte order:** byte *i* of a block sits in word *i*/4 at bits 8·(*i* mod 4), i.e. plain little-endian `memcpy` on the ARM.

**Message framing:** send full 16-byte blocks, then exactly one final block of 0–15 bytes with `last=1`. Empty messages still send one final block. With no AD, set has_AD=0 and send no AD block. This is SP 800-232's padding rule, so the hardware never adds a hidden block.

Encryption sequence: write NONCE → CTRL start → for each block: wait STATUS[1], write DIN, write BLK, read DOUT → wait STATUS[2] → read TAG_OUT.

## How the code works

**`sc_ascon_round.v` — the permutation.** The 320-bit state is five 64-bit words (x0 in bits 63:0 … x4 in bits 319:256), each the little-endian integer of 8 bytes, exactly as in SP 800-232. `sc_ascon_round` is one full round in one clock: add the round constant `((15−r)<<4)|r` to x2, run the 5-bit S-box in its bitsliced form (XOR pre-layer, the non-linear `t_i = ¬a_i ∧ a_{i+1}`, XOR post-layer), then the linear layer `x ^= rotr(x,a) ^ rotr(x,b)` per word.
The masked version splits every bit into two shares whose XOR is the real value. Linear steps (XORs, rotations, constants) are done on each share separately. The only non-linear part is the AND, built as a first-order **Domain-Oriented Masking** gadget: the four partial products `a0·b0`, `a1·b1`, `a0·b1⊕r`, `a1·b0⊕r` are formed in phase A and **registered**. In phase B they are combined back into two shares. The register stage stops glitches from combining both shares of a secret in the combinational logic. Cost: 2 clocks per round and 320 fresh random bits per round. NOTs and the round constant go on share 0 only.

**`sc_ascon_core.v` — the AEAD mode.** A four-state FSM: `IDLE → PERM → POST → WAIT`.
- On `start` the state is loaded with IV ‖ K ‖ N (IV = `0x00001000808C0001`), then 12 rounds.
- `POST` applies the step that follows each permutation: XOR the key into x3,x4 after init, domain separation (`x4 ^= 1<<63`) after the last AD block, or tag = (x3⊕K0, x4⊕K1) after finalization.
- In `WAIT` the core takes one block. AD is XORed into the 128-bit rate. When encrypting, plaintext is XORed in and the rate becomes the ciphertext. When decrypting, the rate is overwritten with the ciphertext bytes (with shares, share 0 is set to `C ⊕ share1` so the shares still add up), and the 0x01 padding byte goes right after the last valid byte. The final message block also XORs the key into x2,x3 and starts the 12-round finalization.
- The two rate shares are only recombined in the cycle a message block is absorbed. The output is ciphertext or plaintext that is released anyway; the gating keeps that XOR quiet during the permutation.
- The fault injector (lab builds) flips one chosen state bit after a chosen round number.

**`securecrypto.v` — the IP around the core.**
- **Key isolation:** two slots, each stored as two shares in the masked variants. Slot 1 is written word by word as `(w⊕r, r)`. Slot 0 is generated in hardware as two random shares, so the key never sits whole in one register and never crosses the bus. No address returns a key bit: the KEY_RD window always reads 0 and counts the attempt. A locked slot refuses writes, and that is logged too.
- **Release rules:**
  - Decryption plaintext goes into a buffer that is readable only once the tag has matched. On a tag failure the buffer is wiped.
  - The computed tag of a decryption is never readable; it would let an attacker forge messages.
  - A message larger than the buffer is refused.
- **Variant C (duplication):** a second core gets exactly the same inputs and the same randomness. Both copies therefore hold identical shares, and the wrapper compares them share by share every clock, together with the control state and the outputs. This catches a fault in either copy without ever recombining a secret. On a mismatch, in the same cycle, it aborts, withholds DOUT, the tag and the buffer, wipes working data and counts the fault. After `FAULT_LIMIT` (16) faults the IP refuses further work until reset. Keys are not erased on the first fault, so one glitch cannot be used to wipe them (denial of service).
- **Other:** optional strictly increasing nonce per slot (catches nonce reuse), cycle counter, lifecycle lock that disables the injector, and abort and zeroize commands.

**`sc_prng.v`** — five xorshift64 lanes give 320 bits per clock. The host can only XOR seed material in, never set the state.

**`sc_selftest.v` + `de10nano_top.v`** — a small Avalon master runs a program generated from the official KAT: 4 vectors encrypt + decrypt, plus the optional fault and key-read steps. It drives the IP through the same registers the HPS will use, and shows the result on the LEDs. The board can be checked before any Linux software exists.

## HPS integration (for the performance and key-isolation demos)

1. Open Terasic's DE10-Nano GHRD (`DE10_NANO_SoC_GHRD`, from the DE10-Nano CD) in Quartus.
2. Add `quartus/` to Platform Designer's IP search path. Add *SecureCrypto Ascon-AEAD128* and set VARIANT.
3. Connect `clock`/`reset` to the system clock and reset, and `s0` to `hps_0.h2f_lw_axi_master`. Note the base address it gets.
4. Export the `status` conduit and wire `trig` to a GPIO pin in the GHRD top. Generate, compile.
5. In Linux, `mmap` `/dev/mem` at `0xFF200000 + base` and follow the register sequence above.

## Limitations — say these out loud

- **The PRNG is not cryptographic and there is no entropy source.** Mask quality, and therefore any leakage result, depends on it. The slot-0 key also comes from it. Replace it with a TRNG + DRBG (SP 800-90A/B) before any security claim; until then, slot 0 is a demo.
- **First-order masking only.** It has not been checked with a masking verifier (PROLEAD, SILVER, maskVerif) or TVLA yet. FPGA routing glitches and synthesis optimizations can still leak. Quartus may merge logic across shares; check that the hierarchy is preserved before measuring.
- **Duplication blind spots:**
  - A fault that hits both copies the same way (a global clock or voltage glitch) is not detected.
  - The wrapper's key and input registers are not duplicated.
  - A first improvement is a one-cycle time offset between the copies, plus separate placement regions on the FPGA.
- **No persistent storage:** the lifecycle lock and fault lock reset on power cycle.
- **Host framing:** the host must frame messages as described above; the hardware refuses anything else.
- **FPGA ≠ ASIC:** FPGA results do not transfer to ASIC.
