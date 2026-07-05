//! x86-64 relocation recovery from linked PE code.
//!
//! Handles:
//!   * `E8 rel32`       (call rel32)         → IMAGE_REL_AMD64_REL32 at offset 1
//!   * `E9 rel32`       (jmp rel32)          → IMAGE_REL_AMD64_REL32 at offset 1
//!   * `0F 8x rel32`    (jcc rel32)          → IMAGE_REL_AMD64_REL32 at offset 2
//!   * `[rip + disp32]` (RIP-relative mem)   → IMAGE_REL_AMD64_REL32 at disp field
//!
//! Intra-function branches are skipped (no reloc emitted).
//! Unresolved targets are counted but not reloc'd.

use anyhow::Result;
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register,
};
use tracing::trace;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocKind {
    /// IMAGE_REL_AMD64_REL32 family — 32-bit PC-relative (calls, jumps,
    /// [rip+disp]). `trailing` is the number of instruction bytes that follow
    /// the 32-bit fixup field, i.e. a trailing immediate on a RIP-relative
    /// operand (`mov byte ptr [rip+x], imm8` → 1). It selects the exact reloc
    /// type: 0 → REL32, 1 → REL32_1, … 5 → REL32_5. Branches and RIP-relative
    /// refs with no trailing immediate use 0.
    Rel32 { trailing: u8 },
    /// IMAGE_REL_AMD64_ADDR32NB — 32-bit RVA (image-base-relative). Emitted for
    /// `[imagebase_reg + index*scale + rva]` accesses (jump tables, /Gy RVA data).
    Addr32Nb,
    /// IMAGE_REL_AMD64_SECREL — 32-bit section-relative offset. Emitted for the
    /// `mov r32, <tls-offset>` that loads a thread-local variable's offset within
    /// the `.tls` section (the `_tls_index` + `gs:[0x58]` access idiom).
    Secrel,
    /// IMAGE_REL_AMD64_ADDR64 — 64-bit absolute pointer embedded in code/data.
    Addr64,
}

/// A switch jump table recovered from an image-base-relative indexed load.
/// The entries are 4-byte RVAs (relative to the image base) pointing at the
/// case labels, so they become ADDR32NB relocations and the table itself gets
/// its own data symbol (which also bounds the owning function in objdiff).
#[derive(Debug, Clone)]
pub struct RecoveredJumpTable {
    /// Synthesized symbol name for the table.
    pub name: String,
    /// Offset within the function bytes where the table starts.
    pub offset: u64,
    /// Number of 4-byte entries.
    pub entry_count: u64,
}

#[derive(Debug, Clone)]
pub struct RecoveredReloc {
    /// Byte offset within the function bytes where the fixup field lives.
    pub offset: u64,
    /// Instruction address (fn_va + offset of instruction start).
    pub pc: u64,
    pub kind: RelocKind,
    /// Symbol name the reloc targets.
    pub target: String,
    /// Addend relative to the symbol (0 = target is exactly the symbol start).
    pub addend: i64,
}

#[derive(Debug, Default)]
pub struct RecoveryDiagnostics {
    pub instructions: usize,
    pub decode_failures: usize,
    pub calls_resolved: usize,
    pub calls_unresolved: usize,
    pub rip_refs_resolved: usize,
    pub rip_refs_unresolved: usize,
}

pub struct RecoveryOutput {
    pub relocs: Vec<RecoveredReloc>,
    pub jump_tables: Vec<RecoveredJumpTable>,
    pub diag: RecoveryDiagnostics,
    /// Byte offsets (within the function) of the `F3` prefix of each `rep ret`
    /// (`F3 C3`) instruction. The emitter can strip these to plain `ret`.
    pub rep_ret_offsets: Vec<u64>,
}

/// Trait that callers implement to resolve VAs to symbol names.
pub trait SymbolResolver {
    /// Resolve a code target (call/jmp destination) → (symbol_name, addend).
    fn resolve_code(&self, va: u64) -> Option<(String, i64)>;
    /// Resolve a data reference (RIP-relative) → (symbol_name, addend).
    fn resolve_data(&self, va: u64) -> Option<(String, i64)>;
    /// The PE image base — anchor for `lea reg, [rip+imagebase]` RVA addressing.
    /// The default (`u64::MAX`) disables image-base-relative recovery for
    /// resolvers that don't track it (it can never equal a real displacement).
    fn image_base(&self) -> u64 {
        u64::MAX
    }
    /// True if `va` lies in an executable (`.text`) section. Defaults to false,
    /// which disables jump-table recovery for resolvers that don't track it.
    fn in_text(&self, _va: u64) -> bool {
        false
    }
    /// Resolve a `.tls` section-relative offset to a thread-local variable
    /// `(name, addend)`. Defaults to None, which disables TLS SECREL recovery
    /// for resolvers that don't track thread-local variables.
    fn resolve_tls_offset(&self, _offset: u32) -> Option<(String, i64)> {
        None
    }
    /// Returns true if `va` is inside the current function (intra-function branch).
    fn is_intra_function(&self, fn_va: u64, fn_size: u64, target_va: u64) -> bool {
        target_va >= fn_va && target_va < fn_va + fn_size
    }
}

/// Map a register to its 0..15 GP64 index (RAX=0 … R15=15), or None.
fn gpr64_index(reg: Register) -> Option<usize> {
    let full = reg.full_register();
    if full.is_gpr64() {
        Some(full.number())
    } else {
        None
    }
}

/// Walk `fn_bytes` starting at `fn_va`, synthesise COFF relocations.
///
/// `fn_size` is the function's byte count (used to detect intra-function
/// branches that need no reloc). Provide `fn_size = fn_bytes.len() as u64`
/// when splitting functions individually.
pub fn recover<R: SymbolResolver>(
    fn_bytes: &[u8],
    fn_va: u64,
    fn_size: u64,
    resolver: &R,
) -> Result<RecoveryOutput> {
    let mut decoder = Decoder::with_ip(64, fn_bytes, fn_va, DecoderOptions::NONE);
    let mut insn = Instruction::default();

    let mut out = RecoveryOutput {
        relocs: Vec::new(),
        jump_tables: Vec::new(),
        diag: RecoveryDiagnostics::default(),
        rep_ret_offsets: Vec::new(),
    };

    let image_base = resolver.image_base();
    let mut info_factory = InstructionInfoFactory::new();
    // Registers currently known to hold __ImageBase (GP64 index 0..15), set by
    // `lea reg, [rip+imagebase]` and cleared when the register is overwritten.
    let mut imgbase: [bool; 16] = [false; 16];
    // Thread-local storage: a `mov r32, <tls-offset>` is only a SECREL reference
    // if the function actually performs TLS access (`gs:[0x58]`), so gather the
    // candidates and only commit them once that idiom has been seen.
    let mut tls_context = false;
    let mut tls_candidates: Vec<RecoveredReloc> = Vec::new();

    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        out.diag.instructions += 1;

        if insn.is_invalid() {
            out.diag.decode_failures += 1;
            continue;
        }

        let pc = insn.ip();
        let insn_offset = pc - fn_va;
        let insn_len = insn.len() as u64;
        let offsets = decoder.get_constant_offsets(&insn);

        // `rep ret` (F3 C3): a 2-byte near return carrying a redundant REP
        // prefix. Record the `F3` byte so the emitter can drop it to plain `ret`.
        if insn.mnemonic() == Mnemonic::Ret
            && insn_len == 2
            && fn_bytes.get(insn_offset as usize) == Some(&0xF3)
        {
            out.rep_ret_offsets.push(insn_offset);
        }

        // Invalidate any tracked __ImageBase register this instruction writes.
        // (Done before re-establishing state below so a fresh `lea` survives.)
        let info = info_factory.info(&insn);
        for ur in info.used_registers() {
            if matches!(
                ur.access(),
                OpAccess::Write
                    | OpAccess::ReadWrite
                    | OpAccess::CondWrite
                    | OpAccess::ReadCondWrite
            ) {
                if let Some(i) = gpr64_index(ur.register()) {
                    imgbase[i] = false;
                }
            }
        }

        // --- Thread-local storage (SECREL) ---
        // `gs:[0x58]` reads the TEB's thread-local storage pointer: the marker
        // that this function touches TLS. A `mov r32, imm32` whose immediate is a
        // known `.tls` variable offset is then that variable's SECREL reference.
        if insn.memory_segment() == Register::GS && insn.memory_displacement64() == 0x58 {
            tls_context = true;
        }
        if insn.mnemonic() == Mnemonic::Mov
            && insn.op0_kind() == OpKind::Register
            && insn.op1_kind() == OpKind::Immediate32
        {
            if let Some((sym, addend)) = resolver.resolve_tls_offset(insn.immediate32()) {
                tls_candidates.push(RecoveredReloc {
                    offset: insn_offset + offsets.immediate_offset() as u64,
                    pc,
                    kind: RelocKind::Secrel,
                    target: sym,
                    addend,
                });
            }
        }

        // --- Direct near branches with a 32-bit relative operand ---
        // rel8 branches are 2 bytes; rel32 are 5 (E8/E9) or 6 (0F 8x) bytes.
        // Only rel32 can cross function boundaries and need a relocation.
        match insn.flow_control() {
            FlowControl::Call
            | FlowControl::UnconditionalBranch
            | FlowControl::ConditionalBranch => {
                if insn_len >= 5 {
                    let target_va = insn.near_branch64();

                    if !resolver.is_intra_function(fn_va, fn_size, target_va) {
                        // The rel32 field is always the last 4 bytes of these instructions.
                        let rel32_off = insn_len - 4;

                        match resolver.resolve_code(target_va) {
                            Some((sym, addend)) => {
                                out.relocs.push(RecoveredReloc {
                                    offset: insn_offset + rel32_off,
                                    pc,
                                    // A branch's rel32 is the last 4 bytes: no trailing immediate.
                                    kind: RelocKind::Rel32 { trailing: 0 },
                                    target: sym,
                                    addend,
                                });
                                out.diag.calls_resolved += 1;
                            }
                            None => {
                                trace!("{:#x}: unresolved call/jmp target {:#x}", pc, target_va);
                                out.diag.calls_unresolved += 1;
                            }
                        }
                    }
                }
                // Skip memory-operand check for branch instructions.
                continue;
            }
            _ => {}
        }

        // --- Memory operands: RIP-relative, or image-base-relative (RVA) ---
        for op_idx in 0..insn.op_count() {
            if insn.op_kind(op_idx) != OpKind::Memory {
                continue;
            }
            let base = insn.memory_base();

            if base == Register::RIP {
                // [rip + disp32]: memory_displacement64() folds in the IP, so it
                // is the absolute target VA. The disp32 field is not necessarily
                // the last 4 bytes (a trailing immediate selects REL32_1..5).
                let target_va = insn.memory_displacement64();
                let disp_off = offsets.displacement_offset() as u64;
                let trailing = (offsets.immediate_size() + offsets.immediate_size2()) as u8;

                match resolver.resolve_data(target_va) {
                    Some((sym, addend)) => {
                        out.relocs.push(RecoveredReloc {
                            offset: insn_offset + disp_off,
                            pc,
                            kind: RelocKind::Rel32 { trailing },
                            target: sym,
                            addend,
                        });
                        out.diag.rip_refs_resolved += 1;
                    }
                    None => {
                        trace!("{:#x}: unresolved RIP-relative ref to {:#x}", pc, target_va);
                        out.diag.rip_refs_unresolved += 1;
                    }
                }
                break;
            }

            // [imagebase_reg + index*scale + rva]: image-base-relative addressing
            // (jump tables and /Gy RVA data). For a register base,
            // memory_displacement64() is the raw disp32 = the RVA.
            if let Some(bi) = gpr64_index(base) {
                if imgbase[bi] {
                    let rva = insn.memory_displacement64();
                    let target_va = image_base.wrapping_add(rva);
                    let disp_off = offsets.displacement_offset() as u64;

                    if resolver.in_text(target_va)
                        && target_va >= fn_va
                        && target_va < fn_va + fn_size
                    {
                        // A switch jump table inside this function's body. Its
                        // entries are 4-byte RVAs to case labels that sit before
                        // the table; count them and emit ADDR32NB relocs + a
                        // table symbol (which also bounds the function).
                        let table_off = target_va - fn_va;
                        let name = format!("$jpt_{:x}", target_va);
                        let mut entries: Vec<RecoveredReloc> = Vec::new();
                        let mut i = 0u64;
                        loop {
                            let e = (table_off + i * 4) as usize;
                            if e + 4 > fn_bytes.len() {
                                break;
                            }
                            let entry_rva =
                                u32::from_le_bytes(fn_bytes[e..e + 4].try_into().unwrap()) as u64;
                            let case_va = image_base.wrapping_add(entry_rva);
                            if case_va < fn_va || case_va >= fn_va + table_off {
                                break;
                            }
                            match resolver.resolve_code(case_va) {
                                Some((sym, addend)) => entries.push(RecoveredReloc {
                                    offset: table_off + i * 4,
                                    pc: target_va + i * 4,
                                    kind: RelocKind::Addr32Nb,
                                    target: sym,
                                    addend,
                                }),
                                None => break,
                            }
                            i += 1;
                        }
                        if !entries.is_empty() {
                            let count = entries.len() as u64;
                            out.relocs.extend(entries);
                            out.relocs.push(RecoveredReloc {
                                offset: insn_offset + disp_off,
                                pc,
                                kind: RelocKind::Addr32Nb,
                                target: name.clone(),
                                addend: 0,
                            });
                            out.jump_tables.push(RecoveredJumpTable {
                                name,
                                offset: table_off,
                                entry_count: count,
                            });
                        }
                    } else if let Some((sym, addend)) = resolver.resolve_data(target_va) {
                        // RVA reference to a named data symbol.
                        out.relocs.push(RecoveredReloc {
                            offset: insn_offset + disp_off,
                            pc,
                            kind: RelocKind::Addr32Nb,
                            target: sym,
                            addend,
                        });
                    }
                    break;
                }
            }
        }

        // --- Establish __ImageBase tracking: lea reg64, [rip + imagebase] ---
        if insn.mnemonic() == Mnemonic::Lea
            && insn.op0_kind() == OpKind::Register
            && insn.op1_kind() == OpKind::Memory
            && insn.memory_base() == Register::RIP
            && insn.memory_displacement64() == image_base
        {
            if let Some(i) = gpr64_index(insn.op0_register()) {
                imgbase[i] = true;
            }
        }
    }

    // Commit TLS SECREL relocations only if the function actually accessed TLS.
    if tls_context {
        out.relocs.append(&mut tls_candidates);
    }

    Ok(out)
}
