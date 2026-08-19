use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "delink",
    version,
    about = "Split a debug .so or .exe into .o/.obj files"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Report sections, dynamic relocations, and DWARF compilation units.
    Inspect { input: PathBuf },

    /// Emit a single CU as an ET_REL `.o` file (no relocations yet; M2 validation).
    Emit {
        input: PathBuf,
        /// Match against the suffix of the CU name (e.g. `bacolor.cpp`).
        #[arg(long)]
        cu: String,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        comdat: bool,
        #[arg(long)]
        dwarf: bool,
        /// Emit one `.text.<mangled>` per function (default: single `.text`).
        #[arg(long)]
        per_function_sections: bool,
    },

    /// List CUs matching a substring, sorted by .text size ascending.
    ListCus {
        input: PathBuf,
        #[arg(long, default_value = "")]
        contains: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },

    /// Dump a relocatable `.o` file's sections and symbols (for validation).
    Readobj { input: PathBuf },

    /// Emit `__shared_data.o` carrying .rodata / .bss (and eventually .data).
    EmitShared {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Split the whole `.so` into one `.o` per CU plus `__shared_data.o`.
    Split {
        input: PathBuf,
        #[arg(short, long)]
        outdir: PathBuf,
        #[arg(long)]
        comdat: bool,
        #[arg(long)]
        dwarf: bool,
        /// Emit one `.text.<mangled>` per function (default: single `.text`).
        /// Required for `--comdat` and for `ld --gc-sections` to work.
        #[arg(long)]
        per_function_sections: bool,
    },

    // -----------------------------------------------------------------------
    // Windows PE + PDB subcommands
    // -----------------------------------------------------------------------
    /// Inspect a Windows PE (.exe) and its PDB: print sections, imports, and CU list.
    PeInspect {
        /// Path to the PE executable (.exe or .dll).
        input: PathBuf,
        /// Path to the matching PDB file.
        #[arg(long)]
        pdb: PathBuf,
    },

    /// List PDB modules (CUs) sorted by .text size.
    PeListCus {
        input: PathBuf,
        #[arg(long)]
        pdb: PathBuf,
        #[arg(long, default_value = "")]
        contains: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },

    /// Split a PE + PDB into one COFF `.obj` per module plus `__shared_data.obj`.
    PeSplit {
        /// Path to the PE executable (.exe or .dll).
        input: PathBuf,
        /// Path to the matching PDB file.
        #[arg(long)]
        pdb: Option<PathBuf>,
        /// Existing editable symbol manifest.
        #[arg(long)]
        symbols: Option<PathBuf>,
        /// Existing editable split manifest.
        #[arg(long)]
        splits: Option<PathBuf>,
        /// Run the no-PDB x86 analysis instead of the config-driven split.
        /// Emits raw analysis manifests (functions/strings/splits) for seeding.
        #[arg(long)]
        analyze: bool,
        /// Output directory for the `.obj` files.
        #[arg(short, long)]
        outdir: PathBuf,
        /// Rewrite `rep ret` (F3 C3) to a plain `ret` (C3) in emitted code.
        #[arg(long)]
        replace_rep_ret: bool,
    },

    // -----------------------------------------------------------------------
    // Mach-O subcommands
    // -----------------------------------------------------------------------
    /// Inspect a Mach-O binary: print sections and DWARF compilation units.
    MachoInspect {
        /// Path to the Mach-O executable or dylib.
        input: PathBuf,
    },

    /// List Mach-O DWARF compilation units sorted by .text size.
    MachoListCus {
        input: PathBuf,
        #[arg(long, default_value = "")]
        contains: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },

    /// Split a Mach-O binary into one `.o` per function (symtab-driven) plus `__shared_data.o`.
    ///
    /// On the first run a `symtab.json` is generated in the output directory
    /// listing every N_SECT function symbol with its raw symbol-table fields and
    /// a `cu` field naming the output `.o` file.  Edit the `cu` values to group
    /// functions and re-run with `--symtab` to produce the merged files.
    MachoSplit {
        /// Path to the Mach-O executable or dylib.
        input: PathBuf,
        /// Output directory for the `.o` files.
        #[arg(short, long)]
        outdir: PathBuf,
        /// Path to an existing `symtab.json` to control function → file grouping.
        /// If omitted a default symtab (one function per file) is created and
        /// written to `<outdir>/symtab.json`.
        #[arg(long)]
        symtab: Option<PathBuf>,
        /// Emit standard ELF ET_REL objects instead of Mach-O objects.
        ///
        /// Useful when targeting a Linux/ELF toolchain with a Mach-O input.
        /// i386 input: PC-relative calls become `R_386_PC32` relocations.
        /// `__DATA,__data` → `.data`, `__DATA,__const` → `.rodata`,
        /// `__DATA,__bss` → `.bss`.
        #[arg(long)]
        emit_elf: bool,
    },

    // -----------------------------------------------------------------------
    // IDA import subcommands  (consume JSON produced by crates/delink-ida/ida_export.py)
    // -----------------------------------------------------------------------
    /// Inspect a `*.delink.json` exported from IDA: arch, segments, counts.
    IdaInspect {
        /// Path to the JSON produced by `ida_export.py`.
        json: PathBuf,
    },

    /// Split using an IDA export: one object per function (or per `idapro.json`
    /// group) plus a shared data object.
    ///
    /// For x86/x86-64 the function bytes are disassembled with iced-x86 to
    /// recover rel32 / RIP-relative relocations; IDA's fixup table supplies the
    /// absolute pointer relocations.  On the first run a default `idapro.json`
    /// (one function per file) is written to the output directory; edit it to
    /// group functions and re-run with `--idapro`.
    IdaSplit {
        /// Path to the JSON produced by `ida_export.py`.
        json: PathBuf,
        /// Path to the original input binary (the export carries no bytes; the
        /// function/section bytes and the PE `.reloc` table come from here).
        binary: PathBuf,
        /// Output directory for the objects.
        #[arg(short, long)]
        outdir: PathBuf,
        /// Path to an existing `idapro.json` controlling function → file grouping.
        #[arg(long)]
        idapro: Option<PathBuf>,
        /// Emit ELF `.o` objects instead of COFF `.obj` (default is chosen from
        /// the input file type: PE → COFF, ELF/Mach-O → ELF).
        #[arg(long)]
        elf: bool,
        /// Force COFF output regardless of the input file type.
        #[arg(long, conflicts_with = "elf")]
        coff: bool,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Inspect { input } => cmd_inspect(&input),
        Cmd::Emit {
            input,
            cu,
            output,
            comdat,
            dwarf,
            per_function_sections,
        } => cmd_emit(&input, &cu, &output, comdat, dwarf, per_function_sections),
        Cmd::ListCus {
            input,
            contains,
            limit,
        } => cmd_list_cus(&input, &contains, limit),
        Cmd::Readobj { input } => cmd_readobj(&input),
        Cmd::EmitShared { input, output } => cmd_emit_shared(&input, &output),
        Cmd::Split {
            input,
            outdir,
            comdat,
            dwarf,
            per_function_sections,
        } => cmd_split(&input, &outdir, comdat, dwarf, per_function_sections),
        Cmd::PeInspect { input, pdb } => cmd_pe_inspect(&input, &pdb),
        Cmd::PeListCus {
            input,
            pdb,
            contains,
            limit,
        } => cmd_pe_list_cus(&input, &pdb, &contains, limit),
        Cmd::PeSplit {
            input,
            pdb,
            symbols,
            splits,
            analyze,
            outdir,
            replace_rep_ret,
        } => cmd_pe_split(
            &input,
            pdb.as_deref(),
            symbols.as_deref(),
            splits.as_deref(),
            analyze,
            &outdir,
            replace_rep_ret,
        ),
        Cmd::MachoInspect { input } => cmd_macho_inspect(&input),
        Cmd::MachoListCus {
            input,
            contains,
            limit,
        } => cmd_macho_list_cus(&input, &contains, limit),
        Cmd::MachoSplit {
            input,
            outdir,
            symtab,
            emit_elf,
        } => cmd_macho_split(&input, &outdir, symtab.as_deref(), emit_elf),
        Cmd::IdaInspect { json } => cmd_ida_inspect(&json),
        Cmd::IdaSplit {
            json,
            binary,
            outdir,
            idapro,
            elf,
            coff,
        } => cmd_ida_split(&json, &binary, &outdir, idapro.as_deref(), elf, coff),
    }
}

fn cmd_split(
    path: &Path,
    outdir: &Path,
    comdat: bool,
    dwarf: bool,
    per_function_sections: bool,
) -> Result<()> {
    let mmap = mmap_file(path)?;
    let binary = open_binary(&mmap, path)?;
    tracing::info!("indexing DWARF…");
    let idx = delink_core::cu::CuIndex::build(&binary)?;
    tracing::info!("building symbol resolver…");
    let symbols = delink_core::symbols::GlobalSymbols::build(&binary, &idx)?;
    tracing::info!(
        "emitting {} CUs in parallel",
        idx.units
            .iter()
            .filter(|u| u.functions.iter().any(|f| f.size > 0))
            .count()
    );
    let outcomes = delink_emit::split_all(
        &binary,
        &idx,
        &symbols,
        outdir,
        comdat,
        dwarf,
        per_function_sections,
    )?;
    let shared = outdir.join("__shared_data.o");
    let shared_stats = delink_emit::emit_shared_data(
        &binary,
        &symbols,
        delink_emit::SharedDataOptions { dwarf },
        &shared,
    )?;

    let mut total = delink_emit::EmitStats::default();
    let mut failures = 0usize;
    for o in &outcomes {
        match &o.result {
            Ok(s) => {
                total.text_bytes += s.text_bytes;
                total.local_symbols += s.local_symbols;
                total.undef_symbols += s.undef_symbols;
                total.relocations += s.relocations;
                total.unresolved_calls += s.unresolved_calls;
                total.instructions += s.instructions;
                total.adrp_seen += s.adrp_seen;
                total.adrp_paired += s.adrp_paired;
                total.adrp_unresolved += s.adrp_unresolved;
            }
            Err(e) => {
                failures += 1;
                tracing::warn!(cu = %o.cu_name, error = %e, "emit failed");
            }
        }
    }
    println!(
        "split complete: {} CUs ({} failed)\n  {} bytes .text, {} instructions\n  {} local + {} undef symbols\n  {} relocs ({} unresolved calls, {} unresolved adrps of {})\n  shared data: rodata={} data={} data.rel.ro={} bss={}",
        outcomes.len() - failures,
        failures,
        total.text_bytes,
        total.instructions,
        total.local_symbols,
        total.undef_symbols,
        total.relocations,
        total.unresolved_calls,
        total.adrp_unresolved,
        total.adrp_seen,
        shared_stats.rodata_bytes,
        shared_stats.data_bytes,
        shared_stats.data_rel_ro_bytes,
        shared_stats.bss_bytes,
    );
    Ok(())
}

fn cmd_emit_shared(path: &Path, output: &Path) -> Result<()> {
    let mmap = mmap_file(path)?;
    let binary = open_binary(&mmap, path)?;
    let idx = delink_core::cu::CuIndex::build(&binary)?;
    let symbols = delink_core::symbols::GlobalSymbols::build(&binary, &idx)?;
    let stats = delink_emit::emit_shared_data(
        &binary,
        &symbols,
        delink_emit::SharedDataOptions { dwarf: true },
        output,
    )?;
    println!(
        "wrote {}\n  .rodata: {} bytes\n  .data: {} bytes\n  .data.rel.ro: {} bytes\n  .init_array: {} bytes\n  .fini_array: {} bytes\n  .bss: {} bytes\n  .eh_frame: {} bytes ({} FDE relocs)\n  data relocs: {} RELATIVE + {} ABS64 + {} GLOB_DAT translated; {} skipped, {} unresolved",
        output.display(),
        stats.rodata_bytes,
        stats.data_bytes,
        stats.data_rel_ro_bytes,
        stats.init_array_bytes,
        stats.fini_array_bytes,
        stats.bss_bytes,
        stats.eh_frame_bytes,
        stats.fde_relocs,
        stats.translated_relatives,
        stats.translated_abs64,
        stats.translated_glob_dat,
        stats.skipped_relocs,
        stats.unresolved_relocs,
    );
    Ok(())
}

fn cmd_readobj(path: &Path) -> Result<()> {
    use object::read::elf::{ElfFile64, FileHeader};
    use object::{Endianness, Object, ObjectSection, ObjectSymbol};

    let mmap = mmap_file(path)?;
    let elf = ElfFile64::<Endianness>::parse(&mmap[..])
        .with_context(|| format!("parse {}", path.display()))?;
    let endian = elf.elf_header().endian()?;
    let e_type = elf.elf_header().e_type(endian);
    let e_machine = elf.elf_header().e_machine(endian);

    println!("ELF  e_type=0x{:x} e_machine=0x{:x}", e_type, e_machine);
    println!("\nSECTIONS");
    for s in elf.sections() {
        let name = s.name().unwrap_or("<?>");
        println!(
            "  {:<24} addr={:#010x} size={:>8} kind={:?}",
            name,
            s.address(),
            s.size(),
            s.kind()
        );
    }

    println!("\nSYMBOLS");
    for sym in elf.symbols() {
        let name = sym.name().unwrap_or("<?>");
        if name.is_empty() {
            continue;
        }
        println!(
            "  {:<40} value={:#010x} size={:>6} kind={:?} scope={:?} section={:?}",
            name,
            sym.address(),
            sym.size(),
            sym.kind(),
            sym.scope(),
            sym.section(),
        );
    }

    println!("\nRELOCATIONS");
    let symbols: Vec<_> = elf.symbols().collect();
    for section in elf.sections() {
        let relocs: Vec<_> = section.relocations().collect();
        if relocs.is_empty() {
            continue;
        }
        println!("  in {}:", section.name().unwrap_or("<?>"));
        for (offset, rel) in relocs {
            let target_name = match rel.target() {
                object::RelocationTarget::Symbol(idx) => symbols
                    .iter()
                    .find(|s| s.index() == idx)
                    .and_then(|s| s.name().ok())
                    .unwrap_or("<?>")
                    .to_string(),
                other => format!("{:?}", other),
            };
            let flags = match rel.flags() {
                object::RelocationFlags::Elf { r_type } => {
                    format!("elf_type={}", aarch64_reloc_name(r_type))
                }
                other => format!("{:?}", other),
            };
            println!(
                "    {:#010x} -> {:<40} addend={:+#x} {}",
                offset,
                target_name,
                rel.addend(),
                flags
            );
        }
    }
    Ok(())
}

fn aarch64_reloc_name(t: u32) -> String {
    use object::elf::*;
    let name = match t {
        R_AARCH64_NONE => "R_AARCH64_NONE",
        R_AARCH64_ABS64 => "R_AARCH64_ABS64",
        R_AARCH64_ABS32 => "R_AARCH64_ABS32",
        R_AARCH64_ABS16 => "R_AARCH64_ABS16",
        R_AARCH64_PREL64 => "R_AARCH64_PREL64",
        R_AARCH64_PREL32 => "R_AARCH64_PREL32",
        R_AARCH64_CALL26 => "R_AARCH64_CALL26",
        R_AARCH64_JUMP26 => "R_AARCH64_JUMP26",
        R_AARCH64_ADR_PREL_PG_HI21 => "R_AARCH64_ADR_PREL_PG_HI21",
        R_AARCH64_ADD_ABS_LO12_NC => "R_AARCH64_ADD_ABS_LO12_NC",
        R_AARCH64_LDST8_ABS_LO12_NC => "R_AARCH64_LDST8_ABS_LO12_NC",
        R_AARCH64_LDST16_ABS_LO12_NC => "R_AARCH64_LDST16_ABS_LO12_NC",
        R_AARCH64_LDST32_ABS_LO12_NC => "R_AARCH64_LDST32_ABS_LO12_NC",
        R_AARCH64_LDST64_ABS_LO12_NC => "R_AARCH64_LDST64_ABS_LO12_NC",
        R_AARCH64_LDST128_ABS_LO12_NC => "R_AARCH64_LDST128_ABS_LO12_NC",
        R_AARCH64_ADR_GOT_PAGE => "R_AARCH64_ADR_GOT_PAGE",
        R_AARCH64_LD64_GOT_LO12_NC => "R_AARCH64_LD64_GOT_LO12_NC",
        _ => return format!("R_AARCH64_{t}"),
    };
    name.to_string()
}

fn open_binary<'a>(mmap: &'a memmap2::Mmap, path: &Path) -> Result<delink_core::Binary<'a>> {
    delink_core::Binary::load(&mmap[..])
        .with_context(|| format!("failed to load {}", path.display()))
}

fn mmap_file(path: &Path) -> Result<memmap2::Mmap> {
    let file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    Ok(unsafe { memmap2::Mmap::map(&file)? })
}

fn cmd_inspect(path: &Path) -> Result<()> {
    let mmap = mmap_file(path)?;
    let binary = open_binary(&mmap, path)?;
    let report = delink_core::inspect::inspect(&binary)?;
    print!("{}", delink_core::inspect::format_text(&report));
    Ok(())
}

fn cmd_emit(
    path: &Path,
    cu_needle: &str,
    output: &Path,
    comdat: bool,
    dwarf: bool,
    per_function_sections: bool,
) -> Result<()> {
    let mmap = mmap_file(path)?;
    let binary = open_binary(&mmap, path)?;
    let idx = delink_core::cu::CuIndex::build(&binary)?;
    let cu = delink_emit::find_cu(&idx.units, cu_needle)
        .ok_or_else(|| anyhow!("no CU matches suffix '{}'", cu_needle))?;

    tracing::info!(
        "emitting CU '{}' ({} functions, {} ranges)",
        cu.name,
        cu.functions.len(),
        cu.ranges.len()
    );

    let symbols = delink_core::symbols::GlobalSymbols::build(&binary, &idx)?;
    tracing::info!(
        "resolved {} functions across all CUs, {} PLT stubs",
        symbols.functions.len(),
        symbols.plt.len()
    );

    let stats = delink_emit::emit_cu(
        &binary,
        delink_emit::EmitOptions {
            cu,
            symbols: &symbols,
            comdat,
            dwarf,
            per_function_sections,
        },
        output,
    )?;
    println!(
        "wrote {}\n  .text: {} bytes ({} insns)\n  symbols: {} local, {} undef\n  relocs: {} emitted\n  calls: {} unresolved\n  adrp: {} seen, {} paired, {} unresolved\n  ranges coalesced: {}",
        output.display(),
        stats.text_bytes,
        stats.instructions,
        stats.local_symbols,
        stats.undef_symbols,
        stats.relocations,
        stats.unresolved_calls,
        stats.adrp_seen,
        stats.adrp_paired,
        stats.adrp_unresolved,
        stats.ranges_coalesced,
    );
    Ok(())
}

fn cmd_list_cus(path: &Path, contains: &str, limit: usize) -> Result<()> {
    let mmap = mmap_file(path)?;
    let binary = open_binary(&mmap, path)?;
    let idx = delink_core::cu::CuIndex::build(&binary)?;
    let mut rows: Vec<_> = idx
        .units
        .iter()
        .filter(|u| u.name.contains(contains))
        .map(|u| {
            let bytes: u64 = u.ranges.iter().map(|r| r.end - r.start).sum();
            (bytes, u.functions.len(), u.name.clone())
        })
        .collect();
    rows.sort_by_key(|(b, _, _)| *b);
    println!("{:>10} {:>6}  name", "bytes", "funcs");
    for (bytes, funcs, name) in rows.iter().take(limit) {
        println!("{:>10} {:>6}  {}", bytes, funcs, name);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PE + PDB subcommands
// ---------------------------------------------------------------------------

fn load_pe_context(exe_path: &Path, pdb_path: &Path) -> Result<delink_pe::PeContext> {
    let exe_data =
        std::fs::read(exe_path).with_context(|| format!("read {}", exe_path.display()))?;
    let pdb_data =
        std::fs::read(pdb_path).with_context(|| format!("read {}", pdb_path.display()))?;
    tracing::info!(
        "loaded PE ({} bytes) + PDB ({} bytes)",
        exe_data.len(),
        pdb_data.len()
    );
    delink_pe::load_pe_and_pdb(&exe_data, &pdb_data)
        .with_context(|| format!("load {} + {}", exe_path.display(), pdb_path.display()))
}

fn cmd_pe_inspect(exe_path: &Path, pdb_path: &Path) -> Result<()> {
    let pe = load_pe_context(exe_path, pdb_path)?;

    println!("PE sections:");
    println!("  {:<16} {:>16} {:>12}  flags", "name", "VA", "size");
    for s in &pe.sections {
        println!(
            "  {:<16} {:#016x} {:>12}  0x{:08x}",
            s.name, s.va, s.virtual_size, s.characteristics
        );
    }

    println!("\nBase relocations: {} entries", pe.base_relocations.len());
    let dir64 = pe
        .base_relocations
        .iter()
        .filter(|r| matches!(r.kind, delink_pe::BaseRelocKind::Dir64))
        .count();
    println!(
        "  DIR64: {}  other: {}",
        dir64,
        pe.base_relocations.len() - dir64
    );

    println!("\nImports: {} IAT entries", pe.imports.len());

    println!("\nPDB modules (CUs): {}", pe.cu_index.units.len());
    let total_funcs: usize = pe.cu_index.units.iter().map(|u| u.functions.len()).sum();
    println!("  total functions: {}", total_funcs);

    Ok(())
}

fn cmd_pe_list_cus(exe_path: &Path, pdb_path: &Path, contains: &str, limit: usize) -> Result<()> {
    let pe = load_pe_context(exe_path, pdb_path)?;

    let mut rows: Vec<_> = pe
        .cu_index
        .units
        .iter()
        .filter(|u| u.name.contains(contains))
        .map(|u| (u.text_size(), u.functions.len(), u.name.clone()))
        .collect();
    rows.sort_by_key(|(b, _, _)| *b);

    println!("{:>10} {:>6}  name", "text bytes", "funcs");
    for (bytes, funcs, name) in rows.iter().take(limit) {
        println!("{:>10} {:>6}  {}", bytes, funcs, name);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Mach-O subcommands
// ---------------------------------------------------------------------------

fn load_macho_context(path: &Path) -> Result<delink_macho::MachoContext> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    tracing::info!("loaded Mach-O ({} bytes)", data.len());
    delink_macho::load_macho(&data).with_context(|| format!("load {}", path.display()))
}

fn cmd_macho_inspect(path: &Path) -> Result<()> {
    let ctx = load_macho_context(path)?;

    println!("Mach-O  arch={:?}", ctx.arch);
    println!("\nSECTIONS");
    println!(
        "  {:<20} {:<12} {:>16} {:>12}  flags",
        "segment", "name", "addr", "size"
    );
    for s in &ctx.sections {
        println!(
            "  {:<20} {:<12} {:#016x} {:>12}  0x{:08x}",
            s.segment, s.name, s.addr, s.size, s.flags
        );
    }

    println!("\nDWARF compilation units: {}", ctx.cu_index.units.len());
    let total_funcs: usize = ctx.cu_index.units.iter().map(|u| u.functions.len()).sum();
    println!("  total functions: {}", total_funcs);

    Ok(())
}

fn cmd_macho_list_cus(path: &Path, contains: &str, limit: usize) -> Result<()> {
    let ctx = load_macho_context(path)?;

    let mut rows: Vec<_> = ctx
        .cu_index
        .units
        .iter()
        .filter(|u| u.name.contains(contains))
        .map(|u| (u.text_size(), u.functions.len(), u.name.clone()))
        .collect();
    rows.sort_by_key(|(b, _, _)| *b);

    println!("{:>10} {:>6}  name", "text bytes", "funcs");
    for (bytes, funcs, name) in rows.iter().take(limit) {
        println!("{:>10} {:>6}  {}", bytes, funcs, name);
    }
    Ok(())
}

fn cmd_macho_split(
    path: &Path,
    outdir: &Path,
    symtab_arg: Option<&Path>,
    emit_as_elf: bool,
) -> Result<()> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    tracing::info!("loaded Mach-O ({} bytes)", data.len());

    let ctx =
        delink_macho::load_macho(&data).with_context(|| format!("load {}", path.display()))?;

    let input_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let arch_str = format!("{:?}", ctx.arch);

    std::fs::create_dir_all(outdir).with_context(|| format!("create {}", outdir.display()))?;

    // ------------------------------------------------------------------
    // Choose split strategy:
    //   • --symtab provided  → always symtab-driven (user override)
    //   • DWARF / STABS      → use the CU index from debug info directly
    //   • Symtab fallback    → generate a flat per-symbol symtab.json
    // ------------------------------------------------------------------
    let use_debug_info = symtab_arg.is_none()
        && matches!(
            ctx.cu_index.source,
            delink_macho::DebugInfoSource::Dwarf | delink_macho::DebugInfoSource::Stabs
        );

    let outcomes: Vec<delink_macho::emit::CuOutcome>;
    let mut manifest = serde_json::Map::new();

    if use_debug_info {
        // DWARF / STABS path — split by the CU index built from debug info.
        tracing::info!(
            "splitting {} CUs (from {:?}) in parallel",
            ctx.cu_index
                .units
                .iter()
                .filter(|u| u.functions.iter().any(|f| f.size > 0))
                .count(),
            ctx.cu_index.source,
        );

        // Write a symtab.json derived from the CU index so the user can
        // inspect (and re-run with --symtab to customise) the grouping.
        let symtab_for_ref = delink_macho::symtab_json::generate_from_cu_index(&ctx.cu_index);
        let symtab_out = outdir.join("symtab.json");
        let symtab_json_str =
            serde_json::to_string_pretty(&symtab_for_ref).context("serialize symtab")?;
        std::fs::write(&symtab_out, &symtab_json_str)
            .with_context(|| format!("write {}", symtab_out.display()))?;
        tracing::info!("symtab  → {}", symtab_out.display());

        outcomes = delink_macho::emit::split_all_macho(&ctx, outdir, emit_as_elf)?;

        // Build manifest from cu_index (no SymtabInfo available here).
        for o in &outcomes {
            let file_name = o
                .file
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();

            let functions_json: Vec<_> = ctx
                .cu_index
                .units
                .iter()
                .find(|u| u.id == o.cu_id)
                .map(|cu| {
                    let mut fns: Vec<_> = cu.functions.iter().filter(|f| f.size > 0).collect();
                    fns.sort_by_key(|f| f.addr);
                    fns.iter()
                        .map(|f| {
                            serde_json::json!({
                                "name": f.symbol_name(),
                                "addr": f.addr,
                                "size": f.size,
                                "external": f.external,
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();

            let emit_json = match &o.result {
                Ok(s) => serde_json::json!({
                    "text_bytes": s.text_bytes,
                    "instructions": s.instructions,
                    "local_symbols": s.local_symbols,
                    "undef_symbols": s.undef_symbols,
                    "relocations": s.relocations,
                    "unresolved_calls": s.unresolved_calls,
                }),
                Err(_) => serde_json::Value::Null,
            };
            let error_json = match &o.result {
                Ok(_) => serde_json::Value::Null,
                Err(e) => serde_json::Value::String(e.clone()),
            };

            manifest.insert(
                file_name,
                serde_json::json!({
                    "input_path": input_path.to_string_lossy(),
                    "output_path": o.file.canonicalize().unwrap_or_else(|_| o.file.clone()).to_string_lossy(),
                    "arch": arch_str,
                    "functions": functions_json,
                    "emit": emit_json,
                    "error": error_json,
                }),
            );
        }
    } else {
        // Symtab-driven path (no debug info, or --symtab override).
        let symtab: delink_macho::symtab_json::SymtabJson = if let Some(sp) = symtab_arg {
            let raw = std::fs::read_to_string(sp)
                .with_context(|| format!("read symtab {}", sp.display()))?;
            serde_json::from_str(&raw).with_context(|| format!("parse symtab {}", sp.display()))?
        } else {
            delink_macho::symtab_json::generate(&data).context("generate symtab")?
        };

        let n_syms: usize = symtab.values().map(|v| v.len()).sum();
        tracing::info!("symtab: {} symbols → {} output files", n_syms, symtab.len());

        let symtab_out = outdir.join("symtab.json");
        let symtab_json_str = serde_json::to_string_pretty(&symtab).context("serialize symtab")?;
        std::fs::write(&symtab_out, &symtab_json_str)
            .with_context(|| format!("write {}", symtab_out.display()))?;
        tracing::info!("symtab  → {}", symtab_out.display());

        let lookup =
            delink_macho::symtab_json::build_lookup(&data).context("build symtab lookup")?;

        outcomes =
            delink_macho::emit::split_by_symtab(&ctx, &symtab, &lookup, outdir, emit_as_elf)?;

        // Build manifest using rich SymtabInfo.
        for o in &outcomes {
            let file_name = o
                .file
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();

            let empty: Vec<String> = vec![];
            let names = symtab.get(o.cu_name.as_str()).unwrap_or(&empty);
            let mut resolved: Vec<_> = names
                .iter()
                .filter_map(|name| lookup.get(name.as_str()).map(|info| (name, info)))
                .collect();
            resolved.sort_by_key(|(_, info)| info.addr);

            let functions_json: Vec<_> = resolved
                .iter()
                .map(|(name, info)| {
                    serde_json::json!({
                        "name": name,
                        "addr": info.addr,
                        "size": info.size,
                        "n_type": info.n_type,
                        "n_sect": info.n_sect,
                        "n_desc": info.n_desc,
                        "external": info.external,
                        "private_external": info.private_external,
                    })
                })
                .collect();

            let emit_json = match &o.result {
                Ok(s) => serde_json::json!({
                    "text_bytes": s.text_bytes,
                    "instructions": s.instructions,
                    "local_symbols": s.local_symbols,
                    "undef_symbols": s.undef_symbols,
                    "relocations": s.relocations,
                    "unresolved_calls": s.unresolved_calls,
                }),
                Err(_) => serde_json::Value::Null,
            };
            let error_json = match &o.result {
                Ok(_) => serde_json::Value::Null,
                Err(e) => serde_json::Value::String(e.clone()),
            };

            manifest.insert(
                file_name,
                serde_json::json!({
                    "input_path": input_path.to_string_lossy(),
                    "output_path": o.file.canonicalize().unwrap_or_else(|_| o.file.clone()).to_string_lossy(),
                    "arch": arch_str,
                    "functions": functions_json,
                    "emit": emit_json,
                    "error": error_json,
                }),
            );
        }
    }

    // ------------------------------------------------------------------
    // Shared data
    // ------------------------------------------------------------------
    let shared = outdir.join("__shared_data.o");
    tracing::info!("emitting shared data → {}", shared.display());
    let shared_stats = if emit_as_elf {
        delink_macho::emit::emit_elf_shared(&ctx, &shared)?
    } else {
        delink_macho::emit::emit_macho_shared(&ctx, &shared)?
    };

    // Shared data manifest entry.
    let shared_vars: Vec<_> = ctx
        .symbols
        .variables
        .iter()
        .map(|(addr, v)| {
            serde_json::json!({
                "name": v.symbol_name(),
                "demangled": v.name,
                "addr": addr,
                "external": v.external,
            })
        })
        .collect();
    let shared_name = shared
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    manifest.insert(
        shared_name,
        serde_json::json!({
            "input_path": input_path.to_string_lossy(),
            "output_path": shared.canonicalize().unwrap_or_else(|_| shared.clone()).to_string_lossy(),
            "arch": arch_str,
            "functions": [],
            "variables": shared_vars,
            "emit": {
                "data_bytes": shared_stats.data_bytes,
                "const_bytes": shared_stats.const_bytes,
                "bss_bytes": shared_stats.bss_bytes,
            },
            "error": null,
        }),
    );

    let manifest_path = outdir.join("manifest.json");
    let json_str = serde_json::to_string_pretty(&serde_json::Value::Object(manifest))
        .context("serialize manifest")?;
    std::fs::write(&manifest_path, json_str)
        .with_context(|| format!("write {}", manifest_path.display()))?;
    tracing::info!("manifest → {}", manifest_path.display());

    // ------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------
    let mut total = delink_macho::EmitStats::default();
    let mut failures = 0usize;
    for o in &outcomes {
        match &o.result {
            Ok(s) => {
                total.text_bytes += s.text_bytes;
                total.local_symbols += s.local_symbols;
                total.undef_symbols += s.undef_symbols;
                total.relocations += s.relocations;
                total.unresolved_calls += s.unresolved_calls;
                total.instructions += s.instructions;
            }
            Err(e) => {
                failures += 1;
                tracing::warn!(cu = %o.cu_name, error = %e, "emit failed");
            }
        }
    }

    println!(
        "macho-split complete: {} files ({} failed)\n  {} bytes .text, {} instructions\n  {} local + {} undef symbols\n  {} relocs ({} unresolved calls)\n  shared: data={} const={} bss={}",
        outcomes.len().saturating_sub(failures),
        failures,
        total.text_bytes,
        total.instructions,
        total.local_symbols,
        total.undef_symbols,
        total.relocations,
        total.unresolved_calls,
        shared_stats.data_bytes,
        shared_stats.const_bytes,
        shared_stats.bss_bytes,
    );
    Ok(())
}

fn cmd_pe_split(
    exe_path: &Path,
    pdb_path: Option<&Path>,
    symbols_path: Option<&Path>,
    splits_path: Option<&Path>,
    analyze: bool,
    outdir: &Path,
    replace_rep_ret: bool,
) -> Result<()> {
    if let Some(pdb_path) = pdb_path {
        let pe = load_pe_context(exe_path, pdb_path)?;
        return cmd_pe_split_pdb(&pe, outdir, replace_rep_ret);
    }

    let exe_data =
        std::fs::read(exe_path).with_context(|| format!("read {}", exe_path.display()))?;
    let image = delink_pe::load_pe_image(&exe_data)
        .with_context(|| format!("load {}", exe_path.display()))?;

    // Config-driven split: build symbols/splits purely from the editable
    // CSV/splits manifests. No x86 analysis runs, so no invented symbols such
    // as `data_0041933F` leak into symbols.json / the emitted objects.
    let config_symbols = symbols_path.filter(|path| path.is_file()).map(|p| p.to_path_buf());
    let config_splits = splits_path.filter(|path| path.is_file()).map(|p| p.to_path_buf());
    if !analyze {
        if let Some(config) = config_symbols {
            let (pe, manifest) = build_config_context(&image, &config, config_splits.as_deref())?;
            std::fs::create_dir_all(outdir)
                .with_context(|| format!("create {}", outdir.display()))?;
            write_analysis_manifests(outdir, &manifest, &pe.cu_index)?;
            tracing::info!(
                "config mode: emitting {} units from manifests",
                pe.cu_index.units.len()
            );
            let outcomes = delink_pe::emit::split_all_pe(&pe, outdir, replace_rep_ret)?;
            return finish_pe_split(&pe, outdir, outcomes, false);
        }
    }

    let (mut pe, mut manifest) = delink_pe::analysis::analyze(&image)?;
    if !analyze {
        if let Some(symbols_path) = symbols_path.filter(|path| path.is_file()) {
            apply_symbol_overrides(&mut pe, &mut manifest, symbols_path)?;
        }
        if let Some(splits_path) = splits_path.filter(|path| path.is_file()) {
            apply_split_overrides(&mut pe, splits_path)?;
        }
    }
    std::fs::create_dir_all(outdir).with_context(|| format!("create {}", outdir.display()))?;
    write_analysis_manifests(outdir, &manifest, &pe.cu_index)?;
    tracing::info!(
        "analysis mode: emitting {} inferred functions",
        pe.cu_index.units.len()
    );
    let outcomes = delink_pe::emit::split_all_pe(&pe, outdir, replace_rep_ret)?;
    finish_pe_split(&pe, outdir, outcomes, true)
}

fn finish_pe_split(
    pe: &delink_pe::PeContext,
    outdir: &Path,
    outcomes: Vec<delink_pe::emit::CuOutcome>,
    analysis: bool,
) -> Result<()> {
    let shared = outdir.join("__shared_data.obj");
    let shared_stats = delink_pe::emit::emit_pe_shared(pe, &shared)?;
    let failures = outcomes.iter().filter(|o| o.result.is_err()).count();
    let label = if analysis { "analysis" } else { "config" };
    println!(
        "pe-split {label} complete: {} functions ({} failed), shared: rdata={} data={} bss={}",
        outcomes.len().saturating_sub(failures),
        failures,
        shared_stats.rdata_bytes,
        shared_stats.data_bytes,
        shared_stats.bss_bytes
    );
    Ok(())
}

/// Build a `PeContext` + manifest purely from the config CSV/splits manifests.
/// No x86 analysis runs: the symbols, sizes and CU grouping come entirely from
/// the editable manifests, so invented names never leak into symbols.json.
fn build_config_context(
    image: &delink_pe::PeImage,
    symbols_path: &Path,
    splits_path: Option<&Path>,
) -> Result<(delink_pe::PeContext, delink_pe::AnalysisOutput)> {
    let text = std::fs::read_to_string(symbols_path)
        .with_context(|| format!("read symbols config {}", symbols_path.display()))?;

    let mut functions: std::collections::BTreeMap<u64, delink_pe::PeFunction> =
        std::collections::BTreeMap::new();
    let mut variables: std::collections::BTreeMap<u64, delink_pe::PeVariable> =
        std::collections::BTreeMap::new();
    let mut imports = image.imports.clone();
    let mut symbols_manifest = Vec::new();

    for line in text.lines().skip(1) {
        let fields: Vec<_> = line.splitn(4, ',').map(str::trim).collect();
        if fields.len() != 4 {
            continue;
        }
        let Ok(address) = u64::from_str_radix(fields[0].trim_start_matches("0x"), 16) else {
            continue;
        };
        let size = u32::from_str_radix(fields[1].trim_start_matches("0x"), 16).unwrap_or(0);
        let name = fields[3].to_string();
        let (section, symbol_type) = match fields[2] {
            "func" => (".text", "function"),
            "imp" => (".idata", "object"),
            "data" => (".data", "object"),
            _ => continue,
        };
        if let Some(import) = imports.get_mut(&address) {
            *import = name.clone();
        }
        match fields[2] {
            "func" => {
                functions.insert(
                    address,
                    delink_pe::PeFunction {
                        name: name.clone(),
                        va: address,
                        size,
                        is_public: true,
                        module_id: 0,
                        aliases: Vec::new(),
                    },
                );
            }
            "data" => {
                variables.insert(
                    address,
                    delink_pe::PeVariable {
                        name: name.clone(),
                        va: address,
                        is_public: true,
                        size,
                    },
                );
            }
            _ => {}
        }
        symbols_manifest.push(delink_pe::AnalysisSymbol {
            name,
            section: section.to_string(),
            address,
            size: size as u64,
            symbol_type: symbol_type.to_string(),
            scope: "global".to_string(),
            data: None,
        });
    }

    let symbols = delink_pe::PeGlobalSymbols::build(
        functions.clone(),
        variables,
        std::collections::BTreeMap::new(),
        std::collections::BTreeMap::new(),
        &imports,
        &image.sections,
        image.image_base,
    );

    let mut pe = delink_pe::PeContext {
        arch: image.arch,
        image_base: image.image_base,
        sections: image.sections.clone(),
        cu_index: delink_pe::PeCuIndex { units: Vec::new() },
        symbols,
        base_relocations: image.base_relocations.clone(),
        imports,
        inlined_functions: Vec::new(),
    };

    if let Some(splits_path) = splits_path {
        apply_split_overrides(&mut pe, splits_path)?;
    }

    let mut splits = Vec::new();
    if let Some(splits_path) = splits_path {
        for (object, spans) in parse_split_groups(splits_path)? {
            splits.push(delink_pe::AnalysisSplit {
                object,
                spans: spans
                    .into_iter()
                    .map(|(section, start, end, _)| delink_pe::AnalysisSpan {
                        section,
                        start,
                        end,
                    })
                    .collect(),
            });
        }
    }

    Ok((
        pe,
        delink_pe::AnalysisOutput {
            symbols: symbols_manifest,
            splits,
        },
    ))
}

fn apply_symbol_overrides(
    pe: &mut delink_pe::PeContext,
    manifest: &mut delink_pe::AnalysisOutput,
    path: &Path,
) -> Result<()> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read symbols override {}", path.display()))?;
    let mut overrides = std::collections::HashMap::new();
    for line in text.lines().skip(1) {
        let fields: Vec<_> = line.splitn(4, ',').map(str::trim).collect();
        if fields.len() != 4 {
            continue;
        }
        let Ok(address) = u64::from_str_radix(fields[0].trim_start_matches("0x"), 16) else {
            continue;
        };
        let size = u32::from_str_radix(fields[1].trim_start_matches("0x"), 16).unwrap_or(0);
        let symbol_type = fields[2].to_string();
        if !matches!(symbol_type.as_str(), "func" | "data" | "imp") {
            continue;
        }
        let section = match symbol_type.as_str() {
            "func" => ".text",
            "imp" => ".idata",
            _ => ".data",
        };
        overrides.insert(
            address,
            (
                fields[3].to_string(),
                section.to_string(),
                size,
                symbol_type,
            ),
        );
    }
    for (address, (name, section, size, symbol_type)) in overrides {
        let emitted_name = name.clone();
        if let Some(import) = pe.imports.get_mut(&address) {
            *import = emitted_name.clone();
        }
        if let Some(import) = pe.symbols.imports.get_mut(&address) {
            *import = emitted_name.clone();
        }
        if let Some(function) = pe.symbols.functions.get_mut(&address) {
            function.name = emitted_name.clone();
            if size != 0 {
                function.size = size;
            }
        }
        if let Some(variable) = pe.symbols.variables.get_mut(&address) {
            variable.name = name.clone();
            if size != 0 {
                variable.size = size;
            }
        }
        for unit in &mut pe.cu_index.units {
            for function in &mut unit.functions {
                if function.va == address {
                    function.name = emitted_name.clone();
                    if size != 0 {
                        function.size = size;
                    }
                }
            }
        }
        if symbol_type != "function" && !pe.symbols.variables.contains_key(&address) {
            pe.symbols.variables.insert(
                address,
                delink_pe::PeVariable {
                    name: name.clone(),
                    va: address,
                    is_public: true,
                    size,
                },
            );
        }
        if let Some(symbol) = manifest
            .symbols
            .iter_mut()
            .find(|symbol| symbol.address == address)
        {
            symbol.name = name;
            if size != 0 {
                symbol.size = size as u64;
            }
        } else if symbol_type == "func" {
            let function = delink_pe::PeFunction {
                name: emitted_name.clone(),
                va: address,
                size,
                is_public: true,
                module_id: 0,
                aliases: Vec::new(),
            };
            pe.symbols.functions.insert(address, function.clone());
            let id = pe.cu_index.units.len();
            pe.cu_index.units.push(delink_pe::PeCompilationUnit {
                id,
                name: name.clone(),
                obj_file: format!("{:04}_{name}.obj", id),
                functions: vec![function],
                contributions: Vec::new(),
            });
            manifest.symbols.push(delink_pe::AnalysisSymbol {
                name,
                section,
                address,
                size: size as u64,
                symbol_type: "function".to_string(),
                scope: "global".to_string(),
                data: None,
            });
        } else {
            pe.symbols.variables.insert(
                address,
                delink_pe::PeVariable {
                    name: name.clone(),
                    va: address,
                    is_public: true,
                    size,
                },
            );
            manifest.symbols.push(delink_pe::AnalysisSymbol {
                name,
                section,
                address,
                size: size as u64,
                symbol_type: "object".to_string(),
                scope: "global".to_string(),
                data: None,
            });
        }
    }
    Ok(())
}

type SplitGroup = (String, Vec<(String, u64, u64, Option<String>)>);

fn parse_split_groups(path: &Path) -> Result<Vec<SplitGroup>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("read splits {}", path.display()))?;
    let mut groups: Vec<SplitGroup> = Vec::new();
    let mut current: Option<usize> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed == "Sections:" {
            continue;
        }
        if !line.starts_with(' ') && trimmed.ends_with(':') {
            groups.push((trimmed.trim_end_matches(':').to_string(), Vec::new()));
            current = Some(groups.len() - 1);
            continue;
        }
        let Some(index) = current else { continue };
        let mut values = trimmed.split_whitespace();
        let Some(section) = values.next() else {
            continue;
        };
        if !section.starts_with('.') {
            continue;
        }
        let Some(start) = values.next().and_then(|value| value.strip_prefix("start:")) else {
            continue;
        };
        let Some(end) = values.next().and_then(|value| value.strip_prefix("end:")) else {
            continue;
        };
        let Ok(start) = u64::from_str_radix(start.trim_start_matches("0x"), 16) else {
            continue;
        };
        let Ok(end) = u64::from_str_radix(end.trim_start_matches("0x"), 16) else {
            continue;
        };
        let rename = values.find_map(|value| value.strip_prefix("rename:").map(str::to_string));
        groups[index].1.push((section.to_string(), start, end, rename));
    }
    Ok(groups)
}

fn apply_split_overrides(pe: &mut delink_pe::PeContext, path: &Path) -> Result<()> {
    let groups = parse_split_groups(path)?;
    if groups.is_empty() {
        pe.cu_index.units.clear();
        return Ok(());
    }

    let mut grouped: Vec<(String, Vec<delink_pe::PeFunction>)> = groups
        .iter()
        .map(|(name, _)| (name.clone(), Vec::new()))
        .collect();
    for function in pe.symbols.functions.values() {
        let group = groups.iter().position(|(_, spans)| {
            spans.iter().any(|(section, start, end, _)| {
                section == ".text" && function.va >= *start && function.va < *end
            })
        });
        if let Some(group) = group {
            grouped[group].1.push(function.clone());
        }
    }
    let units: Vec<delink_pe::PeCompilationUnit> = grouped
        .into_iter()
        .enumerate()
        .filter(|(_, (name, functions))| {
            !functions.is_empty()
                || groups
                    .iter()
                    .find(|(group_name, _)| group_name == name)
                    .map(|(_, spans)| spans.iter().any(|(section, _, _, _)| section != ".text"))
                    .unwrap_or(false)
        })
        .map(|(id, (name, functions))| {
            let obj_file = if matches!(
                Path::new(&name).extension().and_then(|ext| ext.to_str()),
                Some("c" | "cc" | "cpp" | "cxx")
            ) {
                Path::new(&name)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .replace(".cxx", ".obj")
                    .replace(".cpp", ".obj")
                    .replace(".cc", ".obj")
                    .replace(".c", ".obj")
            } else {
                name.clone()
            };
            let contributions = groups
                .iter()
                .find(|(group_name, _)| group_name == &name)
                .into_iter()
                .flat_map(|(_, spans)| spans.iter())
                .filter(|(section, _, _, _)| section != ".text")
                .map(|(section, start, end, rename)| delink_pe::PeContrib {
                    va: *start,
                    size: (*end - *start) as u32,
                    section_name: rename.clone().unwrap_or_else(|| section.clone()),
                    characteristics: pe
                        .sections
                        .iter()
                        .find(|candidate| candidate.name == rename.as_deref().unwrap_or(section))
                        .map(|candidate| candidate.characteristics)
                        .unwrap_or_else(|| match rename.as_deref().unwrap_or(section) {
                            ".bss" => 0x8000_0000 | 0x0000_0080,
                            ".data" => 0x8000_0000,
                            _ => 0,
                        }),
                })
                .collect();
            delink_pe::PeCompilationUnit {
                id,
                name: obj_file.trim_end_matches(".obj").to_string(),
                obj_file,
                functions,
                contributions,
            }
        })
        .collect();
    pe.cu_index = delink_pe::PeCuIndex { units };
    Ok(())
}

fn cmd_pe_split_pdb(pe: &delink_pe::PeContext, outdir: &Path, replace_rep_ret: bool) -> Result<()> {
    tracing::info!(
        "splitting {} CUs (modules with functions) in parallel",
        pe.cu_index
            .units
            .iter()
            .filter(|u| u.functions.iter().any(|f| f.size > 0))
            .count()
    );

    let outcomes = delink_pe::emit::split_all_pe(&pe, outdir, replace_rep_ret)?;

    let shared = outdir.join("__shared_data.obj");
    tracing::info!("emitting shared data → {}", shared.display());
    let shared_stats = delink_pe::emit::emit_pe_shared(&pe, &shared)?;

    let mut total = delink_pe::emit::EmitStats::default();
    let mut failures = 0usize;
    for o in &outcomes {
        match &o.result {
            Ok(s) => {
                total.text_bytes += s.text_bytes;
                total.local_symbols += s.local_symbols;
                total.undef_symbols += s.undef_symbols;
                total.relocations += s.relocations;
                total.unresolved_calls += s.unresolved_calls;
                total.instructions += s.instructions;
            }
            Err(e) => {
                failures += 1;
                tracing::warn!(cu = %o.cu_name, error = %e, "emit failed");
            }
        }
    }

    println!(
        "pe-split complete: {} modules ({} failed)\n  {} bytes .text, {} instructions\n  {} local + {} undef symbols\n  {} relocs ({} unresolved calls)\n  shared: rdata={} data={} bss={} ({} ADDR64 relocs)",
        outcomes.len().saturating_sub(failures),
        failures,
        total.text_bytes,
        total.instructions,
        total.local_symbols,
        total.undef_symbols,
        total.relocations,
        total.unresolved_calls,
        shared_stats.rdata_bytes,
        shared_stats.data_bytes,
        shared_stats.bss_bytes,
        shared_stats.addr64_relocs,
    );
    Ok(())
}

fn write_analysis_manifests(
    outdir: &Path,
    manifest: &delink_pe::AnalysisOutput,
    cu_index: &delink_pe::PeCuIndex,
) -> Result<()> {
    let mut symbols = String::from("Address,Size,Type,Symbol\n");
    for s in &manifest.symbols {
        let symbol_type = if s.section == ".idata" {
            "imp"
        } else if s.symbol_type == "function" {
            "func"
        } else {
            "data"
        };
        symbols.push_str(&format!(
            "0x{:08X},0x{:X},{},{}\n",
            s.address, s.size, symbol_type, s.name
        ));
    }
    std::fs::write(outdir.join("symbols.csv"), symbols)?;
    let mut splits = String::from(
        "Sections:\n    .text      type:code  align:16\n    .rdata     type:rodata align:16\n    .data      type:data align:16\n    .bss       type:bss align:16\n\n",
    );
    for unit in &cu_index.units {
        splits.push_str(&format!("{}:\n", unit.obj_file));
        for function in &unit.functions {
            splits.push_str(&format!(
                "    .text start:0x{:08X} end:0x{:08X}\n",
                function.va,
                function.va + u64::from(function.size),
            ));
        }
    }
    std::fs::write(outdir.join("splits.txt"), splits)?;
    std::fs::write(
        outdir.join("symbols.json"),
        serde_json::to_vec_pretty(&manifest.symbols)?,
    )?;
    std::fs::write(
        outdir.join("splits.json"),
        serde_json::to_vec_pretty(&manifest.splits)?,
    )?;
    std::fs::write(
        outdir.join("manifest.json"),
        serde_json::to_vec_pretty(manifest)?,
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// IDA import subcommands
// ---------------------------------------------------------------------------

fn cmd_ida_inspect(json: &Path) -> Result<()> {
    let model = delink_ida::load(json)?;

    println!(
        "IDA export  arch={:?} ({}) {}-bit  filetype={}",
        model.arch, model.procname, model.bits, model.filetype
    );
    println!("input: {}", model.input_file);
    println!("\nSEGMENTS");
    println!(
        "  {:<14} {:<6} {:>16} {:>10}  perms",
        "name", "class", "addr", "size"
    );
    for s in &model.sections {
        let perms = format!(
            "{}{}{}",
            if s.read { "r" } else { "-" },
            if s.write { "w" } else { "-" },
            if s.exec { "x" } else { "-" },
        );
        println!(
            "  {:<14} {:<6?} {:#016x} {:>10}  {}",
            s.name,
            s.class,
            s.start,
            s.size(),
            perms
        );
    }
    let text: u64 = model.functions.iter().map(|f| f.size()).sum();
    println!(
        "\nfunctions: {}  ({} bytes)\nnames: {}\nrelocations (fixups): {}",
        model.functions.len(),
        text,
        model.names.len(),
        model.relocations.len(),
    );
    Ok(())
}

fn cmd_ida_split(
    json: &Path,
    binary: &Path,
    outdir: &Path,
    idapro_arg: Option<&Path>,
    elf: bool,
    coff: bool,
) -> Result<()> {
    use delink_ida::emit::OutputFormat;

    let model = delink_ida::load(json)?;
    let pe = delink_ida::load_binary(binary)?;
    let relocs = delink_ida::combined_relocations(&model, &pe);
    let symbols = delink_ida::IdaSymbols::build(&model, &relocs);
    tracing::info!(
        "ida-split: {} relocations ({} IDA fixups + {} PE .reloc, combined)",
        relocs.len(),
        model.relocations.len(),
        pe.base_relocations.len(),
    );

    let format = if elf {
        OutputFormat::Elf
    } else if coff {
        OutputFormat::Coff
    } else {
        OutputFormat::default_for_filetype(&model.filetype)
    };
    tracing::info!(
        "ida-split: arch={:?} format={:?} ({} functions)",
        model.arch,
        format,
        model.functions.len()
    );

    std::fs::create_dir_all(outdir).with_context(|| format!("create {}", outdir.display()))?;

    // Grouping: explicit --idapro overrides the generated default.
    let groups: delink_ida::idapro_json::IdaproJson = if let Some(p) = idapro_arg {
        let raw =
            std::fs::read_to_string(p).with_context(|| format!("read idapro {}", p.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parse idapro {}", p.display()))?
    } else {
        delink_ida::idapro_json::generate(&model, format.ext())
    };

    let idapro_out = outdir.join("idapro.json");
    std::fs::write(
        &idapro_out,
        serde_json::to_string_pretty(&groups).context("serialize idapro")?,
    )
    .with_context(|| format!("write {}", idapro_out.display()))?;
    tracing::info!("idapro → {}", idapro_out.display());

    let outcomes =
        delink_ida::emit::split_by_groups(&model, &pe, &symbols, &groups, outdir, format)?;

    let shared_ext = if matches!(format, OutputFormat::Elf) {
        "o"
    } else {
        "obj"
    };
    let shared = outdir.join(format!("__shared_data.{shared_ext}"));
    tracing::info!("emitting shared data → {}", shared.display());
    let shared_stats = delink_ida::emit::emit_shared(&model, &pe, &symbols, &shared, format)?;

    // Summary.
    let mut total = delink_ida::emit::EmitStats::default();
    let mut failures = 0usize;
    for o in &outcomes {
        match &o.result {
            Ok(s) => {
                total.text_bytes += s.text_bytes;
                total.instructions += s.instructions;
                total.local_symbols += s.local_symbols;
                total.undef_symbols += s.undef_symbols;
                total.relocations += s.relocations;
                total.unresolved_calls += s.unresolved_calls;
                total.unresolved_rip += s.unresolved_rip;
            }
            Err(e) => {
                failures += 1;
                tracing::warn!(obj = %o.cu_name, error = %e, "emit failed");
            }
        }
    }

    println!(
        "ida-split complete: {} objects ({} failed)\n  {} bytes .text, {} instructions\n  {} local + {} undef symbols\n  {} relocs ({} unresolved calls, {} unresolved rip refs)\n  shared: data={} const={} bss={} ({} relocs)",
        outcomes.len().saturating_sub(failures),
        failures,
        total.text_bytes,
        total.instructions,
        total.local_symbols,
        total.undef_symbols,
        total.relocations,
        total.unresolved_calls,
        total.unresolved_rip,
        shared_stats.data_bytes,
        shared_stats.const_bytes,
        shared_stats.bss_bytes,
        shared_stats.relocations,
    );
    Ok(())
}
