//! Lightweight no-PDB analysis for 32-bit PE images.

use anyhow::{anyhow, Result};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    PeArch, PeCompilationUnit, PeContext, PeFunction, PeGlobalSymbols, PeImage, PeVariable,
};

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisSymbol {
    pub name: String,
    pub section: String,
    pub address: u64,
    pub size: u64,
    #[serde(rename = "type")]
    pub symbol_type: String,
    pub scope: String,
    pub data: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisSpan {
    pub section: String,
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisSplit {
    pub object: String,
    pub spans: Vec<AnalysisSpan>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisOutput {
    pub symbols: Vec<AnalysisSymbol>,
    pub splits: Vec<AnalysisSplit>,
}

/// Discover conservative function candidates and printable data strings.
/// The result intentionally favors under-claiming bytes over inventing large
/// overlapping functions; the emitted text files are the manual correction point.
pub fn analyze(image: &PeImage) -> Result<(PeContext, AnalysisOutput)> {
    if image.arch != PeArch::X86 {
        return Err(anyhow!(
            "analysis mode currently supports only 32-bit x86 PE"
        ));
    }
    let text = image
        .sections
        .iter()
        .find(|s| s.name == ".text")
        .ok_or_else(|| anyhow!("PE has no .text section"))?;
    let text_strings = printable_runs(text);
    let jump_tables = infer_text_jump_tables(image, text);
    let mut text_data: Vec<(u64, u64)> = text_strings
        .iter()
        .map(|(_, start, size, _)| (*start, *start + *size))
        .collect();
    text_data.extend(
        jump_tables
            .iter()
            .map(|(start, size)| (*start, *start + *size)),
    );
    let text_data = merge_ranges(text_data);
    let mut starts = BTreeSet::new();
    if text.contains_va(image.entry_point) {
        starts.insert(image.entry_point);
    }
    // The first .text byte is a useful fallback for stripped images, but is
    // deliberately not treated as an additional root when the PE has an entry.
    if starts.is_empty() {
        starts.insert(text.va);
    }
    starts.extend(scan_entrypoints(text, &text_data));
    starts.extend(
        image
            .exported_entrypoints
            .iter()
            .map(|rva| image.image_base + *rva)
            .filter(|va| text.contains_va(*va)),
    );
    // Address-taken procedures (callback tables, vtables, atexit arrays) are
    // often never reached by a direct CALL. On x86 the PE HIGHLOW relocation
    // records identify their absolute pointer slots.
    for reloc in &image.base_relocations {
        if !matches!(reloc.kind, crate::BaseRelocKind::HighLow) {
            continue;
        }
        let Some(bytes) = image
            .sections
            .iter()
            .find_map(|s| s.data_at_va(reloc.va, 4))
        else {
            continue;
        };
        let target = u32::from_le_bytes(bytes.try_into().unwrap()) as u64;
        let target = if text.contains_va(target) && !in_ranges(target, &text_data) {
            target
        } else {
            continue;
        };
        let offset = (target - text.va) as usize;
        if likely_root(text.data.get(offset..).unwrap_or_default()) {
            starts.insert(target);
        }
    }
    // Padding boundaries are fallback roots for stripped functions which are
    // not reachable from the image entry point or a direct call.
    for (i, &byte) in text.data.iter().enumerate().skip(1) {
        if byte == 0xcc && text.data.get(i - 1) != Some(&0xcc) {
            let mut end = i;
            while text.data.get(end) == Some(&0xcc) {
                end += 1;
            }
            if end < text.data.len()
                && !in_ranges(text.va + end as u64, &text_data)
                && likely_prologue(&text.data[end..])
            {
                starts.insert(text.va + end as u64);
            }
        }
    }

    // Walk each root's reachable basic blocks. Calls add new function roots;
    // jumps only add blocks to the current function and never create symbols.
    let mut pending: Vec<u64> = starts.iter().copied().collect();
    let mut discovered = BTreeMap::new();
    while let Some(start) = pending.pop() {
        if discovered.contains_key(&start) || !text.contains_va(start) {
            continue;
        }
        let (end, calls) = discover_cfg(text, start, &starts, &text_data);
        if end <= start {
            continue;
        }
        discovered.insert(start, end);
        for target in calls {
            if !discovered.contains_key(&target) {
                starts.insert(target);
                pending.push(target);
            }
        }
    }

    // A candidate discovered inside an already accepted function is a block
    // or a false root, never a second function. Keep the earlier outer range.
    let mut non_overlapping = BTreeMap::new();
    for (&start, &end) in &discovered {
        if non_overlapping
            .range(..start)
            .next_back()
            .is_some_and(|(_, outer_end)| *outer_end > start)
        {
            continue;
        }
        non_overlapping.insert(start, end);
    }
    let discovered = non_overlapping;

    let starts: Vec<u64> = discovered.keys().copied().collect();
    let mut functions = BTreeMap::new();
    let mut symbols = Vec::new();
    let mut splits = Vec::new();
    for (index, &start) in starts.iter().enumerate() {
        let section_offset = (start - text.va) as usize;
        if section_offset >= text.data.len() {
            continue;
        }
        let end = discovered[&start];
        if end <= start {
            continue;
        }
        let name = format!("fn_{start:08X}");
        let size = end - start;
        functions.insert(
            start,
            PeFunction {
                name: name.clone(),
                va: start,
                size: size as u32,
                is_public: true,
                module_id: index,
                aliases: Vec::new(),
            },
        );
        symbols.push(AnalysisSymbol {
            name: name.clone(),
            section: ".text".into(),
            address: start,
            size,
            symbol_type: "function".into(),
            scope: "global".into(),
            data: None,
        });
        splits.push(AnalysisSplit {
            object: format!("{index:04}_{name}.obj"),
            spans: vec![AnalysisSpan {
                section: ".text".into(),
                start,
                end,
            }],
        });
    }
    let mut text_data_spans = Vec::new();
    for (name, start, size, kind) in text_strings {
        symbols.push(AnalysisSymbol {
            name,
            section: ".text".into(),
            address: start,
            size,
            symbol_type: "object".into(),
            scope: "global".into(),
            data: Some(kind),
        });
        text_data_spans.push(AnalysisSpan {
            section: ".text".into(),
            start,
            end: start + size,
        });
    }
    for (start, size) in jump_tables {
        symbols.push(AnalysisSymbol {
            name: format!("jumptable_{start:08X}"),
            section: ".text".into(),
            address: start,
            size,
            symbol_type: "object".into(),
            scope: "local".into(),
            data: Some("4byte".into()),
        });
        text_data_spans.push(AnalysisSpan {
            section: ".text".into(),
            start,
            end: start + size,
        });
    }
    if !text_data_spans.is_empty() {
        splits.push(AnalysisSplit {
            object: "__text_data.obj".into(),
            spans: text_data_spans,
        });
    }

    for section_name in [".rdata", ".data", ".bss"] {
        let Some(section) = image.sections.iter().find(|s| s.name == section_name) else {
            continue;
        };
        let mut data_splits = Vec::new();
        let runs = printable_runs(section);
        for (_, start, size, _) in &runs {
            data_splits.push(AnalysisSpan {
                section: section_name.into(),
                start: *start,
                end: *start + *size,
            });
        }
        for (name, start, size, kind) in runs {
            symbols.push(AnalysisSymbol {
                name,
                section: section_name.into(),
                address: start,
                size,
                symbol_type: "object".into(),
                scope: "global".into(),
                data: Some(kind),
            });
        }
        // Fill the unclaimed gaps with conservative anonymous globals. Long
        // zero runs are padding, so split them on 16-byte boundaries rather
        // than making one symbol swallow an entire read-only section.
        let mut boundaries: BTreeSet<u64> =
            BTreeSet::from([section.va, section.va + section.virtual_size]);
        for span in &data_splits {
            boundaries.insert(span.start);
            boundaries.insert(span.end);
        }
        for (start, end) in zero_runs(section) {
            boundaries.insert(start);
            boundaries.insert(end);
        }
        // HIGHLOW entries are the PE linker's evidence that a four-byte slot
        // contains an address. They are useful object boundaries even when no
        // source symbol survived the link.
        for reloc in &image.base_relocations {
            if matches!(reloc.kind, crate::BaseRelocKind::HighLow)
                && reloc.va >= section.va
                && reloc.va + 4 <= section.va + section.virtual_size
            {
                boundaries.insert(reloc.va);
                boundaries.insert(reloc.va + 4);
            }
        }
        // Sorted, merged coverage of the string/global spans, so the gap-fill
        // below can test "fully covered" in O(log n) instead of O(n) per span.
        let covered = merge_ranges(
            data_splits
                .iter()
                .map(|s| (s.start, s.end))
                .collect::<Vec<(u64, u64)>>(),
        );
        let boundaries: Vec<u64> = boundaries.into_iter().collect();
        for pair in boundaries.windows(2) {
            let (start, end) = (pair[0], pair[1]);
            if end <= start || fully_covered(start, end, &covered) {
                continue;
            }
            let mut cursor = start;
            while cursor < end {
                let next = (cursor + 0x100).min(end);
                let name = format!("data_{cursor:08X}");
                symbols.push(AnalysisSymbol {
                    name,
                    section: section_name.into(),
                    address: cursor,
                    size: next - cursor,
                    symbol_type: "object".into(),
                    scope: "global".into(),
                    data: Some(data_kind(next - cursor).into()),
                });
                data_splits.push(AnalysisSpan {
                    section: section_name.into(),
                    start: cursor,
                    end: next,
                });
                cursor = next;
            }
        }
        if !data_splits.is_empty() {
            splits.push(AnalysisSplit {
                object: format!("__{}_data.obj", section_name.trim_start_matches('.')),
                spans: data_splits,
            });
        }
    }

    let imports = image.imports.clone();
    let variables = symbols
        .iter()
        .filter(|symbol| symbol.data.is_some())
        .map(|symbol| {
            (
                symbol.address,
                PeVariable {
                    name: symbol.name.clone(),
                    va: symbol.address,
                    is_public: true,
                    size: symbol.size as u32,
                },
            )
        })
        .collect();
    let globals = PeGlobalSymbols::build(
        functions.clone(),
        variables,
        BTreeMap::new(),
        BTreeMap::new(),
        &imports,
        &image.sections,
        image.image_base,
    );
    let units = functions
        .values()
        .enumerate()
        .map(|(id, f)| PeCompilationUnit {
            id,
            name: f.name.clone(),
            obj_file: format!("{:04}_{}.obj", id, f.name),
            functions: vec![f.clone()],
            contributions: Vec::new(),
        })
        .collect();
    let context = PeContext {
        arch: image.arch,
        image_base: image.image_base,
        sections: image.sections.clone(),
        cu_index: crate::PeCuIndex { units },
        symbols: globals,
        base_relocations: image.base_relocations.clone(),
        imports,
        inlined_functions: Vec::new(),
    };
    Ok((context, AnalysisOutput { symbols, splits }))
}

fn data_kind(size: u64) -> &'static str {
    match size {
        1 => "byte",
        2 => "2byte",
        4 => "4byte",
        8 => "8byte",
        _ => "4byte",
    }
}

fn likely_prologue(bytes: &[u8]) -> bool {
    matches!(
        bytes,
        [0x55, ..] | [0x53, ..] | [0x56, ..] | [0x57, ..] | [0x8b, 0xff, ..]
    ) || bytes.starts_with(&[0x83, 0xec])
        || bytes.starts_with(&[0x81, 0xec])
}

fn likely_exception_handler(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x6a, 0x00, 0x6a, 0x00])
        && bytes
            .get(4..20)
            .map_or(false, |window| window.contains(&0xe8))
}

fn likely_root(bytes: &[u8]) -> bool {
    likely_prologue(bytes) || likely_exception_handler(bytes)
}

fn in_ranges(address: u64, ranges: &[(u64, u64)]) -> bool {
    // Ranges are sorted by start and non-overlapping: binary search for the
    // last range whose start <= address, then check the address is inside it.
    // This is the hot path (called per decoded instruction), so it must not
    // scan the whole list.
    let i = ranges.partition_point(|(start, _)| *start <= address);
    if i == 0 {
        return false;
    }
    let (start, end) = ranges[i - 1];
    address >= start && address < end
}

/// Sort a raw interval list and merge overlaps so the result is suitable for
/// the binary search in `in_ranges`.
fn merge_ranges(ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    if ranges.is_empty() {
        return ranges;
    }
    let mut ranges = ranges;
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if end <= start {
            continue;
        }
        if let Some(last) = merged.last_mut() {
            if start <= last.1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

/// True if `[start, end)` is fully contained in one of `covered`'s ranges.
fn fully_covered(start: u64, end: u64, covered: &[(u64, u64)]) -> bool {
    let i = covered.partition_point(|(s, _)| *s <= start);
    if i == 0 {
        return false;
    }
    let (s, e) = covered[i - 1];
    start >= s && end <= e
}

fn infer_text_jump_tables(image: &PeImage, text: &crate::PeSection) -> Vec<(u64, u64)> {
    let mut slots: Vec<u64> = image
        .base_relocations
        .iter()
        .filter(|reloc| matches!(reloc.kind, crate::BaseRelocKind::HighLow))
        .filter(|reloc| reloc.va >= text.va && reloc.va + 4 <= text.va + text.virtual_size)
        .filter(|reloc| {
            image
                .sections
                .iter()
                .find_map(|s| s.data_at_va(reloc.va, 4))
                .and_then(|bytes| Some(u32::from_le_bytes(bytes.try_into().ok()?) as u64))
                .is_some_and(|target| text.contains_va(target))
        })
        .map(|reloc| reloc.va)
        .collect();
    slots.sort_unstable();
    let mut tables = Vec::new();
    let mut start = None;
    let mut previous = 0;
    for slot in slots.into_iter().chain(std::iter::once(u64::MAX)) {
        if start.is_none() {
            start = Some(slot);
            previous = slot;
            continue;
        }
        if slot == previous + 4 {
            previous = slot;
            continue;
        }
        let table_start = start.take().unwrap();
        let count = (previous - table_start) / 4 + 1;
        if count >= 2 {
            tables.push((table_start, count * 4));
        }
        if slot != u64::MAX {
            start = Some(slot);
            previous = slot;
        }
    }
    tables
}

fn near_target(ins: &Instruction) -> Option<u64> {
    match ins.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 => Some(ins.near_branch_target()),
        _ => None,
    }
}

/// Decode all reachable basic blocks for one function. The returned end is a
/// conservative high-water mark used for the linked-byte object; branch
/// targets remain part of the same function rather than becoming symbols.
fn scan_entrypoints(text: &crate::PeSection, text_data: &[(u64, u64)]) -> BTreeSet<u64> {
    let mut starts = BTreeSet::new();
    let mut decoder = Decoder::with_ip(32, &text.data, text.va, DecoderOptions::NONE);
    let mut ins = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut ins);
        if ins.is_invalid() {
            continue;
        }
        if in_ranges(ins.ip(), text_data) {
            continue;
        }
        let Some(target) = near_target(&ins) else {
            continue;
        };
        match ins.flow_control() {
            // Direct calls are the strongest stripped-binary entry-point
            // evidence and recover functions not reachable from the PE entry.
            FlowControl::Call if ins.op0_kind() == OpKind::NearBranch32 => {
                if text.contains_va(target) {
                    starts.insert(target);
                }
            }
            _ => {}
        }
    }
    starts
}

fn discover_cfg(
    text: &crate::PeSection,
    start: u64,
    known_starts: &BTreeSet<u64>,
    text_data: &[(u64, u64)],
) -> (u64, Vec<u64>) {
    let start_offset = (start - text.va) as usize;
    let mut blocks = vec![start_offset];
    let mut visited = BTreeSet::new();
    let mut calls = BTreeSet::new();
    let mut end = start;
    let mut instruction_count = 0usize;
    while let Some(offset) = blocks.pop() {
        if offset >= text.data.len() || !visited.insert(offset) {
            continue;
        }
        let mut decoder = Decoder::with_ip(
            32,
            &text.data[offset..],
            text.va + offset as u64,
            DecoderOptions::NONE,
        );
        let mut ins = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut ins);
            if ins.is_invalid() {
                break;
            }
            if in_ranges(ins.ip(), text_data) {
                break;
            }
            let ins_offset = (ins.ip() - text.va) as usize;
            if text.data.get(ins_offset) == Some(&0xcc) {
                break;
            }
            let ins_end = ins.ip() + ins.len() as u64;
            end = end.max(ins_end);
            instruction_count += 1;
            match ins.flow_control() {
                FlowControl::Call => {
                    if ins.op0_kind() == OpKind::NearBranch32 {
                        let target = ins.near_branch_target();
                        if text.contains_va(target) && !in_ranges(target, text_data) {
                            calls.insert(target);
                        }
                    }
                }
                FlowControl::ConditionalBranch => {
                    if let Some(target) = near_target(&ins) {
                        if text.contains_va(target) && !in_ranges(target, text_data) {
                            blocks.push((target - text.va) as usize);
                        }
                    }
                }
                FlowControl::UnconditionalBranch => {
                    if let Some(target) = near_target(&ins) {
                        if text.contains_va(target) && !in_ranges(target, text_data) {
                            // A one- or two-instruction jump wrapper is a
                            // thunk, including MSVC's `mov al,cl; jmp` form.
                            let is_thunk = instruction_count <= 2
                                && ins.ip() <= start + 8
                                && target.abs_diff(ins.ip()) > 0x10;
                            // Short jumps close to the current block are
                            // normally internal CFG edges. Far jumps are tail
                            // calls unless the target is already a known root.
                            let is_near_internal = target.abs_diff(ins.ip()) <= 0x100;
                            if is_thunk
                                || (!is_near_internal
                                    && likely_tail_target(text, target, known_starts))
                            {
                                calls.insert(target);
                            } else if is_near_internal {
                                blocks.push((target - text.va) as usize);
                            }
                        }
                    }
                    break;
                }
                FlowControl::Return | FlowControl::Exception => break,
                _ => {}
            }
        }
    }
    (end, calls.into_iter().collect())
}

fn likely_tail_target(text: &crate::PeSection, target: u64, known_starts: &BTreeSet<u64>) -> bool {
    if known_starts.contains(&target) {
        return true;
    }
    let offset = (target - text.va) as usize;
    likely_root(text.data.get(offset..).unwrap_or_default())
}

fn printable_runs(section: &crate::PeSection) -> Vec<(String, u64, u64, String)> {
    let mut out = Vec::new();
    let mut start = None;
    for i in 0..=section.data.len() {
        let printable = i < section.data.len() && (0x20..=0x7e).contains(&section.data[i]);
        if printable && start.is_none() {
            start = Some(i);
        }
        if !printable {
            if let Some(s) = start.take() {
                if i - s >= 3 && i < section.data.len() && section.data[i] == 0 {
                    let address = section.va + s as u64;
                    out.push((
                        format!("str_{address:08X}"),
                        address,
                        (i - s + 1) as u64,
                        "string".into(),
                    ));
                }
            }
        }
    }
    // UTF-16LE literals are common in MSVC data. Require at least three
    // printable code units and a terminating wide NUL.
    let mut i = 0usize;
    while i + 1 < section.data.len() {
        let mut j = i;
        while j + 1 < section.data.len()
            && section.data[j + 1] == 0
            && (0x20..=0x7e).contains(&section.data[j])
        {
            j += 2;
        }
        if j >= i + 6
            && j + 1 < section.data.len()
            && section.data[j] == 0
            && section.data[j + 1] == 0
        {
            let address = section.va + i as u64;
            out.push((
                format!("wstr_{address:08X}"),
                address,
                (j + 2 - i) as u64,
                "wstring".into(),
            ));
            i = j + 2;
        } else {
            i += 1;
        }
    }
    out.sort_by_key(|(_, address, _, _)| *address);
    out.dedup_by(|a, b| a.1 == b.1);
    out
}

fn zero_runs(section: &crate::PeSection) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut start = None;
    for i in 0..=section.data.len() {
        let zero = i < section.data.len() && section.data[i] == 0;
        if zero && start.is_none() {
            start = Some(i);
        }
        if !zero {
            if let Some(s) = start.take() {
                if i - s >= 4 {
                    out.push((section.va + s as u64, section.va + i as u64));
                }
            }
        }
    }
    if section.data.len() < section.virtual_size as usize {
        out.push((
            section.va + section.data.len() as u64,
            section.va + section.virtual_size,
        ));
    }
    out
}
