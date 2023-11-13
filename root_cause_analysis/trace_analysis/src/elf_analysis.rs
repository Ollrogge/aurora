use anyhow::{anyhow, Context, Result};
use gimli::{DebuggingInformationEntry, EndianSlice, EntriesTree, LittleEndian, UnitOffset};
use glob::glob;
use goblin::elf::Elf;
use object::{Object, ObjectSection};
use std::borrow::{self, BorrowMut};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::ops::Range;

fn glob_paths(pattern: String) -> Vec<String> {
    glob(&pattern)
        .unwrap()
        .map(|p| p.unwrap().to_str().unwrap().to_string())
        .collect()
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum FunctionType {
    Contigious,
    Range,
}
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Function {
    pub typ: FunctionType,
    pub ranges: Vec<Range<usize>>,
}

impl Function {
    pub fn new(typ: FunctionType, ranges: Vec<Range<usize>>) -> Function {
        Function { typ, ranges }
    }

    pub fn contains(&self, address: usize) -> bool {
        for range in self.ranges.iter() {
            if range.contains(&address) {
                return true;
            }
        }

        false
    }

    pub fn is_more_specific_than(&self, addr: usize, other: &Function) -> Result<bool> {
        let closest_me = self
            .ranges
            .iter()
            .filter(|&range| range.contains(&addr))
            .map(|range| range.start)
            .max()
            .context("Error finding best range start")?;

        let closest_other = other
            .ranges
            .iter()
            .filter(|&range| range.contains(&addr))
            .map(|range| range.start)
            .max()
            .context("Error finding best range start")?;

        if closest_me == closest_other {
            let typ_me = self.typ;

            if typ_me == FunctionType::Range {
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(closest_me > closest_other)
        }
    }
}

pub fn get_functions(eval_dir: &String) -> Result<Vec<Function>> {
    let binary_path = glob_paths(format!("{}/*_trace", eval_dir))
        .pop()
        .expect("Unable to find binary for compound ranking");

    let binary = fs::read(binary_path)?;
    let elf = Elf::parse(&binary).expect("Failed to parse elf");

    /*
    let mut functions: HashSet<Function> = elf
        .syms
        .iter()
        .filter(|sym| sym.st_type() == goblin::elf::sym::STT_FUNC)
        // mask out the thumb bit.
        // readelf will say function is at e.g. address 0x200fdd but when executing,
        // it will actually be at 0x200fdc
        .map(|sym| {
            let start = (sym.st_value & !1) as usize;
            let end = start + sym.st_size as usize;

            Function::new(FunctionType::Contigious, vec![Range { start, end }])
        })
        .collect();
    */

    let mut functions: HashSet<Function> = HashSet::new();

    /* parse DWARF debug information to find inlined functions and add them to vec */
    let object = object::File::parse(&*binary)?;
    let endian = gimli::RunTimeEndian::Little; // Assuming little endian; adjust as needed

    let load_section = |id: gimli::SectionId| -> Result<borrow::Cow<[u8]>, gimli::Error> {
        match object.section_by_name(id.name()) {
            Some(ref section) => Ok(section
                .uncompressed_data()
                .unwrap_or(borrow::Cow::Borrowed(&[][..]))),
            None => Ok(borrow::Cow::Borrowed(&[][..])),
        }
    };

    // Load all of the sections.
    let dwarf_cow = gimli::Dwarf::load(&load_section)?;

    // Borrow a `Cow<[u8]>` to create an `EndianSlice`.
    let borrow_section: &dyn for<'a> Fn(
        &'a borrow::Cow<[u8]>,
    ) -> gimli::EndianSlice<'a, gimli::RunTimeEndian> =
        &|section| gimli::EndianSlice::new(&*section, endian);

    let dwarf = dwarf_cow.borrow(&borrow_section);

    let mut iter = dwarf.units();
    while let Some(header) = iter.next()? {
        let unit = dwarf.unit(header)?;
        let mut entries = unit.entries();
        while let Some((_, entry)) = entries.next_dfs()? {
            if entry.tag() == gimli::DW_TAG_subprogram
                || entry.tag() == gimli::DW_TAG_inlined_subroutine
            {
                let name: Option<String> = if let Some(attr) = entry.attr(gimli::DW_AT_name)? {
                    if let gimli::AttributeValue::DebugStrRef(offset) = attr.value() {
                        let raw_name = dwarf.string(offset)?;
                        Some(String::from_utf8_lossy(&raw_name).to_string())
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some(gimli::AttributeValue::Addr(low_addr)) =
                    entry.attr_value(gimli::DW_AT_low_pc)?
                {
                    let start_addr = (low_addr & !1) as usize;

                    if let Some(high_value) = entry.attr_value(gimli::DW_AT_high_pc)? {
                        let high_addr = match high_value {
                            gimli::AttributeValue::Addr(addr) => addr as usize, // high_pc is an absolute address
                            gimli::AttributeValue::Udata(offset) => start_addr + offset as usize, // high_pc is an offset from low_pc
                            _ => continue, // Unexpected type for high_pc; skip this entry
                        };

                        let end_addr = high_addr & !1;

                        let range = Range {
                            start: start_addr,
                            end: end_addr,
                        };

                        let func = Function::new(FunctionType::Contigious, vec![range]);

                        functions.insert(func);
                    }
                } else if let Some(gimli::AttributeValue::RangeListsRef(range_list_offset)) =
                    entry.attr_value(gimli::DW_AT_ranges)?
                {
                    let offset = gimli::RangeListsOffset(range_list_offset.0);
                    // Here, you'll need to fetch the actual ranges from the `.debug_ranges` section
                    let mut range_list = dwarf.ranges(&unit, offset)?;
                    let mut ranges = vec![];
                    while let Some(range) = range_list.next()? {
                        if range.begin != 0 && range.end != 0 {
                            let start_addr = (range.begin & !1) as usize;
                            let end_addr = (range.end & !1) as usize;

                            let range = Range {
                                start: start_addr,
                                end: end_addr,
                            };

                            ranges.push(range);
                        }
                    }

                    let func = Function::new(FunctionType::Range, ranges);
                    //functions.insert(func);
                }
            }
        }
    }

    Ok(functions.into_iter().collect())
}

// find the correct function for an address, considering inlining
// e.g. if func2 is inlined in func1, then this function will return func1 for
// an address contained within the range on func1, even though this is also
// contained within the range of func2
pub fn find_func_for_addr(functions: &Vec<Function>, addr: usize) -> Option<Function> {
    let mut best_candidate: Option<Function> = None;
    for func in functions.iter() {
        if !func.contains(addr) {
            continue;
        }
        match best_candidate {
            Some(ref best) => {
                if func.is_more_specific_than(addr, &best).unwrap_or(false) {
                    best_candidate = Some(func.clone());
                }
            }
            None => best_candidate = Some(func.clone()),
        }
    }

    best_candidate
}
