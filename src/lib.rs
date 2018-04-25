extern crate addr2line;
extern crate fallible_iterator;
extern crate gimli;
extern crate goblin;
extern crate object;

use std::mem;
use std::path::PathBuf;
use goblin::Object;
use goblin::mach::{symbols, Mach};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum DebugInfoOrigin {
    ThisFile,
    OtherFile(PathBuf),
}

#[derive(Debug)]
pub struct FoundAddressInFunction {
    pub original_address: u64,
    pub function_relative_offset: u64,
}

#[derive(Debug)]
pub struct FunctionWithFoundAddresses {
    pub symbol_name: String,
    pub found_addresses: Vec<FoundAddressInFunction>,
}

struct OriginSection<'a> {
    file_name: &'a str,
    functions_with_found_addresses: Vec<FunctionWithFoundAddresses>,
}

enum FunctionLocation<'a> {
    OutsideOfOriginSection,
    InsidePreviousOriginSection(OriginSection<'a>),
    InsideCurrentOriginSection,
}

struct CurrentFunction<'a> {
    address: u64,
    name: &'a str,
    location: FunctionLocation<'a>,
}

struct Resolver<'a, 'b> {
    remaining_addresses_to_look_up: &'b [u64],
    current_origin_section: Option<OriginSection<'a>>,
    current_function: Option<CurrentFunction<'a>>,
    results: Vec<(DebugInfoOrigin, Vec<FunctionWithFoundAddresses>)>,
    outside_file: Vec<FunctionWithFoundAddresses>,
}

impl<'a, 'b> Resolver<'a, 'b> {
    fn new(addresses_to_look_up: &'b [u64]) -> Self {
        Resolver {
            remaining_addresses_to_look_up: addresses_to_look_up,
            current_origin_section: None,
            current_function: None,
            results: Vec::new(),
            outside_file: Vec::new(),
        }
    }

    fn split_out_addresses_before_address(&mut self, address: u64) -> &'b [u64] {
        let index = self.remaining_addresses_to_look_up
            .iter()
            .position(|&a| a > address)
            .unwrap_or(self.remaining_addresses_to_look_up.len());
        let (result, rest) = self.remaining_addresses_to_look_up.split_at(index);
        self.remaining_addresses_to_look_up = rest;
        result
    }

    fn enter_origin_section(&mut self, file_name: &'a str) {
        self.current_origin_section = Some(OriginSection {
            file_name,
            functions_with_found_addresses: Vec::new(),
        });
    }

    fn exit_current_origin_section(&mut self) {
        let previous_origin_section = mem::replace(&mut self.current_origin_section, None);
        if let Some(previous_origin_section) = previous_origin_section {
            if let &mut Some(ref mut current_function) = &mut self.current_function {
                if let FunctionLocation::InsideCurrentOriginSection = current_function.location {
                    current_function.location =
                        FunctionLocation::InsidePreviousOriginSection(previous_origin_section)
                }
            }
        }
    }

    fn finish_processing_function(
        &mut self,
        function: Option<CurrentFunction<'a>>,
        assigned_addresses: &[u64],
    ) {
        match function {
            Some(CurrentFunction {
                name,
                mut location,
                address,
            }) => {
                if !assigned_addresses.is_empty() {
                    let f = FunctionWithFoundAddresses {
                        symbol_name: name.to_string(),
                        found_addresses: assigned_addresses
                            .iter()
                            .map(|&a| FoundAddressInFunction {
                                original_address: a,
                                function_relative_offset: a - address,
                            })
                            .collect(),
                    };
                    match &mut location {
                        &mut FunctionLocation::OutsideOfOriginSection => {
                            self.outside_file.push(f);
                        }
                        &mut FunctionLocation::InsidePreviousOriginSection(
                            ref mut origin_section,
                        ) => {
                            origin_section.functions_with_found_addresses.push(f);
                        }
                        &mut FunctionLocation::InsideCurrentOriginSection => {
                            self.current_origin_section
                                .as_mut()
                                .unwrap()
                                .functions_with_found_addresses
                                .push(f);
                        }
                    }
                }
                if let FunctionLocation::InsidePreviousOriginSection(origin_section) = location {
                    if !origin_section.functions_with_found_addresses.is_empty() {
                        self.results.push((
                            DebugInfoOrigin::OtherFile(PathBuf::from(origin_section.file_name)),
                            origin_section.functions_with_found_addresses,
                        ));
                    }
                }
            }
            None => for address in assigned_addresses {
                println!("address {:x} is before the first FUN symbol", address);
            },
        }
    }

    fn process_symbol(&mut self, (name, nlist): (&'a str, symbols::Nlist)) {
        match nlist.n_type {
            symbols::N_OSO => {
                if name != "" {
                    self.enter_origin_section(name);
                }
            }
            symbols::N_SO => {
                if name == "" {
                    self.exit_current_origin_section();
                }
            }
            symbols::N_FUN => {
                if name != "" {
                    let previous_function = mem::replace(
                        &mut self.current_function,
                        Some(CurrentFunction {
                            address: nlist.n_value,
                            name,
                            location: match self.current_origin_section {
                                Some(_) => FunctionLocation::InsideCurrentOriginSection,
                                None => FunctionLocation::OutsideOfOriginSection,
                            },
                        }),
                    );
                    let addresses_for_previous_function =
                        self.split_out_addresses_before_address(nlist.n_value);
                    self.finish_processing_function(
                        previous_function,
                        addresses_for_previous_function,
                    );
                }
            }
            _ => {}
        }
    }

    fn finish(mut self) -> Vec<(DebugInfoOrigin, Vec<FunctionWithFoundAddresses>)> {
        self.exit_current_origin_section();
        let addresses_for_last_function =
            mem::replace(&mut self.remaining_addresses_to_look_up, &[]);
        let last_function = mem::replace(&mut self.current_function, None);
        self.finish_processing_function(last_function, addresses_for_last_function);
        let mut results = self.results;
        let outside_file = self.outside_file;
        if !outside_file.is_empty() {
            results.push((DebugInfoOrigin::ThisFile, outside_file));
        }
        results
    }

    fn is_done(&self) -> bool {
        self.remaining_addresses_to_look_up.is_empty()
    }
}

pub fn resolve_to_debug_info_origins(
    lib_data: &[u8],
    addresses: &[u64],
) -> Vec<(DebugInfoOrigin, Vec<FunctionWithFoundAddresses>)> {
    match Object::parse(lib_data).unwrap() {
        Object::Elf(elf) => {
            println!("elf: {:#?}", &elf);
        }
        Object::PE(pe) => {
            println!("pe: {:#?}", &pe);
        }
        Object::Mach(mach) => match mach {
            Mach::Binary(mach) => {
                let mut sorted_addresses = Vec::from(addresses);
                sorted_addresses.sort();
                let mut resolver = Resolver::new(&sorted_addresses);
                for s in mach.symbols() {
                    resolver.process_symbol(s.unwrap());
                    if resolver.is_done() {
                        return resolver.finish();
                    }
                }
                return resolver.finish();
            }
            _ => {}
        },
        Object::Archive(archive) => {
            println!("archive: {:#?}", &archive);
        }
        Object::Unknown(magic) => println!("unknown magic: {:#x}", magic),
    }
    Vec::new()
}

pub fn resolve_to_origin_relative_addresses(
    object_file: &mut object::File,
    functions_with_addresses: Vec<FunctionWithFoundAddresses>,
) -> Vec<(u64, u64)> {
    use object::Object;

    let mut result = Vec::new();

    let mut map: HashMap<String, Vec<FoundAddressInFunction>> = functions_with_addresses
        .into_iter()
        .map(
            |FunctionWithFoundAddresses {
                 symbol_name,
                 found_addresses,
             }| (symbol_name, found_addresses),
        )
        .collect();
    for symbol in object_file.symbols() {
        if let Some(symbol_name) = symbol.name() {
            if let Some(f) = map.remove(symbol_name) {
                for FoundAddressInFunction {
                    original_address,
                    function_relative_offset,
                } in f
                {
                    result.push((
                        original_address,
                        symbol.address() + function_relative_offset,
                    ));
                }
            }
        }
    }

    result
}

#[derive(Debug)]
pub struct StackFrame {
    pub function_name: Option<String>,
    pub file_path: Option<PathBuf>,
    pub line: Option<u64>,
    pub column: Option<u64>,
}

fn convert_stack_frame<R: gimli::Reader>(frame: addr2line::Frame<R>) -> StackFrame {
    StackFrame {
        function_name: frame
            .function
            .and_then(|f| f.demangle().ok().map(|n| n.into_owned())),
        file_path: frame.location.as_ref().and_then(|l| l.file.clone()),
        line: frame.location.as_ref().and_then(|l| l.line),
        column: frame.location.as_ref().and_then(|l| l.column),
    }
}

pub fn resolve_everything(
    origins: Vec<(DebugInfoOrigin, Vec<FunctionWithFoundAddresses>)>,
) -> HashMap<u64, Vec<StackFrame>> {
    use fallible_iterator::FallibleIterator;

    let mut result = HashMap::new();
    for (origin, functions_with_found_addresses) in origins {
        match origin {
            DebugInfoOrigin::ThisFile => {}
            DebugInfoOrigin::OtherFile(file_path) => {
                let mut data = Vec::new();
                File::open(file_path)
                    .unwrap()
                    .read_to_end(&mut data)
                    .unwrap();
                let mut object_file = object::File::parse(&data).unwrap();
                let origin_relative_addresses = resolve_to_origin_relative_addresses(
                    &mut object_file,
                    functions_with_found_addresses,
                );
                let mut context = addr2line::Context::new(&object_file).unwrap();
                for (original_address, origin_relative_address) in
                    origin_relative_addresses.into_iter()
                {
                    match context.find_frames(origin_relative_address) {
                        Ok(frame_iter) => {
                            result.insert(
                                original_address,
                                frame_iter.map(convert_stack_frame).collect().unwrap(),
                            );
                        }
                        Err(error) => {
                            println!("context.find_frames did not find anything for origin_relative_address {:x} because of error {:?}", origin_relative_address, error);
                        }
                    }
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn it_works() {
        let mut data = Vec::new();
        File::open("/Users/mstange/code/obj-m-opt/dist/bin/XUL")
            .unwrap()
            .read_to_end(&mut data)
            .unwrap();
        let result = ::resolve_to_debug_info_origins(&data, &[0x100cdad]);
        println!("result: {:#?}", result);
        let result = ::resolve_everything(result);
        println!("result: {:#?}", result);

        // Output:
        //
        // result: [
        //     (
        //         OtherFile(
        //             "/Users/mstange/code/obj-m-opt/toolkit/library/../../dom/bindings/UnifiedBindings0.o"
        //         ),
        //         [
        //             FunctionWithFoundAddresses {
        //                 symbol_name: "__ZN7mozilla3dom11AttrBindingL13get_specifiedEP9JSContextN2JS6HandleIP8JSObjectEEPNS0_4AttrE19JSJitGetterCallArgs",
        //                 found_addresses: [
        //                     FoundAddressInFunction {
        //                         original_address: 16829869,
        //                         function_relative_offset: 77
        //                     }
        //                 ]
        //             }
        //         ]
        //     )
        // ]
        // result: {
        //     16829869: [
        //         StackFrame {
        //             function_name: Some(
        //                 "std::__1::__atomic_base<char const*, false>::store(char const*, std::__1::memory_order)"
        //             ),
        //             file_path: None,
        //             line: None,
        //             column: None
        //         },
        //         StackFrame {
        //             function_name: Some(
        //                 "mozilla::detail::IntrinsicMemoryOps<char const*, (mozilla::MemoryOrdering)1>::store(std::__1::atomic<char const*>&, char const*)"
        //             ),
        //             file_path: Some(
        //                 "/Users/mstange/code/obj-m-opt/dist/include/mozilla/Atomics.h"
        //             ),
        //             line: Some(
        //                 201
        //             ),
        //             column: None
        //         },
        //         StackFrame {
        //             function_name: Some(
        //                 "mozilla::detail::AtomicBase<char const*, (mozilla::MemoryOrdering)1>::operator=(char const*)"
        //             ),
        //             file_path: Some(
        //                 "/Users/mstange/code/obj-m-opt/dist/include/mozilla/Atomics.h"
        //             ),
        //             line: Some(
        //                 324
        //             ),
        //             column: None
        //         },
        //         StackFrame {
        //             function_name: Some(
        //                 "js::ProfileEntry::initLabelFrame(char const*, char const*, void*, unsigned int, js::ProfileEntry::Kind, js::ProfileEntry::Category)"
        //             ),
        //             file_path: Some(
        //                 "/Users/mstange/code/obj-m-opt/dist/include/js/ProfilingStack.h"
        //             ),
        //             line: Some(
        //                 232
        //             ),
        //             column: None
        //         },
        //         StackFrame {
        //             function_name: Some(
        //                 "PseudoStack::pushLabelFrame(char const*, char const*, void*, unsigned int, js::ProfileEntry::Kind, js::ProfileEntry::Category)"
        //             ),
        //             file_path: Some(
        //                 "/Users/mstange/code/obj-m-opt/dist/include/js/ProfilingStack.h"
        //             ),
        //             line: Some(
        //                 350
        //             ),
        //             column: None
        //         },
        //         StackFrame {
        //             function_name: Some(
        //                 "mozilla::AutoProfilerLabel::Push(PseudoStack*, char const*, char const*, unsigned int, js::ProfileEntry::Category)"
        //             ),
        //             file_path: Some(
        //                 "/Users/mstange/code/obj-m-opt/dist/include/GeckoProfiler.h"
        //             ),
        //             line: Some(
        //                 710
        //             ),
        //             column: None
        //         },
        //         StackFrame {
        //             function_name: Some(
        //                 "mozilla::AutoProfilerLabel::base object constructor(JSContext*, char const*, char const*, unsigned int, js::ProfileEntry::Category)"
        //             ),
        //             file_path: Some(
        //                 "/Users/mstange/code/obj-m-opt/dist/include/GeckoProfiler.h"
        //             ),
        //             line: Some(
        //                 695
        //             ),
        //             column: None
        //         },
        //         StackFrame {
        //             function_name: Some(
        //                 "mozilla::AutoProfilerLabel::complete object constructor(JSContext*, char const*, char const*, unsigned int, js::ProfileEntry::Category)"
        //             ),
        //             file_path: Some(
        //                 "/Users/mstange/code/obj-m-opt/dist/include/GeckoProfiler.h"
        //             ),
        //             line: Some(
        //                 692
        //             ),
        //             column: None
        //         },
        //         StackFrame {
        //             function_name: Some(
        //                 "mozilla::dom::AttrBinding::get_specified(JSContext*, JS::Handle<JSObject*>, mozilla::dom::Attr*, JSJitGetterCallArgs)"
        //             ),
        //             file_path: Some(
        //                 "/Users/mstange/code/obj-m-opt/dom/bindings/AttrBinding.cpp"
        //             ),
        //             line: Some(
        //                 249
        //             ),
        //             column: None
        //         }
        //     ]
        // }
    }
}
