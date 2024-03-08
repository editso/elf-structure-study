use std::{
    collections::HashMap,
    ffi::CStr,
    ops::{Deref, DerefMut},
    os::raw::c_void,
};

use crate::{
    elf, Elf32_Addr, Elf32_Dyn, Elf32_Half, Elf32_Rel, Elf32_Rela, Elf32_Sym, Elf32_Word, Error,
    ELF32_R_SYM, ELF32_R_TYPE, ELF32_ST_BIND, ELF32_ST_TYPE,
};

#[derive(Debug, Default)]
pub struct Ref<V> {
    value: V,
}

#[derive(Debug)]
pub enum Reloc<'a> {
    Rel(Option<&'a CStr>, &'a Elf32_Rel),
    Rela(Option<&'a CStr>, &'a Elf32_Rela),
}

#[derive(Default)]
pub struct ElfDynamic<'a> {
    sym: Ref<
        Option<(
            Option<Vec<(&'a CStr, &'a Elf32_Sym)>>,
            Option<&'a Elf32_Dyn>,
            Option<&'a Elf32_Dyn>,
        )>,
    >,
    got: Ref<
        Option<(
            Option<&'a [Elf32_Addr]>,
            Option<&'a Elf32_Dyn>,
            Option<&'a Elf32_Dyn>,
        )>,
    >,
    tabs: Ref<Option<&'a [Elf32_Dyn]>>,
    strtab: Ref<
        Option<(
            Option<&'a [u8]>,
            Option<&'a Elf32_Dyn>,
            Option<&'a Elf32_Dyn>,
        )>,
    >,
    needed_so: Ref<Option<Vec<(Option<&'a CStr>, &'a Elf32_Dyn)>>>,
    init: Ref<Vec<&'a Elf32_Dyn>>,
    fini: Ref<Vec<&'a Elf32_Dyn>>,
}

pub struct ElfHeader<'a> {
    raw: &'a [u8],
    hdr: Ref<&'a elf::Elf32_Ehdr>,
    secs: Ref<Vec<(&'a CStr, &'a elf::Elf32_Shdr)>>,
    phdrs: Ref<Option<&'a [elf::Elf32_Phdr]>>,
    strtab: Ref<HashMap<Elf32_Half, &'a [u8]>>,
    symtab: Ref<HashMap<Elf32_Half, Vec<(&'a CStr, &'a Elf32_Sym)>>>,
    relocs: Ref<HashMap<Elf32_Half, Vec<Reloc<'a>>>>,
    dynamic: Ref<Option<ElfDynamic<'a>>>,
}

impl<'a> ElfHeader<'a> {
    pub fn parse(data: &'a [u8]) -> crate::Result<Self> {
        Ok({
            let e_hdr = elf::Elf32_Ehdr::parse(data.as_ptr())?;

            let s_hdrs = unsafe {
                std::slice::from_raw_parts(
                    data[e_hdr.e_shoff as usize..].as_ptr() as *const elf::Elf32_Shdr,
                    e_hdr.e_shnum as usize,
                )
            };

            let str_tabs = {
                let mut tabs = HashMap::new();
                for (idx, hdr) in s_hdrs.iter().enumerate() {
                    if hdr.sh_type.eq(&elf::SHT_STRTAB) {
                        tabs.insert(idx as _, {
                            &data[hdr.sh_offset as usize..(hdr.sh_offset + hdr.sh_size) as usize]
                        });
                    }
                }
                tabs
            };

            let s_hdrs = {
                let mut secs = Vec::new();
                for hdr in s_hdrs {
                    let strs = str_tabs.get(&e_hdr.e_shstrndx).unwrap();
                    unsafe {
                        let name = CStr::from_ptr(strs[hdr.sh_name as usize..].as_ptr() as _);
                        secs.push((name, hdr));
                    }
                }
                secs
            };

            let s_syms = {
                let mut syms = HashMap::new();
                for (idx, (_, hdr)) in s_hdrs.iter().enumerate() {
                    if hdr.sh_type.eq(&elf::SHT_SYMTAB) || hdr.sh_type.eq(&elf::SHT_DYNSYM) {
                        let mut sym = Vec::new();
                        let symtab = unsafe {
                            let ptr = &data[hdr.sh_offset as usize..];
                            std::slice::from_raw_parts(
                                ptr.as_ptr() as *const Elf32_Sym,
                                hdr.sh_size as usize / std::mem::size_of::<Elf32_Sym>(),
                            )
                        };

                        let strtab = str_tabs.get(&(hdr.sh_link as u16)).unwrap();

                        for sy in symtab {
                            unsafe {
                                sym.push((
                                    CStr::from_ptr(strtab[sy.st_name as usize..].as_ptr() as _),
                                    sy,
                                ))
                            }
                        }

                        syms.insert(idx as Elf32_Half, sym);
                    }
                }
                syms
            };

            let relocs = {
                let mut relocs = HashMap::new();

                for (idx, (_, hdr)) in s_hdrs.iter().enumerate() {
                    let mut rels = Vec::new();
                    if hdr.sh_type.eq(&elf::SHT_REL) {
                        let res = unsafe {
                            std::slice::from_raw_parts(
                                data[hdr.sh_offset as usize..].as_ptr() as *const Elf32_Rel,
                                hdr.sh_size as usize / std::mem::size_of::<Elf32_Rel>(),
                            )
                        };

                        let symtab = s_syms.get(&(hdr.sh_link as _)).unwrap();

                        for r in res {
                            let sym = r.r_info >> 8;

                            let name = {
                                match symtab.get(sym as usize) {
                                    Some((s, _)) => Some(*s),
                                    None => None,
                                }
                            };

                            rels.push(Reloc::Rel(name, r))
                        }

                        relocs.insert(idx as Elf32_Half, rels);
                    } else if hdr.sh_type.eq(&elf::SHT_RELA) {
                        let res = unsafe {
                            std::slice::from_raw_parts(
                                data[hdr.sh_offset as usize..].as_ptr() as *const Elf32_Rela,
                                hdr.sh_size as usize / std::mem::size_of::<Elf32_Rela>(),
                            )
                        };

                        let symtab = s_syms.get(&(hdr.sh_link as _)).unwrap();

                        for r in res {
                            let sym = r.r_info >> 8;

                            let name = {
                                match symtab.get(sym as usize) {
                                    Some((s, _)) => Some(*s),
                                    None => None,
                                }
                            };

                            rels.push(Reloc::Rela(name, r))
                        }

                        relocs.insert(idx as Elf32_Half, rels);
                    }
                }

                relocs
            };

            let phdr = {
                if e_hdr.e_phoff == 0 {
                    None
                } else {
                    unsafe {
                        Some(std::slice::from_raw_parts(
                            data[e_hdr.e_phoff as usize..].as_ptr() as *const elf::Elf32_Phdr,
                            e_hdr.e_phnum as usize,
                        ))
                    }
                }
            };

            let dynamic = {
                if let Some(phdr) = phdr.as_ref() {
                    let mut dynamic = ElfDynamic {
                        sym: Default::default(),
                        got: Default::default(),
                        tabs: Default::default(),
                        init: Default::default(),
                        fini: Default::default(),
                        strtab: Default::default(),
                        needed_so: Default::default(),
                    };

                    for hdr in phdr.iter() {
                        if hdr.p_type != elf::PT_DYNAMIC {
                            continue;
                        }

                        let base = data[hdr.p_offset as usize..].as_ptr() as *const elf::Elf32_Dyn;

                        let mut dy = base;

                        loop {
                            unsafe {
                                if let Some(dy) = dy.as_ref() {
                                    if dy.d_tag == elf::DT_NEEDED {
                                        let needed = match dynamic.needed_so.take() {
                                            None => vec![(None, dy)],
                                            Some(mut neededs) => {
                                                neededs.push((None, dy));
                                                neededs
                                            }
                                        };
                                        dynamic.needed_so.replace(needed);
                                    } else if dy.d_tag == elf::DT_STRTAB {
                                        let strtab = match dynamic.strtab.take() {
                                            None => (None, Some(dy), None),
                                            Some((None, None, Some(inf))) => {
                                                let str = std::slice::from_raw_parts(
                                                    data[dy.d_un.d_val as usize..].as_ptr()
                                                        as *const u8,
                                                    inf.d_un.d_val as usize,
                                                );
                                                (Some(str), Some(dy), Some(inf))
                                            }
                                            _ => unreachable!(),
                                        };
                                        dynamic.strtab.replace(strtab);
                                    } else if dy.d_tag == elf::DT_STRSZ {
                                        let strtab = match dynamic.strtab.take() {
                                            None => (None, None, Some(dy)),
                                            Some((None, Some(inf), None)) => {
                                                let str = std::slice::from_raw_parts(
                                                    data[inf.d_un.d_val as usize..].as_ptr()
                                                        as *const u8,
                                                    dy.d_un.d_val as usize,
                                                );
                                                (Some(str), Some(inf), Some(dy))
                                            }
                                            _ => unreachable!(),
                                        };
                                        dynamic.strtab.replace(strtab);
                                    } else if dy.d_tag == elf::DT_INIT {
                                        dynamic.init.push(dy);
                                    } else if dy.d_tag == elf::DT_FINI {
                                        dynamic.fini.push(dy);
                                    } else if dy.d_tag == elf::DT_SYMTAB {
                                        let sym = match dynamic.sym.take() {
                                            None => (None, Some(dy), None),
                                            Some((None, None, Some(inf))) => {
                                                (None, Some(dy), Some(inf))
                                            }
                                            _ => unreachable!(),
                                        };

                                        dynamic.sym.replace(sym);
                                    } else if dy.d_tag == elf::DT_SYMENT {
                                        let sym = match dynamic.sym.take() {
                                            None => (None, None, Some(dy)),
                                            Some((None, Some(inf), None)) => {
                                                (None, Some(inf), Some(dy))
                                            }
                                            _ => unreachable!(),
                                        };

                                        dynamic.sym.replace(sym);
                                    } else if dy.d_tag == elf::DT_NULL {
                                        break;
                                    }
                                }

                                dy = dy.add(1);
                            }
                        }

                        let count =
                            (dy as usize - base as usize) / std::mem::size_of::<elf::Elf32_Dyn>();

                        dynamic
                            .tabs
                            .replace(unsafe { std::slice::from_raw_parts(base, count) });
                    }

                    if let Some(needed_so) = dynamic.needed_so.as_mut() {
                        for (name, dy) in needed_so.iter_mut() {
                            if let Some((Some(strtab), ..)) = dynamic.strtab.as_ref() {
                                unsafe {
                                    name.replace(CStr::from_ptr(
                                        strtab[dy.d_un.d_val as usize..].as_ptr() as _,
                                    ));
                                }
                            }
                        }
                    }

                    if let Some((None, Some(dy), Some(inf))) = dynamic.sym.take() {
                        unsafe {
                            if let Some((Some(strtab), ..)) = dynamic.strtab.as_ref() {
                                let syms = std::slice::from_raw_parts(
                                    data[dy.d_un.d_val as usize..].as_ptr() as *const Elf32_Sym,
                                    inf.d_un.d_val as usize,
                                )
                                .iter()
                                .fold(
                                    Vec::new(),
                                    |mut syms, sym| {
                                        syms.push((
                                            CStr::from_ptr(
                                                strtab[sym.st_name as usize..].as_ptr() as _
                                            ),
                                            sym,
                                        ));
                                        syms
                                    },
                                );

                                dynamic.sym.replace((Some(syms), Some(dy), Some(inf)));
                            }
                        }
                    }

                    Some(dynamic)
                } else {
                    None
                }
            };

            Self {
                raw: data,
                strtab: Ref { value: str_tabs },
                hdr: Ref {
                    value: unsafe { elf::Elf32_Ehdr::from_raw(data.as_ptr()) },
                },
                secs: Ref { value: s_hdrs },
                symtab: Ref { value: s_syms },
                relocs: Ref { value: relocs },
                phdrs: Ref { value: phdr },
                dynamic: Ref { value: dynamic },
            }
        })
    }
}

impl elf::Elf32_Ehdr {
    pub fn parse<'a>(raw: *const u8) -> crate::Result<&'a Self> {
        unsafe {
            let hdr = Self::from_raw(raw);
            if hdr.e_ident[..4].ne(&[0x7f, 'E' as _, 'L' as _, 'F' as _]) {
                Err(Error::InvalidElf)
            } else {
                Ok(hdr)
            }
        }
    }

    pub unsafe fn from_raw<'a>(raw: *const u8) -> &'a Self {
        std::mem::transmute(raw)
    }
}

impl elf::Elf32_Sym {
    pub unsafe fn from_raw<'a>(raw: *const u8) -> &'a Self {
        std::mem::transmute(raw)
    }
}

impl elf::Elf32_Phdr {
    pub unsafe fn from_raw<'a>(raw: *const u8) -> &'a Self {
        std::mem::transmute(raw)
    }
}

impl<V> Deref for Ref<V> {
    type Target = V;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<V> DerefMut for Ref<V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

impl ElfHeader<'_> {
    pub unsafe fn load(&self) {
        let mut minva = 0;
        let mut maxva = 0;

        if let Some(phdr) = self.phdrs.as_ref() {
            for hdr in phdr.iter() {
                if hdr.p_type != elf::PT_LOAD {
                    continue;
                }

                if minva > hdr.p_vaddr {
                    minva = hdr.p_vaddr;
                } else if maxva < hdr.p_vaddr + hdr.p_memsz {
                    maxva = hdr.p_vaddr + hdr.p_memsz;
                }
            }
        }

        const MAP_PRIVATE: i32 = 0x2;
        const MAP_ANONYMOUS: i32 = 0x20;
        const PROT_WRITE: i32 = 0x2;
        const PROT_EXEC: i32 = 0x4;
        const PROT_READ: i32 = 0x1;

        extern "C" {

            fn mmap(
                addr: *const u8,
                len: usize,
                prot: i32,
                flags: i32,
                fildes: i32,
                off: usize,
            ) -> *mut c_void;
        }

        let mm = mmap(
            std::ptr::null(),
            (maxva - minva) as usize,
            PROT_WRITE | PROT_EXEC | PROT_READ,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );

        let mm = std::ptr::slice_from_raw_parts_mut(mm as *mut u8, (maxva - minva) as usize)
            .as_mut()
            .expect("out of memory");

        if let Some(phdr) = self.phdrs.as_ref() {
            for hdr in phdr.iter() {
                if hdr.p_type != elf::PT_LOAD {
                    continue;
                }

                let ptr = &self.raw[hdr.p_offset as usize..(hdr.p_offset + hdr.p_filesz) as usize];

                mm[hdr.p_vaddr as usize..(hdr.p_vaddr as usize + ptr.len())].copy_from_slice(ptr);
            }
        }

        for (name, hdr) in self.secs.iter() {
            if hdr.sh_addr == 0 {
                continue;
            }

            let ptr = &self.raw[hdr.sh_offset as usize..(hdr.sh_offset + hdr.sh_size) as usize];

            mm[hdr.sh_addr as usize..(hdr.sh_addr as usize + ptr.len())].copy_from_slice(ptr);
        }

        for (idx, syms) in self.symtab.iter() {
            for (name, sym) in syms {
                let st_bind = ELF32_ST_BIND!(sym.st_info);
                let st_type = ELF32_ST_TYPE!(sym.st_info);
                if st_type == elf::STT_FUNC {
                    println!("this {name:?} is a func")
                } else if st_type == elf::STT_OBJECT {
                    println!("this {name:?} is a variable")
                }
            }
        }

        for (_, relocs) in self.relocs.iter() {
            for reloc in relocs {
                match reloc {
                    Reloc::Rel(n, r) => {}
                    Reloc::Rela(n, r) => {}
                }
            }
        }

        let f = std::mem::transmute::<_, extern "C" fn()>(mm[self.hdr.e_entry as usize..].as_ptr());

        f();

        println!("......");
    }
}

#[cfg(test)]
mod tests {
    use crate::ElfHeader;

    #[test]
    fn test() {
        let r = &std::env::args().collect::<Vec<String>>()[0];
        let elf = std::fs::read(r).unwrap();
        unsafe {
            ElfHeader::parse(&elf)
                .expect("Failed to parse elf file")
                .load();
        }
    }
}
