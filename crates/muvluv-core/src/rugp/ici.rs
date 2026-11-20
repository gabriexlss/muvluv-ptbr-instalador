use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use super::crypto::{
    decode_encrypted_generic, decode_extent_offset, decode_extent_size, decrypt_ici_payload,
    ENCRYPTED_SIGNATURE, ICI_KEY, ICI_SIGNATURE,
};

pub struct Reader<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn seek(&mut self, pos: usize) -> Result<()> {
        if pos > self.data.len() {
            bail!("seek out of bounds: {}", pos);
        }
        self.pos = pos;
        Ok(())
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos.checked_add(n).is_none_or(|end| end > self.data.len()) {
            bail!(
                "EOF at 0x{:X}: need {}, have {}",
                self.pos,
                n,
                self.data.len().saturating_sub(self.pos)
            );
        }
        let b = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(b)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }

    pub fn i64(&mut self) -> Result<i64> {
        let b = self.take(8)?;
        Ok(i64::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn count(&mut self) -> Result<usize> {
        let c = self.u16()?;
        if c == 0xFFFF {
            let v = self.i32()?;
            if v < 0 {
                bail!("negative count: {}", v);
            }
            Ok(v as usize)
        } else {
            Ok(c as usize)
        }
    }

    pub fn short_count(&mut self) -> Result<usize> {
        let c = self.u8()?;
        if c == 0xFF {
            Ok(self.u16()? as usize)
        } else {
            Ok(c as usize)
        }
    }

    pub fn string(&mut self) -> Result<String> {
        let length = self.u8()?;
        if length < 0xFF {
            let b = self.take(length as usize)?;
            return Ok(String::from_utf8_lossy(b).into_owned());
        }
        let len2 = self.u16()?;
        if len2 == 0xFFFE {
            let cc = self.short_count()?;
            let b = self.take(cc * 2)?;
            return Ok(decode_utf16le(b));
        }
        if len2 < 0xFFFF {
            let b = self.take(len2 as usize)?;
            return Ok(String::from_utf8_lossy(b).into_owned());
        }
        let len4 = self.i32()?;
        if len4 < 0 {
            bail!("negative string length: {}", len4);
        }
        let b = self.take(len4 as usize)?;
        Ok(String::from_utf8_lossy(b).into_owned())
    }
}

pub fn decode_utf16le(raw: &[u8]) -> String {
    let mut u16s = Vec::with_capacity(raw.len() / 2);
    for chunk in raw.chunks_exact(2) {
        u16s.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16_lossy(&u16s)
}

const CHAR_MAP1: &[u8; 16] = b"eaitrosducmnSglR";
const CHAR_MAP2: [u8; 16] = [
    1, b'C', b'O', b'F', b'L', b'f', b'B', b'M', b'x', b'p', b'h', b'y', b'A', b'V', b'b', b'I',
];
const CHAR_MAP3: &[u8; 32] = b"EHTDPWXkqvNjwGz02U_K15JQZ467839\0";

pub fn decode_class_name(encoded: &[u8]) -> String {
    let mut bit_pos = 0usize;
    let total_bits = encoded.len() * 8;
    let mut get_bits = |n: usize| -> i32 {
        let mut v = 0i32;
        for i in 0..n {
            if bit_pos >= total_bits {
                return -1;
            }
            let b = i32::from((encoded[bit_pos >> 3] >> (bit_pos & 7)) & 1);
            v |= b << i;
            bit_pos += 1;
        }
        v
    };

    let mut out = Vec::new();
    if get_bits(1) == 0 {
        out.push(b'C');
    }
    loop {
        let b = get_bits(1);
        if b == -1 {
            break;
        }
        let ch = if b == 0 {
            let idx = get_bits(4);
            if idx == -1 {
                break;
            }
            CHAR_MAP1[idx as usize]
        } else if get_bits(1) != 0 {
            let idx = get_bits(5);
            if idx == -1 {
                break;
            }
            CHAR_MAP3[idx as usize]
        } else {
            let idx = get_bits(4);
            if idx == -1 {
                break;
            }
            if idx != 0 {
                CHAR_MAP2[idx as usize]
            } else {
                let v = get_bits(8);
                if v == -1 {
                    break;
                }
                v as u8
            }
        };
        if ch == 0 {
            break;
        }
        out.push(ch);
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Debug, Clone)]
pub struct ArcInfo {
    pub rio_name: String,
    pub rio_offset: i64,
    pub rio_size: i64,
}

#[derive(Debug, Clone)]
pub struct IciInfo {
    pub toc_offset: u32,
    pub toc_size: u32,
    pub rio_file_name: String,
    pub arcs: Vec<ArcInfo>,
}

pub fn parse_ici(path: &Path) -> Result<IciInfo> {
    let raw = fs::read(path).with_context(|| format!("read ICI {}", path.display()))?;
    let (enc_plain, _) = decode_encrypted_generic(&raw, ICI_KEY).context("decrypt ICI stream")?;
    let plain = decrypt_ici_payload(&enc_plain);
    let mut r = Reader::new(&plain);

    let sig = r.u32()?;
    if sig != ICI_SIGNATURE {
        bail!("bad ICI sig 0x{:08X}", sig);
    }
    let ver = r.u16()?;
    if (0x10..=0x3FFF).contains(&ver) {
        if ver >= 0x11 {
            let _ = r.u16()?;
        }
    } else {
        r.seek(r.pos - 2)?;
    }

    let wtag = r.u16()?;
    if wtag != 0xFFFF {
        bail!("bad ICI root class tag 0x{:04X}", wtag);
    }
    let _ = r.u16()?;
    let cls_len = r.u16()? as usize;
    let cls_bytes = r.take(cls_len)?;
    if cls_bytes != b"CObjectArcMan" {
        bail!(
            "unexpected ICI root class {:?}",
            String::from_utf8_lossy(cls_bytes)
        );
    }
    let cnt = r.count()?;
    if cnt != 0 {
        bail!("unexpected ICI class list count {}", cnt);
    }

    let obj_ver = r.i32()?;
    let _ = r.i32()?;
    let _ = r.u8()?;
    let _ = r.u8()?;
    if obj_ver >= 10 {
        let _ = r.i32()?;
        let _ = r.i32()?;
    }
    let _ = r.i32()?;
    let _ = r.i32()?;
    let _ = r.i32()?;

    let mut toc_offset = 0u32;
    let mut toc_size = 0u32;
    if obj_ver >= 6 {
        toc_offset = r.u32()?;
        toc_size = r.u32()?;
        let _ = r.i32()?;
    }
    if obj_ver >= 8 {
        let _ = r.i32()?;
    }
    let _ = r.string()?;
    let _ = r.i32()?;
    let _ = r.string()?;
    let _ = r.i32()?;
    let _ = r.string()?;
    let _ = r.string()?;
    let _ = r.string()?;
    let _ = r.i32()?;
    let _ = r.string()?;

    let n_str = r.count()?;
    for _ in 0..n_str {
        let _ = r.string()?;
    }
    let _ = r.i32()?;
    let rio_name = if obj_ver >= 9 {
        r.string()?
    } else {
        String::new()
    };
    if obj_ver >= 7 {
        let _ = r.string()?;
    }
    if obj_ver >= 5 {
        let _ = r.i32()?;
    }

    let n_arcs = r.count()?;
    let mut arcs = Vec::new();
    for _ in 0..n_arcs {
        let present = r.u8()?;
        if present != 0 {
            arcs.push(parse_install_source(&mut r)?);
        }
    }

    Ok(IciInfo {
        toc_offset,
        toc_size,
        rio_file_name: rio_name,
        arcs,
    })
}

fn parse_install_source(r: &mut Reader<'_>) -> Result<ArcInfo> {
    let ver = r.u16()?;
    if ver >= 7 {
        let _ = r.i32()?;
        let _ = r.i32()?;
        let _ = r.u8()?;
        let _ = r.string()?;
    }
    for _ in 0..5 {
        let _ = r.string()?;
    }
    let _ = r.i64()?;
    let _ = r.i64()?;
    if ver < 6 {
        let _ = r.i32()?;
        let _ = r.i32()?;
    } else {
        let _ = r.i32()?;
    }
    let rio_name = r.string()?;
    let rio_offset = r.i64()?;
    let rio_size = r.i64()?;
    if ver < 6 {
        let _ = r.i64()?;
    }
    let _ = r.i32()?;
    let _ = r.string()?;
    for _ in 0..5 {
        let _ = r.i32()?;
    }
    let _ = r.string()?;
    let cnt = r.count()?;
    let _ = r.take(cnt * 4)?;
    let block_count = (rio_size + 0xFFFF) >> 16;
    let bitmap_len = ((block_count + 7) >> 3) as usize;
    let _ = r.take(bitmap_len)?;

    Ok(ArcInfo {
        rio_name,
        rio_offset,
        rio_size,
    })
}

#[derive(Debug, Clone)]
pub struct TocNode {
    pub index: usize,
    pub name: String,
    pub class_name: String,
    pub flags: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub has_extent: bool,
    pub global_offset: u64,
    pub extent_size: u32,
    pub schema: i32,
    pub is_root: bool,
}

#[derive(Debug, Clone)]
pub struct TocArchive {
    pub ici: IciInfo,
    pub unit_size: u64,
    pub shift: u32,
    pub toc_phys: u64,
    pub nodes: Vec<TocNode>,
    pub ocean_map: HashMap<u32, usize>,
    pub volume_path: HashMap<String, PathBuf>,
}

enum LoadSlot {
    Other,
    ClassName(String),
}

struct TocParser<'a> {
    r: Reader<'a>,
    field4c: u32,
    load_array: Vec<LoadSlot>,
    ocean_map: HashMap<u32, usize>,
    nodes: Vec<TocNode>,
    object_schema: i32,
    depth: usize,
}

impl<'a> TocParser<'a> {
    fn is_encrypted(&self) -> bool {
        (self.field4c & 4) != 0
    }

    fn read_class(&mut self) -> Result<(String, u32, bool)> {
        let wtag = self.r.u16()?;
        let obj_tag = if wtag == 0x7FFF {
            self.r.u32()?
        } else {
            (u32::from(wtag & 0x8000) << 16) | u32::from(wtag & 0x7FFF)
        };
        if (obj_tag & 0x8000_0000) == 0 {
            return Ok((String::new(), obj_tag, false));
        }
        if wtag == 0xFFFF {
            let schema = self.r.u16()?;
            let name = if (self.field4c & 8) != 0 {
                let ln = self.r.short_count()?;
                let raw = self.r.take(ln)?;
                decode_class_name(raw)
            } else {
                let ln = self.r.u16()? as usize;
                let raw = self.r.take(ln)?;
                String::from_utf8_lossy(raw).into_owned()
            };
            self.object_schema = i32::from(schema);
            self.load_array.push(LoadSlot::ClassName(name.clone()));
            return Ok((name, obj_tag, true));
        }
        let idx = (obj_tag & 0x7FFF_FFFF) as usize;
        if idx == 0 || idx >= self.load_array.len() {
            return Ok((String::new(), idx as u32, false));
        }
        match &self.load_array[idx] {
            LoadSlot::ClassName(s) => Ok((s.clone(), idx as u32, true)),
            LoadSlot::Other => Ok((String::new(), idx as u32, false)),
        }
    }

    fn read_class_ref(&mut self) -> Result<String> {
        let (cls, tag, ok) = self.read_class()?;
        if !ok {
            bail!(
                "expected class ref at 0x{:X}, got tag 0x{:X}",
                self.r.pos,
                tag
            );
        }
        Ok(cls)
    }

    fn read_ctype(&mut self) -> Result<String> {
        let code = self.r.u16()?;
        if code == 0x1E57 {
            return self.read_class_ref();
        }
        if code == 0x2D6B || code == 0x2F1A {
            let _ = self.r.u16()?;
            let ln = self.r.u16()? as usize;
            let b = self.r.take(ln)?;
            return Ok(String::from_utf8_lossy(b).into_owned());
        }
        bail!("unsupported ctype 0x{:04X}", code);
    }

    fn deserialize_class_list(&mut self, root_flags: u32) -> Result<()> {
        if self.is_encrypted() && (root_flags & 0x200) != 0 {
            return Ok(());
        }
        self.depth += 1;
        if self.depth > 64 {
            self.depth -= 1;
            bail!("class list depth overflow");
        }
        let res = (|| {
            let cnt = self.r.count()?;
            for _ in 0..cnt {
                let mut node = TocNode {
                    index: 0,
                    name: "unrefix".to_string(),
                    class_name: String::new(),
                    flags: 0,
                    raw_offset: 0,
                    raw_size: 0,
                    has_extent: false,
                    global_offset: 0,
                    extent_size: 0,
                    schema: 0,
                    is_root: false,
                };
                self.deserialize_node(&mut node)?;
                let idx = self.nodes.len();
                node.index = idx;
                if node.has_extent && self.is_encrypted() {
                    self.ocean_map.entry(node.raw_offset).or_insert(idx);
                }
                self.nodes.push(node);
            }
            Ok(())
        })();
        self.depth -= 1;
        res
    }

    fn deserialize_node(&mut self, node: &mut TocNode) -> Result<()> {
        let flags = self.r.u16()?;
        let cls = match flags & 7 {
            0 => {
                if (flags & 0x8000) != 0 {
                    let _ = self.r.u8()?;
                } else {
                    let _ = self.r.u16()?;
                }
                self.read_class_ref()?
            }
            1 => {
                let _ = self.r.i32()?;
                self.read_ctype()?
            }
            _ => bail!("unsupported node flags 0x{:04X} at 0x{:X}", flags, self.r.pos),
        };
        node.class_name = cls;
        node.schema = self.object_schema;
        node.flags = u32::from(flags);
        if (flags & 8) != 0 {
            let id1 = self.r.u32()?;
            let id2 = self.r.u32()?;
            node.has_extent = true;
            node.raw_offset = id1;
            node.raw_size = id2;
            if self.is_encrypted() {
                node.flags |= 0x100;
            }
        }
        self.deserialize_class_list(node.flags)
    }
}

pub fn load_toc(game_dir: &Path, base_name: &str) -> Result<TocArchive> {
    let ici_path = game_dir.join(format!("{}.rio.ici", base_name));
    let main_rio = game_dir.join(format!("{}.rio", base_name));

    let ici = parse_ici(&ici_path)?;
    let mut f = File::open(&main_rio)
        .with_context(|| format!("open main RIO {}", main_rio.display()))?;
    let file_size = f.metadata()?.len();

    let mut toc_phys = 0u64;
    let mut unit_size = 0u64;
    let mut shift = 0u32;
    let mut found = false;

    for (s, &scale) in [1u64, 2, 4, 8].iter().enumerate() {
        let cand = u64::from(ici.toc_offset) * scale;
        if cand + 4 > file_size {
            continue;
        }
        let mut sig_buf = [0u8; 4];
        if f.seek(SeekFrom::Start(cand)).is_err() || f.read_exact(&mut sig_buf).is_err() {
            continue;
        }
        if u32::from_le_bytes(sig_buf) == ENCRYPTED_SIGNATURE {
            toc_phys = cand;
            unit_size = scale;
            shift = s as u32;
            found = true;
            break;
        }
    }
    if !found {
        bail!("could not find encrypted TOC signature in {}", main_rio.display());
    }

    let mut req = (u64::from(ici.toc_size) * unit_size).max(u64::from(ici.toc_size) + 0x10000);
    if toc_phys + req > file_size {
        req = file_size - toc_phys;
    }
    let mut toc_data = vec![0u8; req as usize];
    f.seek(SeekFrom::Start(toc_phys))?;
    f.read_exact(&mut toc_data)?;

    let mut p = TocParser {
        r: Reader::new(&toc_data),
        field4c: 4,
        load_array: vec![LoadSlot::Other, LoadSlot::Other],
        ocean_map: HashMap::new(),
        nodes: Vec::new(),
        object_schema: 0,
        depth: 0,
    };

    let sig = p.r.u32()?;
    if sig != ENCRYPTED_SIGNATURE {
        bail!("bad TOC sig 0x{:08X}", sig);
    }
    let ver = p.r.u16()?;
    if (0x10..=0x3FFF).contains(&ver) {
        if ver >= 0x11 {
            let fl = p.r.u16()?;
            p.field4c = (p.field4c & 0xFFFF) | (u32::from(fl) << 16);
        }
    } else {
        p.r.seek(p.r.pos - 2)?;
    }
    p.field4c |= 0x0C;

    let _root_cls = p.read_class_ref()?;
    p.load_array.push(LoadSlot::Other); // root
    p.deserialize_class_list(0x180).context("TOC class list")?;

    for n in &mut p.nodes {
        if n.has_extent {
            n.global_offset = decode_extent_offset(n.raw_offset, unit_size);
            n.extent_size = decode_extent_size(n.raw_size);
        }
    }

    let mut vol_paths = HashMap::new();
    for (i, arc) in ici.arcs.iter().enumerate() {
        if i == 0 {
            vol_paths.insert(arc.rio_name.clone(), main_rio.clone());
        } else {
            let norm = arc.rio_name.replace('\\', "/");
            let fname = Path::new(&norm)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let cand = game_dir.join(fname);
            if cand.exists() {
                vol_paths.insert(arc.rio_name.clone(), cand);
            }
        }
    }

    Ok(TocArchive {
        ici,
        unit_size,
        shift,
        toc_phys,
        nodes: p.nodes,
        ocean_map: p.ocean_map,
        volume_path: vol_paths,
    })
}
