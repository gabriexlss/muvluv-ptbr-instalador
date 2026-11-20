use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::crsa::parse_crsa_record;
use super::crypto::{
    decode_extent_offset, decode_extent_size, encode_extent_offset, encode_extent_size, round_up,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuoRedirect {
    pub source_raw_offset: u32,
    pub ruo_raw_offset: u32,
    pub replacement_raw_size: u32,
}

#[derive(Debug, Clone)]
pub struct RuoArchive {
    pub path: PathBuf,
    pub unit_size: u64,
    pub file_size: u64,
    pub footer_offset: u64,
    pub redirects: Vec<RuoRedirect>,
    pub redirect_by_src: HashMap<u32, RuoRedirect>,
}

pub fn read_ruo_footer(path: &Path, unit_size: u64) -> Result<RuoArchive> {
    let mut f = File::open(path).with_context(|| format!("open RUO {}", path.display()))?;
    let file_size = f.metadata()?.len();
    if file_size < 4 {
        bail!("RUO {} too short ({} bytes)", path.display(), file_size);
    }

    let mut count_buf = [0u8; 4];
    f.seek(SeekFrom::Start(file_size - 4))?;
    f.read_exact(&mut count_buf)?;
    let count = u32::from_le_bytes(count_buf);
    if count >= 0x20000 {
        bail!("RUO {} count 0x{:X} >= 0x20000", path.display(), count);
    }

    let table_size = u64::from(count) * 12;
    if file_size < 4 + table_size {
        bail!("RUO {} table overflows file", path.display());
    }
    let footer_offset = file_size - 4 - table_size;

    let mut table = vec![0u8; table_size as usize];
    f.seek(SeekFrom::Start(footer_offset))?;
    f.read_exact(&mut table)?;

    let mut redirects = Vec::with_capacity(count as usize);
    let mut by_src = HashMap::with_capacity(count as usize);

    for i in 0..(count as usize) {
        let off = i * 12;
        let r = RuoRedirect {
            source_raw_offset: u32::from_le_bytes(table[off..off + 4].try_into().unwrap()),
            ruo_raw_offset: u32::from_le_bytes(table[off + 4..off + 8].try_into().unwrap()),
            replacement_raw_size: u32::from_le_bytes(table[off + 8..off + 12].try_into().unwrap()),
        };
        let dest = decode_extent_offset(r.ruo_raw_offset, unit_size);
        let sz = u64::from(decode_extent_size(r.replacement_raw_size));
        if dest + sz > footer_offset {
            bail!(
                "RUO {} redirect[{}] extent 0x{:X}+0x{:X} overlaps footer 0x{:X} (unitSize={})",
                path.display(),
                i,
                dest,
                sz,
                footer_offset,
                unit_size
            );
        }
        redirects.push(r);
        by_src.insert(r.source_raw_offset, r);
    }

    Ok(RuoArchive {
        path: path.to_path_buf(),
        unit_size,
        file_size,
        footer_offset,
        redirects,
        redirect_by_src: by_src,
    })
}

impl RuoArchive {
    pub fn read_record(&self, src_raw_offset: u32) -> Result<Option<Vec<u8>>> {
        let Some(red) = self.redirect_by_src.get(&src_raw_offset) else {
            return Ok(None);
        };
        let dest = decode_extent_offset(red.ruo_raw_offset, self.unit_size);
        let sz = decode_extent_size(red.replacement_raw_size) as usize;
        let mut f = File::open(&self.path)?;
        f.seek(SeekFrom::Start(dest))?;
        let mut buf = vec![0u8; sz];
        f.read_exact(&mut buf)?;
        Ok(Some(buf))
    }

    pub fn read_record_from_file(
        &self,
        f: &mut File,
        src_raw_offset: u32,
    ) -> Result<Option<Vec<u8>>> {
        let Some(red) = self.redirect_by_src.get(&src_raw_offset) else {
            return Ok(None);
        };
        let dest = decode_extent_offset(red.ruo_raw_offset, self.unit_size);
        let sz = decode_extent_size(red.replacement_raw_size) as usize;
        f.seek(SeekFrom::Start(dest))?;
        let mut buf = vec![0u8; sz];
        f.read_exact(&mut buf)?;
        Ok(Some(buf))
    }
}

#[derive(Debug, Clone)]
pub struct RuoReplacement {
    pub source_raw_offset: u32,
    pub record: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuoBuildReport {
    pub output_path: String,
    pub base_ruo_path: String,
    pub unit_size: u64,
    pub inherited_data_size: u64,
    pub inherited_redirects: usize,
    pub replaced_count: usize,
    pub appended_new_redirects: usize,
    pub final_redirect_count: usize,
    pub final_footer_offset: u64,
    pub final_file_size: u64,
    pub output_sha256: String,
    pub footer_readback_ok: bool,
}

struct HashWriter<W: Write> {
    inner: W,
    hasher: Sha256,
}

impl<W: Write> HashWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    fn into_parts(mut self) -> Result<(W, String)> {
        self.inner.flush()?;
        let digest = hex::encode(self.hasher.finalize());
        Ok((self.inner, digest))
    }
}

impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn abs_path_str(p: &Path) -> Result<String> {
    if p.is_absolute() {
        Ok(p.to_string_lossy().into_owned())
    } else {
        Ok(std::env::current_dir()?.join(p).to_string_lossy().into_owned())
    }
}

fn atomic_replace(tmp_path: &Path, output_path: &Path) -> Result<()> {
    // On Windows, antivirus or indexing may briefly lock the file; retry a few times.
    let mut last_err = None;
    for attempt in 0..5 {
        match fs::rename(tmp_path, output_path) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = Some(e);
                #[cfg(windows)]
                {
                    if output_path.exists() {
                        let _ = fs::remove_file(output_path);
                    }
                }
                if attempt < 4 {
                    std::thread::sleep(std::time::Duration::from_millis(80 * (attempt + 1)));
                }
            }
        }
    }
    Err(anyhow::anyhow!(
        "failed to move {} -> {}: {:?}",
        tmp_path.display(),
        output_path.display(),
        last_err
    ))
}

/// Copies base_ruo's inherited data region byte-for-byte into `<output_path>.tmp`,
/// appends replacement records aligned to unit_size, updates matching redirects in-place
/// (preserving the exact original redirect order), writes the footer, re-opens `.tmp` from disk
/// to verify footer + every replaced CRsa byte-for-byte + `parse_crsa_record`, and ONLY THEN
/// atomically swaps `.tmp` -> `output_path`.
pub fn build_cumulative_ruo<F>(
    base_ruo_path: &Path,
    output_path: &Path,
    unit_size: u64,
    replacements: &[RuoReplacement],
    mut on_copy_progress: F,
) -> Result<RuoBuildReport>
where
    F: FnMut(u64, u64),
{
    let abs_base = fs::canonicalize(base_ruo_path)
        .unwrap_or_else(|_| PathBuf::from(abs_path_str(base_ruo_path).unwrap_or_default()));
    let abs_out = PathBuf::from(abs_path_str(output_path)?);
    if abs_base == abs_out {
        bail!(
            "refusing to overwrite base RUO in place: {}",
            abs_out.display()
        );
    }

    let base = read_ruo_footer(base_ruo_path, unit_size).context("read base RUO")?;

    let mut seen_rep = HashSet::with_capacity(replacements.len());
    for rep in replacements {
        if !seen_rep.insert(rep.source_raw_offset) {
            bail!(
                "duplicate replacement for source 0x{:08X}",
                rep.source_raw_offset
            );
        }
    }

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = PathBuf::from(format!("{}.tmp", output_path.display()));
    if tmp_path.exists() {
        let _ = fs::remove_file(&tmp_path);
    }

    let build_result: Result<(RuoBuildReport, Vec<RuoRedirect>, u64)> = (|| {
        let out_file = File::create(&tmp_path)
            .with_context(|| format!("create temp RUO {}", tmp_path.display()))?;
        let mut hw = HashWriter::new(BufWriter::with_capacity(1024 * 1024, out_file));

        // 1. Stream inherited data region [0 .. base.footer_offset)
        let mut in_file = File::open(base_ruo_path)?;
        let mut remaining = base.footer_offset;
        let mut copied_total: u64 = 0;
        let mut copy_buf = vec![0u8; 1024 * 1024];
        while remaining > 0 {
            let want = (remaining as usize).min(copy_buf.len());
            let n = in_file.read(&mut copy_buf[..want])?;
            if n == 0 {
                bail!(
                    "short copy of inherited RUO data: {} != {}",
                    copied_total,
                    base.footer_offset
                );
            }
            hw.write_all(&copy_buf[..n])?;
            remaining -= n as u64;
            copied_total += n as u64;
            on_copy_progress(copied_total, base.footer_offset);
        }
        drop(in_file);

        let mut cur_off = base.footer_offset;

        // Copy redirect slice and map source -> index to preserve exact order
        let mut redirects = base.redirects.clone();
        let mut idx_by_src = HashMap::with_capacity(redirects.len());
        for (i, r) in redirects.iter().enumerate() {
            idx_by_src.insert(r.source_raw_offset, i);
        }

        // 2. Append replacement records aligned to unit_size
        let mut replaced_count = 0usize;
        let mut appended_new = 0usize;
        let zeros = vec![0u8; unit_size as usize];

        for rep in replacements {
            let aligned = round_up(cur_off, unit_size);
            if aligned > cur_off {
                hw.write_all(&zeros[..(aligned - cur_off) as usize])?;
                cur_off = aligned;
            }
            let dest = cur_off;
            hw.write_all(&rep.record)?;
            cur_off += rep.record.len() as u64;

            let padded_end = round_up(cur_off, unit_size);
            if padded_end > cur_off {
                hw.write_all(&zeros[..(padded_end - cur_off) as usize])?;
                cur_off = padded_end;
            }

            let raw_off = encode_extent_offset(dest, unit_size)?;
            let raw_sz = encode_extent_size(u32::try_from(rep.record.len())?)?;
            let new_red = RuoRedirect {
                source_raw_offset: rep.source_raw_offset,
                ruo_raw_offset: raw_off,
                replacement_raw_size: raw_sz,
            };
            if let Some(&idx) = idx_by_src.get(&rep.source_raw_offset) {
                redirects[idx] = new_red;
                replaced_count += 1;
            } else {
                idx_by_src.insert(rep.source_raw_offset, redirects.len());
                redirects.push(new_red);
                appended_new += 1;
            }
        }

        if redirects.len() >= 0x20000 {
            bail!(
                "redirect count 0x{:X} exceeds loader limit 0x20000",
                redirects.len()
            );
        }

        // 3. Write footer table + count
        let footer_off = cur_off;
        let mut table = Vec::with_capacity(redirects.len() * 12 + 4);
        for r in &redirects {
            table.extend_from_slice(&r.source_raw_offset.to_le_bytes());
            table.extend_from_slice(&r.ruo_raw_offset.to_le_bytes());
            table.extend_from_slice(&r.replacement_raw_size.to_le_bytes());
        }
        table.extend_from_slice(&(redirects.len() as u32).to_le_bytes());
        hw.write_all(&table)?;
        cur_off += table.len() as u64;

        let (buf_writer, output_sha256) = hw.into_parts()?;
        let out_file = buf_writer
            .into_inner()
            .map_err(|e| anyhow::anyhow!("flush temp RUO: {}", e))?;
        out_file.sync_all()?;
        drop(out_file);

        // 4. MANDATORY readback verification directly on `.tmp` BEFORE atomic swap
        let verified = read_ruo_footer(&tmp_path, unit_size).context("RUO .tmp footer readback")?;
        if verified.footer_offset != footer_off || verified.redirects.len() != redirects.len() {
            bail!(
                "RUO footer readback mismatch: off 0x{:X}!=0x{:X} count {}!={}",
                verified.footer_offset,
                footer_off,
                verified.redirects.len(),
                redirects.len()
            );
        }
        for (i, r) in redirects.iter().enumerate() {
            if verified.redirects[i] != *r {
                bail!("RUO redirect[{}] readback mismatch", i);
            }
        }

        let mut verify_file = File::open(&tmp_path)?;
        for rep in replacements {
            let disk_rec = verified
                .read_record_from_file(&mut verify_file, rep.source_raw_offset)?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "output .tmp RUO missing replaced CRsa 0x{:08X}",
                        rep.source_raw_offset
                    )
                })?;
            if disk_rec != rep.record {
                bail!(
                    "output .tmp RUO CRsa 0x{:08X} bytes mismatch on disk",
                    rep.source_raw_offset
                );
            }
            parse_crsa_record(&disk_rec).with_context(|| {
                format!(
                    "output .tmp RUO CRsa 0x{:08X} failed final parse",
                    rep.source_raw_offset
                )
            })?;
        }
        drop(verify_file);

        let report = RuoBuildReport {
            output_path: abs_out.to_string_lossy().into_owned(),
            base_ruo_path: abs_base.to_string_lossy().into_owned(),
            unit_size,
            inherited_data_size: base.footer_offset,
            inherited_redirects: base.redirects.len(),
            replaced_count,
            appended_new_redirects: appended_new,
            final_redirect_count: redirects.len(),
            final_footer_offset: footer_off,
            final_file_size: cur_off,
            output_sha256,
            footer_readback_ok: true,
        };

        Ok((report, redirects, footer_off))
    })();

    match build_result {
        Ok((report, _redirects, _footer_off)) => {
            atomic_replace(&tmp_path, output_path)?;
            Ok(report)
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}
