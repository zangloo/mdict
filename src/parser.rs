use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;
use adler32::RollingAdler32;
use byteorder::{BE, ByteOrder, LE, ReadBytesExt};
use compress::zlib;
use encoding_rs::{Encoding, UTF_16LE, UTF_8};
use regex::Regex;
use ripemd::{Digest, Ripemd128, Ripemd128Core};
use salsa20::Salsa20;
use salsa20::cipher::{KeyIvInit, StreamCipher};
use salsa20::cipher::crypto_common::Output;

use crate::{Error, mdx::Mdx, Result};
use crate::mdx::{BlockEntryInfo, KeyBlock, KeyEntry, Reader, RecordOffset, WordDefinition};

#[derive(Debug)]
struct KeyBlockHeader {
	// block_num: usize,
	// entry_num: usize,
	// decompressed_size: usize,
	block_info_size: usize,
	key_block_size: usize,
}

#[derive(Debug)]
enum Version {
	V1,
	V2,
}

impl Version {
	#[inline]
	fn read_number(&self, reader: &mut Reader) -> Result<usize>
	{
		let number = match self {
			Version::V1 => reader.read_u32::<BE>()? as usize,
			Version::V2 => reader.read_u64::<BE>()? as usize,
		};
		Ok(number)
	}
	#[inline]
	#[allow(unused)]
	fn byte_number(&self, data: &[u8]) -> (usize, usize)
	{
		match self {
			Version::V1 => (BE::read_u32(data) as usize, 4),
			Version::V2 => (BE::read_u64(data) as usize, 8),
		}
	}
}

fn read_keys(s: &str) -> HashMap<String, String>
{
	let re = Regex::new(r#"(\w+)="((.|\r\n|[\r\n])*?)""#).unwrap();
	let mut attrs = HashMap::new();
	for cap in re.captures_iter(s) {
		attrs.insert(cap[1].to_string(), cap[2].to_string());
	}
	attrs
}

#[derive(Debug)]
struct Header {
	version: Version,
	encrypted: u8,
	encoding: &'static Encoding,
}

#[inline]
fn read_buf(reader: &mut impl Read, len: usize) -> Result<Vec<u8>>
{
	let mut buf = vec![0; len];
	reader.read_exact(&mut buf)?;
	Ok(buf)
}

#[inline]
fn check_adler32(data: &[u8], checksum: u32) -> Result<()>
{
	if RollingAdler32::from_buffer(data).hash() != checksum {
		return Err(Error::InvalidCheckSum("header"));
	}
	Ok(())
}

fn read_header(reader: &mut Reader, default_encoding: &'static Encoding) -> Result<Header>
{
	let bytes = reader.read_u32::<BE>()?;
	let info_buf = read_buf(reader, bytes as usize)?;
	let checksum = reader.read_u32::<LE>()?;
	check_adler32(&info_buf, checksum)?;

	let info = UTF_16LE.decode(&info_buf).0;
	let attrs = read_keys(&info);

	let version_str = attrs
		.get("GeneratedByEngineVersion")
		.ok_or(Error::NoVersion)?
		.trim();
	let version = version_str[0..1]
		.parse::<u8>()
		.or(Err(Error::InvalidVersion(version_str.to_owned())))?;

	let version = match version {
		1 => Version::V1,
		2 => Version::V2,
		3 |
		_ => return Err(Error::UnsupportedVersion(version)),
	};

	let encrypted = attrs
		.get("Encrypted")
		.and_then(|x| match x == "Yes" {
			true => Some(1_u8),
			false => x.as_str().parse().ok(),
		})
		.unwrap_or(0);

	let encoding = if let Some(encoding) = attrs.get("Encoding") {
		if encoding.is_empty() {
			default_encoding
		} else {
			Encoding::for_label(encoding.as_bytes())
				.ok_or(Error::InvalidEncoding(encoding.clone()))?
		}
	} else {
		default_encoding
	};
	Ok(Header {
		version,
		encrypted,
		encoding,
	})
}

fn read_key_block_header_v1(reader: &mut Reader) -> Result<KeyBlockHeader>
{
	let buf = read_buf(reader, 16)?;
	// let block_num = BE::read_u32(&buf[0..4]);
	// let entry_num = BE::read_u32(&buf[4..8]);
	let block_info_size = BE::read_u32(&buf[8..12]);
	let key_block_size = BE::read_u32(&buf[12..16]);

	Ok(KeyBlockHeader {
		// block_num: block_num as usize,
		// entry_num: entry_num as usize,
		// decompressed_size: block_info_size as usize,
		block_info_size: block_info_size as usize,
		key_block_size: key_block_size as usize,
	})
}

fn read_key_block_header_v2(reader: &mut Reader) -> Result<KeyBlockHeader>
{
	let buf = read_buf(reader, 40)?;
	let checksum = reader.read_u32::<BE>()?;
	check_adler32(&buf, checksum)?;

	// let block_num = BE::read_u64(&buf[0..8]);
	// let entry_num = BE::read_u64(&buf[8..16]);
	// let decompressed_size = BE::read_u64(&buf[16..24]);
	let block_info_size = BE::read_u64(&buf[24..32]);
	let key_block_size = BE::read_u64(&buf[32..40]);

	Ok(KeyBlockHeader {
		// block_num: block_num as usize,
		// entry_num: entry_num as usize,
		// decompressed_size: decompressed_size as usize,
		block_info_size: block_info_size as usize,
		key_block_size: key_block_size as usize,
	})
}

fn fast_decrypt(encrypted: &[u8], key: &[u8]) -> Vec<u8>
{
	let mut buf = Vec::from(encrypted);
	let mut prev = 0x36;
	for i in 0..buf.len() {
		let mut t = buf[i] >> 4 | buf[i] << 4;
		t = t ^ prev ^ (i as u8) ^ key[i % key.len()];
		prev = buf[i];
		buf[i] = t;
	}
	buf
}

fn read_key_block_infos(reader: &mut Reader, size: usize, header: &Header) -> Result<Vec<BlockEntryInfo>>
{
	let buf = read_buf(reader, size)?;
	//decrypt
	let key_block_info = match header.version {
		Version::V1 => buf,
		Version::V2 => {
			if buf[0..4] != [2, 0, 0, 0] {
				return Err(Error::InvalidData);
			}
			let checksum = BE::read_u32(&buf[4..8]);
			let mut info = vec![];
			if header.encrypted == 2 {
				let mut v = Vec::from(&buf[4..8]);
				let value: u32 = 0x3695;
				v.extend_from_slice(&value.to_le_bytes());
				let mut md = Ripemd128::default();
				md.update(v);
				let key = md.finalize();
				let decrypted = fast_decrypt(&buf[8..], key.as_slice());
				zlib::Decoder::new(BufReader::new(decrypted.as_slice()))
					.read_to_end(&mut info)?;
			} else {
				zlib::Decoder::new(&buf[8..])
					.read_to_end(&mut info)?;
			}
			check_adler32(&info, checksum)?;
			info
		}
	};
	let key_blocks = decode_key_blocks(&key_block_info, header)?;
	Ok(key_blocks)
}

fn decode_key_blocks(data: &[u8], header: &Header)
	-> Result<Vec<BlockEntryInfo>>
{
	#[inline]
	fn read_size(data: &[u8], header: &Header) -> (usize, usize)
	{
		match header.version {
			Version::V1 => (BE::read_u32(&data[0..4]) as usize, 4),
			Version::V2 => (BE::read_u64(&data[0..8]) as usize, 8),
		}
	}
	#[inline]
	fn read_num_bytes(data: &[u8], header: &Header) -> (usize, usize)
	{
		match header.version {
			Version::V1 => (data[0] as usize, 1),
			Version::V2 => (BE::read_u16(&data[0..2]) as usize, 2)
		}
	}
	#[inline]
	fn text_bytes(header: &Header, bytes: usize) -> usize
	{
		let text_size = match header.version {
			Version::V1 => bytes,
			Version::V2 => bytes + 1,
		};
		if header.encoding == encoding_rs::UTF_8 {
			text_size
		} else {
			text_size * 2
		}
	}
	#[inline]
	#[allow(unused)]
	fn extract_text(data: &[u8], header: &Header, bytes: usize) -> (String, usize)
	{
		let text_size = match header.version {
			Version::V1 => bytes,
			Version::V2 => bytes + 1,
		};
		let bytes = if header.encoding == encoding_rs::UTF_8 {
			text_size
		} else {
			text_size * 2
		};
		let text = header.encoding
			.decode(&data[..text_size])
			.0
			.trim_matches(char::from(0))
			.to_string();
		(text, bytes)
	}

	let mut key_block_info_list = vec![];
	let mut slice = data;
	while !slice.is_empty() {
		let (_num_entries, delta) = read_size(slice, header);
		slice = &slice[delta..];
		let (bytes, delta) = read_num_bytes(slice, header);
		slice = &slice[delta..];
		let delta = text_bytes(header, bytes);
		slice = &slice[delta..];
		let (bytes, delta) = read_num_bytes(slice, header);
		slice = &slice[delta..];
		let delta = text_bytes(header, bytes);
		slice = &slice[delta..];
		let (compressed_size, delta) = read_size(slice, header);
		slice = &slice[delta..];
		let (decompressed_size, delta) = read_size(slice, header);
		slice = &slice[delta..];
		key_block_info_list.push(BlockEntryInfo {
			compressed_size,
			decompressed_size,
		});
	}
	Ok(key_block_info_list)
}

fn decode_block(slice: &[u8], compressed_size: usize, decompressed_size: usize) -> Result<Vec<u8>>
{
	#[inline]
	fn make_key(data: &[u8]) -> Output<Ripemd128Core>
	{
		let mut md = Ripemd128::default();
		md.update(&data[4..8]);
		md.finalize()
	}

	let enc = LE::read_u32(&slice[0..4]);
	let checksum_bytes = &slice[4..8];
	let checksum = BE::read_u32(checksum_bytes);
	let encryption_method = (enc >> 4) & 0xf;
	// let encryption_size = (enc >> 8) & 0xff;
	let compress_method = enc & 0xf;

	let encrypted = &slice[8..compressed_size];
	let compressed: Vec<u8> = match encryption_method {
		0 => Vec::from(encrypted),
		1 => fast_decrypt(encrypted, make_key(checksum_bytes).as_slice()),
		2 => {
			let mut decrypt = Vec::from(encrypted);
			let mut cipher = Salsa20::new(make_key(checksum_bytes).as_slice().into(), &[0; 8].into());
			cipher.apply_keystream(&mut decrypt);
			decrypt
		}
		_ => return Err(Error::InvalidEncryptMethod(encryption_method)),
	};

	let decompressed = match compress_method {
		0 => compressed,
		1 => minilzo::decompress(&compressed, decompressed_size)
			.or(Err(Error::InvalidData))?,
		2 => {
			let mut v = vec![];
			zlib::Decoder::new(&compressed[..]).read_to_end(&mut v)
				.or(Err(Error::InvalidData))?;
			v
		}
		_ => return Err(Error::InvalidCompressMethod(compress_method)),
	};

	check_adler32(&decompressed, checksum)?;
	Ok(decompressed)
}

fn read_key_blocks(reader: &mut Reader, size: usize, header: &Header,
	entry_infos: Vec<BlockEntryInfo>, ) -> Result<Vec<KeyBlock>>
{
	#[inline]
	fn decode_text<'a>(header: &Header, entries_slice: &'a [u8]) -> Result<(Cow<'a, str>, usize)>
	{
		let (idx, delta) = if header.encoding == UTF_16LE {
			let mut found = None;
			for i in (0..entries_slice.len()).step_by(2) {
				if entries_slice[i] == 0 && entries_slice[i + 1] == 0 {
					found = Some(i);
					break;
				}
			}
			if let Some(idx) = found {
				(idx, 2)
			} else {
				return Err(Error::InvalidData);
			}
		} else if header.encoding == UTF_8 {
			let idx = entries_slice
				.iter()
				.position(|b| *b == 0)
				.ok_or(Error::InvalidData)?;
			(idx, 1)
		} else {
			return Err(Error::InvalidEncoding(header.encoding.name().to_owned()));
		};

		let text = header.encoding.decode(&entries_slice[..idx]).0;
		Ok((text, idx + delta))
	}

	let data = read_buf(reader, size)?;

	let mut blocks = vec![];
	let mut slice = data.as_slice();
	for info in entry_infos {
		let decompressed = decode_block(
			slice, info.compressed_size, info.decompressed_size)?;
		slice = &slice[info.compressed_size..];

		let mut entries_slice = decompressed.as_slice();
		let mut entries = vec![];
		while !entries_slice.is_empty() {
			let (offset, delta) = match header.version {
				Version::V1 => (BE::read_u32(entries_slice) as usize, 4),
				Version::V2 => (BE::read_u64(entries_slice) as usize, 8),
			};
			entries_slice = &entries_slice[delta..];
			let (text, idx) = decode_text(header, entries_slice)?;

			entries.push(KeyEntry { offset, text: text.to_string() });
			entries_slice = &entries_slice[idx..];
		}
		blocks.push(KeyBlock {
			entries,
		});
	}

	Ok(blocks)
}

fn read_record_blocks(reader: &mut Reader, header: &Header)
	-> Result<Vec<BlockEntryInfo>>
{
	let version = &header.version;
	let num_records = version.read_number(reader)?;
	let _num_entries = version.read_number(reader)?;
	let _record_info_size = version.read_number(reader)?;
	let _record_data_size = version.read_number(reader)?;
	let mut records = vec![];
	for _i in 0..num_records {
		let compressed_size = version.read_number(reader)?;
		let decompressed_size = version.read_number(reader)?;
		records.push(BlockEntryInfo { compressed_size, decompressed_size })
	}
	Ok(records)
}

pub(crate) fn load(mut reader: Reader, cwd: PathBuf) -> Result<Mdx>
{
	let header = read_header(&mut reader, UTF_16LE)?;
	let key_block_header = match &header.version {
		Version::V1 => read_key_block_header_v1(&mut reader)?,
		Version::V2 => read_key_block_header_v2(&mut reader)?,
	};
	let key_block_infos = read_key_block_infos(
		&mut reader,
		key_block_header.block_info_size,
		&header)?;

	let key_blocks = read_key_blocks(
		&mut reader,
		key_block_header.key_block_size,
		&header,
		key_block_infos)?;

	let records_info = read_record_blocks(
		&mut reader,
		&header)?;

	let record_block_offset = reader.stream_position()?;

	Ok(Mdx {
		encoding: header.encoding,
		encrypted: header.encrypted,
		key_blocks,
		records_info,
		reader,
		record_block_offset,
		record_cache: HashMap::new(),
		cwd,
	})
}

impl PartialEq<str> for KeyBlock {
	fn eq(&self, word: &str) -> bool {
		self.partial_cmp(word)
			.map_or(false, |o| matches!(o, Ordering::Equal))
	}
}

impl PartialOrd<str> for KeyBlock {
	fn partial_cmp(&self, word: &str) -> Option<Ordering> {
		if self.entries.first()?.text.as_str() > word {
			Some(Ordering::Greater)
		} else if self.entries.last()?.text.as_str() < word {
			Some(Ordering::Less)
		} else {
			Some(Ordering::Equal)
		}
	}
}

impl PartialEq<str> for KeyEntry {
	fn eq(&self, word: &str) -> bool
	{
		self.partial_cmp(word)
			.map_or(false, |o| matches!(o, Ordering::Equal))
	}
}

impl PartialOrd<str> for KeyEntry {
	fn partial_cmp(&self, word: &str) -> Option<Ordering>
	{
		self.text.as_str().partial_cmp(word)
	}
}

fn bisect_search<'a, C: ?Sized, T: PartialOrd<C>>(mut slice: &'a [T], word: &C)
	-> Option<&'a T>
{
	while !slice.is_empty() {
		let len = slice.len();
		let idx = len >> 1;
		let current = &slice[idx];
		match current.partial_cmp(word) {
			None => break,
			Some(Ordering::Greater) => slice = &slice[..idx],
			Some(Ordering::Equal) => return Some(current),
			Some(Ordering::Less) => {
				let next = idx + 1;
				if next >= len {
					break;
				} else {
					slice = &slice[next..]
				}
			}
		}
	}
	None
}

fn record_offset(records_info: &Vec<BlockEntryInfo>, entry: &KeyEntry) -> Option<RecordOffset> {
	let mut block_offset = 0;
	let mut buf_offset = 0;
	for info in records_info {
		if entry.offset < block_offset + info.decompressed_size {
			return Some(RecordOffset {
				buf_offset,
				block_offset: entry.offset - block_offset,
				record_size: info.compressed_size,
				decomp_size: info.decompressed_size,
			});
		} else {
			block_offset += info.decompressed_size;
			buf_offset += info.compressed_size;
		}
	}
	None
}

fn find_definition(mdx: &mut Mdx, offset: RecordOffset) -> Result<String>
{
	fn find(sliec: &[u8], encoding: &'static Encoding) -> Result<String>
	{
		let idx = sliec.iter().position(|b| *b == 0)
			.ok_or(Error::InvalidData)?;
		let text = encoding.decode(&sliec[..idx - 1]).0.to_string();
		Ok(text)
	}
	match mdx.record_cache.entry(offset.buf_offset) {
		Entry::Occupied(o) => find(&o.get()[offset.block_offset..], mdx.encoding),
		Entry::Vacant(v) => {
			let reader = &mut mdx.reader;
			reader.seek(SeekFrom::Start(mdx.record_block_offset + offset.buf_offset as u64))?;
			let data = read_buf(reader, offset.record_size)?;
			let decompressed = decode_block(&data, offset.record_size, offset.decomp_size)?;
			let decompressed = v.insert(decompressed);
			find(&decompressed[offset.block_offset..], mdx.encoding)
		}
	}
}

pub(crate) fn lookup_record<'a>(mdx: &mut Mdx, word: &'a str) -> Result<Option<WordDefinition<'a>>>
{
	if let Some(key_block) = bisect_search(&mdx.key_blocks, word) {
		if let Some(entry) = bisect_search(&key_block.entries, word) {
			if let Some(offset) = record_offset(&mdx.records_info, entry) {
				let definition = find_definition(mdx, offset)?;
				return Ok(Some(WordDefinition { key: word, definition }));
			}
		}
	}
	Ok(None)
}