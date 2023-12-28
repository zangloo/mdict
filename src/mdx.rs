use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use encoding_rs::{Encoding, UTF_16LE};
use crate::parser::{decode_slice_string, load, lookup_record};
use crate::{Error, Result};

pub type Reader = BufReader<File>;

pub struct MDict {
	pub(crate) mdx: Mdx,
	pub(crate) resources: Vec<Mdx>,
}

pub struct Mdx {
	pub(crate) encoding: &'static Encoding,
	pub(crate) title: String,
	#[allow(unused)]
	pub(crate) encrypted: u8,
	pub(crate) key_blocks: Vec<KeyBlock>,
	pub(crate) records_info: Vec<BlockEntryInfo>,
	pub(crate) reader: Reader,
	pub(crate) record_block_offset: u64,
	pub(crate) record_cache: HashMap<usize, Vec<u8>>,
}

#[derive(Debug)]
pub(crate) struct KeyBlock {
	pub(crate) entries: Vec<KeyEntry>,
}

#[derive(Debug)]
pub(crate) struct KeyEntry {
	pub(crate) offset: usize,
	pub(crate) text: String,
}

#[derive(Debug)]
pub(crate) struct BlockEntryInfo {
	pub(crate) compressed_size: usize,
	pub(crate) decompressed_size: usize,
}

#[derive(Debug)]
pub(crate) struct RecordOffset {
	pub(crate) buf_offset: usize,
	pub(crate) block_offset: usize,
	pub(crate) record_size: usize,
	pub(crate) decomp_size: usize,
}

#[derive(Debug)]
pub struct WordDefinition<'a> {
	pub key: &'a str,
	pub definition: String,
}

impl MDict {
	pub fn builder(path: impl Into<PathBuf>) -> MDictBuilder
	{
		MDictBuilder {
			path: path.into(),
			cache_definition: false,
			cache_resource: false,
		}
	}

	pub fn from(path: impl Into<PathBuf>) -> Result<Self>
	{
		MDict::builder(path).build()
	}

	pub fn lookup<'a>(&mut self, word: &'a str) -> Result<Option<WordDefinition<'a>>>
	{
		let encoding = self.mdx.encoding;
		if let Some(slice) = lookup_record(&mut self.mdx, word)? {
			let definition = decode_slice_string(slice, encoding)?.0.to_string();
			Ok(Some(WordDefinition { key: word, definition }))
		} else {
			Ok(None)
		}
	}

	pub fn get_resource(&mut self, path: &str) -> Result<Option<&[u8]>>
	{
		for mdx in &mut self.resources {
			if let Some(slice) = lookup_record(mdx, path)? {
				return Ok(Some(slice));
			}
		}
		Ok(None)
	}

	pub fn title(&self) -> &str
	{
		&self.mdx.title
	}
}

pub struct MDictBuilder {
	path: PathBuf,
	cache_definition: bool,
	cache_resource: bool,
}

impl MDictBuilder {
	pub fn cache_definition(mut self, cache: bool) -> Self
	{
		self.cache_definition = cache;
		self
	}
	pub fn cache_resource(mut self, cache: bool) -> Self
	{
		self.cache_resource = cache;
		self
	}
	pub fn build(self) -> Result<MDict>
	{
		let path = self.path;
		let f = File::open(&path)?;
		let reader = BufReader::new(f);
		let cwd = path.parent()
			.ok_or_else(|| Error::InvalidPath(path.clone()))?
			.canonicalize()?;
		let mdx = load(reader, UTF_16LE)?;
		let filename = path.file_stem()
			.ok_or_else(|| Error::InvalidPath(path.clone()))?
			.to_str()
			.ok_or_else(|| Error::InvalidPath(path.clone()))?;
		let resources = load_resources(&cwd, filename)?;
		Ok(MDict {
			mdx,
			resources,
		})
	}
}

fn load_resources(cwd: &PathBuf, name: &str) -> Result<Vec<Mdx>>
{
	let mut resources = vec![];
	// <filename>.mdd first
	let path = cwd.join(format!("{}.mdd", name));
	if !path.exists() {
		return Ok(resources);
	}
	let f = File::open(&path)?;
	let reader = BufReader::new(f);
	resources.push(load(reader, UTF_16LE)?);

	// filename.n.mdd then
	let mut i = 1;
	loop {
		let path = cwd.join(format!("{}.{}.mdd", name, i));
		if !path.exists() {
			break;
		}
		let f = File::open(&path)?;
		let reader = BufReader::new(f);
		resources.push(load(reader, UTF_16LE)?);
		i += 1;
	}
	Ok(resources)
}
