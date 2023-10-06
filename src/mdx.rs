use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use encoding_rs::Encoding;
use crate::parser::{load, lookup_record};
use crate::Result;

pub type Reader = BufReader<File>;

pub struct Mdx {
	pub(crate) encoding: &'static Encoding,
	#[allow(unused)]
	pub(crate) encrypted: u8,
	pub(crate) key_blocks: Vec<KeyBlock>,
	pub(crate) records_info: Vec<BlockEntryInfo>,
	pub(crate) reader: Reader,
	pub(crate) record_block_offset: u64,
	pub(crate) record_cache: HashMap<usize, Vec<u8>>,
	pub(crate) cwd: PathBuf,
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

impl Mdx {
	pub fn from(path: impl Into<PathBuf>) -> Result<Self>
	{
		let path = path.into();
		let f = File::open(&path)?;
		let reader = BufReader::new(f);
		let cwd = path.parent().unwrap().canonicalize()?;
		let mdx = load(reader, cwd)?;
		Ok(mdx)
	}

	pub fn lookup<'a>(&mut self, word: &'a str) -> Result<Option<WordDefinition<'a>>>
	{
		lookup_record(self, word)
	}

	pub fn get_resource(&self, path: &str) -> Result<Vec<u8>>
	{
		let path = self.cwd.join(path);
		Ok(fs::read(path)?)
	}
}
