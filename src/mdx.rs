use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use encoding_rs::{Encoding, UTF_16LE};
use crate::parser::{decode_slice_string, load, lookup_record};
use crate::{Error, Result};

pub type Reader = BufReader<File>;

pub trait KeyMaker {
	fn make(&self, key: &Cow<str>, resource: bool) -> String;
}

impl<F> KeyMaker for F where F: Fn(&Cow<str>, bool) -> String {
	#[inline]
	fn make(&self, key: &Cow<str>, resource: bool) -> String
	{
		self(key, resource)
	}
}

pub struct MDict<M: KeyMaker> {
	pub(crate) mdx: Mdx,
	pub(crate) resources: Vec<Mdx>,
	pub(crate) key_maker: M,
}

pub struct Mdx {
	pub(crate) encoding: &'static Encoding,
	pub(crate) title: String,
	#[allow(unused)]
	pub(crate) encrypted: u8,
	pub(crate) key_entries: Vec<KeyEntry>,
	pub(crate) records_info: Vec<BlockEntryInfo>,
	pub(crate) reader: Reader,
	pub(crate) record_block_offset: u64,
	pub(crate) record_cache: Option<HashMap<usize, Vec<u8>>>,
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

impl<M: KeyMaker> MDict<M> {
	pub fn lookup<'a>(&mut self, word: &'a str) -> Result<Option<WordDefinition<'a>>>
	{
		let encoding = self.mdx.encoding;
		let key = self.key_maker.make(&Cow::Borrowed(word), false);
		if let Some(slice) = lookup_record(&mut self.mdx, &key)? {
			let definition = decode_slice_string(&slice, encoding)?.0.to_string();
			Ok(Some(WordDefinition { key: word, definition }))
		} else {
			Ok(None)
		}
	}

	pub fn get_resource(&mut self, path: &str) -> Result<Option<Cow<[u8]>>>
	{
		let key = self.key_maker.make(&Cow::Borrowed(path), true);
		for mdx in &mut self.resources {
			if let Some(slice) = lookup_record(mdx, &key)? {
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
	pub fn new(path: impl Into<PathBuf>) -> Self
	{
		MDictBuilder {
			path: path.into(),
			cache_definition: false,
			cache_resource: false,
		}
	}

	#[inline]
	pub fn cache_definition(mut self, cache: bool) -> Self
	{
		self.cache_definition = cache;
		self
	}
	#[inline]
	pub fn cache_resource(mut self, cache: bool) -> Self
	{
		self.cache_resource = cache;
		self
	}
	#[inline]
	pub fn build(self) -> Result<MDict<impl KeyMaker>>
	{
		self.build_with_key_maker(|key: &Cow<str>, _resource: bool| key.to_ascii_lowercase())
	}
	pub fn build_with_key_maker<M: KeyMaker>(self, key_maker: M)
		-> Result<MDict<M>>
	{
		let path = self.path;
		let f = File::open(&path)?;
		let reader = BufReader::new(f);
		let cwd = path.parent()
			.ok_or_else(|| Error::InvalidPath(path.clone()))?
			.canonicalize()?;
		let mdx = load(
			reader,
			UTF_16LE,
			self.cache_definition,
			&key_maker,
			false)?;
		let filename = path.file_stem()
			.ok_or_else(|| Error::InvalidPath(path.clone()))?
			.to_str()
			.ok_or_else(|| Error::InvalidPath(path.clone()))?;
		let resources = load_resources(
			&cwd,
			filename,
			self.cache_resource,
			&key_maker)?;
		Ok(MDict {
			mdx,
			resources,
			key_maker,
		})
	}
}

fn load_resources(cwd: &PathBuf, name: &str, cache_resources: bool,
	key_maker: &dyn KeyMaker) -> Result<Vec<Mdx>>
{
	let mut resources = vec![];
	// <filename>.mdd first
	let path = cwd.join(format!("{}.mdd", name));
	if !path.exists() {
		return Ok(resources);
	}
	let f = File::open(&path)?;
	let reader = BufReader::new(f);
	resources.push(load(
		reader,
		UTF_16LE,
		cache_resources,
		key_maker,
		true)?);

	// filename.n.mdd then
	let mut i = 1;
	loop {
		let path = cwd.join(format!("{}.{}.mdd", name, i));
		if !path.exists() {
			break;
		}
		let f = File::open(&path)?;
		let reader = BufReader::new(f);
		resources.push(load(
			reader,
			UTF_16LE,
			cache_resources,
			key_maker,
			true)?);
		i += 1;
	}
	Ok(resources)
}
