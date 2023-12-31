mod mdx;
mod error;
mod parser;

pub use crate::mdx::MDict;
pub use crate::mdx::MDictBuilder;
pub use crate::mdx::KeyMaker;
pub use crate::mdx::WordDefinition;
pub use crate::error::Error;
pub use crate::error::Result;

#[cfg(test)]
mod tests {
	use std::borrow::Cow;
	use crate::MDictBuilder;

	const MDX_V2: &str = "/home/zl/dicts/漢語大字典/漢語大字典 (2010).mdx";

	#[test]
	fn lookup()
	{
		let mut mdx = MDictBuilder::new(MDX_V2).build().unwrap();
		let definition = mdx.lookup("將進酒").unwrap();
		assert!(definition.is_none());
		let definition = mdx.lookup("无").unwrap();
		assert!(definition.is_some());
		let definition = mdx.lookup("無").unwrap();
		assert!(definition.is_some());
		let definition = mdx.get_resource("\\ZhongHuaSongPlane02b-HZ.woff").unwrap();
		assert!(definition.is_some());
	}

	#[test]
	fn cache_lookup()
	{
		let mut mdx = MDictBuilder::new(MDX_V2)
			.cache_definition(true)
			.cache_resource(true)
			.build_with_key_maker(|key: &Cow<str>, _| key.to_ascii_lowercase())
			.unwrap();
		let definition = mdx.lookup("將進酒").unwrap();
		assert!(definition.is_none());
		let definition = mdx.lookup("无").unwrap();
		assert!(definition.is_some());
		let definition = mdx.lookup("無").unwrap();
		assert!(definition.is_some());
		let definition = mdx.get_resource("\\ZhongHuaSongPlane02b-HZ.woff").unwrap();
		assert!(definition.is_some());
	}
}
