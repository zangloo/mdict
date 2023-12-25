mod error;
mod mdx;
mod parser;

pub use crate::error::Error;
pub use crate::error::Result;
pub use crate::mdx::Mdx;

#[cfg(test)]
mod tests {
    use crate::Mdx;

    const MDX_V2: &str = "/home/zl/dicts/漢語大字典/漢語大字典 (2010).mdx";

    #[test]
    fn lookup() {
        let mut mdx = Mdx::from(MDX_V2).unwrap();
        let definition = mdx.lookup("无").unwrap();
        assert!(definition.is_some());
        let definition = mdx.lookup("無").unwrap();
        assert!(definition.is_some());
    }
}
