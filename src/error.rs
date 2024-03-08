pub type Result<O> = std::result::Result<O, Error>;


#[derive(Debug)]
pub enum Error{
  InvalidElf
}


