
use rand::{random};
use std::{env, io};
use std::error::Error;
use std::io::{BufWriter, Write};


fn main() -> Result<(), Box<dyn Error>> {
    let arg = env::args().nth(1);
    let mut num = 30_000_000;

    if let Some(arg_str) = arg {
        num = arg_str.parse::<i32>()?;
    }
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());

    eprintln!("gen integers..");
    for _i in 0..num {
        let random_number = random::<u32>();
        let le_bytes = random_number.to_le_bytes();
        writer.write_all(&le_bytes)?;
    }

    Ok(())
}

// SUPPORT CRAP
