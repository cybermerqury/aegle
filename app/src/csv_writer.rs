use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::Path,
    time::Duration,
};

use ppaas_core::{
    key_state_machine::{Key, Secret},
    models::{DeviceId, KeyId},
};

use crate::errors::MainResult;

pub struct CsvWriter {
    filename: String,
}

impl CsvWriter {
    pub fn new(link_id: DeviceId) -> Self {
        Self {
            filename: format!("{link_id}.csv"),
        }
    }

    pub fn write_key(&self, key: &Key<Secret>, pp_duration: Duration) -> MainResult<()> {
        let key_id = key.key_id();
        let value = key
            .get_interior_ref()
            .iter()
            .by_vals()
            .map(|b| if b { "1" } else { "0" })
            .collect::<String>();

        self.write_row(key_id, pp_duration, value)
    }

    fn write_row(&self, key_id: KeyId, duration: Duration, value: String) -> MainResult<()> {
        let mut file = self.get_file()?;

        write!(file, "{},{},{}\n", key_id, duration.as_millis(), value)?;

        Ok(())
    }

    fn get_file(&self) -> MainResult<File> {
        let path = Path::new(&self.filename);

        if !path.exists() {
            let file = OpenOptions::new().create(true).write(true).open(path)?;
            let mut writer = BufWriter::new(file);

            write!(writer, "key_id,duration_millis,value\n")?;
        }

        Ok(OpenOptions::new().append(true).open(path)?)
    }
}
