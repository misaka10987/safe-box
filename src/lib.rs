mod hasher;

use std::{error::Error, path::Path};

use crypto::password_hash::PasswordHash;
use hasher::{hasher, salt, Hasher};
use sqlite::Connection;

pub struct SafeBox {
    conn: Connection,
    hasher: Hasher,
}

const Q_INIT: &str = "CREATE TABLE IF NOT EXISTS main (name TEXT PRIMARY KEY, phc TEXT);";

fn check(s: &[&str]) -> Result<(), String> {
    for s in s {
        if s.contains('\'') || s.contains('\"') {
            return Err(format!("reject suspicious SQL query: argument=\"{s}\""));
        }
    }
    Ok(())
}

impl SafeBox {
    pub fn new(p: impl AsRef<Path>) -> Self {
        let conn = sqlite::open(p).unwrap();
        conn.execute(Q_INIT).unwrap();
        Self {
            conn,
            hasher: hasher(),
        }
    }

    fn select(&self, username: &str) -> Result<Option<String>, Box<dyn Error>> {
        check(&[username])?;
        let query = format!("SELECT * FROM main WHERE name = '{username}';");
        let mut res = vec![];
        self.conn.iterate(query, |pair| {
            res = pair
                .into_iter()
                .filter(|(k, _)| *k == "phc")
                .filter_map(|(_, p)| p.map(|s| s.to_owned()))
                .collect();
            true
        })?;
        assert!(res.len() <= 1, "multiple passwords");
        Ok(res.pop())
    }

    pub fn verify(&self, username: &str, password: &str) -> Result<(), Box<dyn Error>> {
        check(&[username, password])?;
        let p = self.select(username)?;
        if p.is_none() {
            return Err(format!("missing password for username={username}").into());
        }
        let p = p.unwrap();
        let p = PasswordHash::new(&p).map_err(|e| format!("{e}"))?;
        p.verify_password(&[&self.hasher], password)
            .map_err(|e| format!("{e}").into())
    }

    pub fn update(&self, src: &str, dst: &str, old: &str) -> Result<(), Box<dyn Error>> {
        check(&[src, dst, old])?;
        self.verify(src, old)?;
        let p = PasswordHash::generate(self.hasher.clone(), dst, &salt())
            .map_err(|e| format!("{e}"))?
            .to_string();
        let query = format!("UPDATE main SET phc = '{p}' WHERE name = '{src}';");
        Ok(self.conn.execute(query)?)
    }

    pub fn create(&self, username: &str, password: &str) -> Result<(), Box<dyn Error>> {
        check(&[username, password])?;
        if self.select(username)?.is_some() {
            return Err(format!("username \"{username}\" already exists").into());
        }
        let p = PasswordHash::generate(self.hasher.clone(), password, &salt())
            .map_err(|e| format!("{e}"))?
            .to_string();
        let query = format!("INSERT INTO main (name, phc) VALUES ('{username}', '{p}');");
        Ok(self.conn.execute(query)?)
    }

    pub fn delete(&self, username: &str, password: &str) -> Result<(), Box<dyn Error>> {
        check(&[username, password])?;
        self.verify(username, password)?;
        let query = format!("DELETE FROM main WHERE name = '{username}';");
        Ok(self.conn.execute(query)?)
    }
}
