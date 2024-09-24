pub mod err;

use std::{
    collections::HashMap,
    ops::DerefMut,
    path::Path,
    sync::RwLock,
    time::{Duration, SystemTime},
};

use argon2::{Argon2, Params, PasswordHash};
use async_mutex::Mutex as AsyncMutex;
use base64::Engine;
use crypto::password_hash::SaltString;
use getrandom::getrandom;
use rand_core::OsRng;
use sqlx::{query, sqlite::SqliteConnectOptions, Connection, Row, SqliteConnection};

fn salt() -> SaltString {
    SaltString::generate(OsRng)
}

fn gen_token() -> String {
    let mut buf = [0u8; 32];
    getrandom(&mut buf).unwrap();
    base64::engine::general_purpose::STANDARD.encode(buf)
}

/// Interface to the password database.
pub struct SafeBox {
    conn: AsyncMutex<SqliteConnection>,
    param: Params,
    token: RwLock<HashMap<String, (String, SystemTime)>>,
}

pub use err::SafeBoxError as Error;

/// Initialize the database.
const Q_INIT: &str = "CREATE TABLE IF NOT EXISTS main (user TEXT PRIMARY KEY, phc TEXT);";

impl SafeBox {
    /// Open an SQLite connection with specified database file and create a `SafeBox`.
    /// # Example
    /// ```
    /// use safe_box::SafeBox;
    ///
    /// let safe = SafeBox::new("secure.db").await.unwrap();
    /// ```
    pub async fn new(p: impl AsRef<Path>) -> Result<Self, Error> {
        let opt = SqliteConnectOptions::default()
            .filename(p)
            .create_if_missing(true);
        let mut conn = SqliteConnection::connect_with(&opt).await?;
        query(Q_INIT).execute(&mut conn).await?;
        Ok(Self {
            conn: AsyncMutex::new(conn),
            param: Params::DEFAULT,
            token: RwLock::new(HashMap::new()),
        })
    }

    /// Instantantiate a hasher with `self.param`.
    fn hasher(&self) -> Argon2<'static> {
        Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            self.param.clone(),
        )
    }

    /// Create new user entry with `user`name and `pass`word.
    pub async fn create(&self, user: &str, pass: &str) -> Result<(), Error> {
        let q = query("SELECT NULL FROM main WHERE user = ?").bind(user);
        let v = q.fetch_all(self.conn.lock().await.deref_mut()).await?;
        if v.len() > 0 {
            return Err(Error::UserAlreadyExist(user.to_owned()));
        }
        let p = PasswordHash::generate(self.hasher(), pass, &salt())?.to_string();
        let q = query("INSERT INTO main (user, phc) VALUES (?, ?)")
            .bind(user)
            .bind(p);
        q.execute(self.conn.lock().await.deref_mut()).await?;
        Ok(())
    }

    /// Verify the provided `user`name and `pass`word.
    /// Return a new token if successful.
    pub async fn verify(&self, user: &str, pass: &str) -> Result<String, Error> {
        let query = query("SELECT phc FROM main WHERE user = ?").bind(user);
        let mut conn = self.conn.lock().await;
        let v = query.fetch_all(conn.deref_mut()).await?;
        match v.len() {
            0 => return Err(Error::UserNotExist(user.to_owned())),
            2.. => return Err(Error::InvalidData(format!("duplicate user '{user}'"))),
            _ => (),
        };
        let p = v[0].try_get("phc")?;
        let p = PasswordHash::new(p)?;
        let res = p.verify_password(&[&self.hasher()], pass);
        if let Err(crypto::password_hash::Error::Password) = res {
            return Err(Error::BadPass {
                user: user.to_owned(),
                pass: pass.to_owned(),
            });
        }
        res?;
        let token = gen_token();
        self.token
            .write()
            .unwrap()
            .insert(token.clone(), (user.to_owned(), SystemTime::now()));
        Ok(token)
    }

    /// Verify the provided `token`.
    /// Returns the user it belongs to if valid.
    pub fn verify_token(&self, token: &str) -> Result<String, Error> {
        let map = self.token.read().unwrap();
        if let Some((s, t)) = map.get(token) {
            let now = SystemTime::now();
            if let Ok(d) = now.duration_since(*t) {
                if d < Duration::from_secs(300) {
                    return Ok(s.to_owned());
                }
            }
        }
        Err(Error::BadToken(token.to_owned()))
    }

    /// Update a user's password to `new`.
    pub async fn update(&self, user: &str, pass: &str, new: &str) -> Result<(), Error> {
        self.verify(user, pass).await?;
        let p = PasswordHash::generate(self.hasher(), new, &salt())?.to_string();
        let q = query("UPDATE main SET phc = ? WHERE user = ?")
            .bind(p)
            .bind(user);
        q.execute(self.conn.lock().await.deref_mut()).await?;
        Ok(())
    }

    /// Delate a user entry.
    pub async fn delete(&self, user: &str, pass: &str) -> Result<(), Error> {
        self.verify(user, pass).await?;
        let q = query("DELETE FROM main WHERE user = ?").bind(user);
        q.execute(self.conn.lock().await.deref_mut()).await?;
        Ok(())
    }
}
