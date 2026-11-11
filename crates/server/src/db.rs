//! Account storage. The connection sits behind a mutex; callers run these
//! blocking methods through `spawn_blocking`.

use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;
use transfer_proto::FriendStatus;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    device_key TEXT NOT NULL,
    token_hash BLOB,
    token_expires INTEGER,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS friendships (
    requester INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    addressee INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    accepted INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (requester, addressee)
);
CREATE INDEX IF NOT EXISTS friendships_addressee ON friendships(addressee);
";

/// Session tokens stop working after this long without a reconnect.
const TOKEN_TTL: i64 = 60 * 60 * 24 * 30;

pub struct Db {
    conn: Mutex<Connection>,
}

pub struct FriendRow {
    pub username: String,
    pub status: FriendStatus,
    pub device_key: String,
}

pub enum FriendAdd {
    Requested,
    Accepted,
    AlreadyLinked,
}

type Sql<T> = rusqlite::Result<T>;

fn now_secs() -> i64 {
    transfer_proto::now_secs() as i64
}

impl Db {
    pub fn open(path: &Path) -> Sql<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Returns false when the username is already taken.
    pub fn create_user(&self, username: &str, hash: &str, device_key: &str) -> Sql<bool> {
        let inserted = self.conn().execute(
            "INSERT OR IGNORE INTO users (username, password_hash, device_key, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![username, hash, device_key, now_secs()],
        )?;
        Ok(inserted == 1)
    }

    pub fn password_hash(&self, username: &str) -> Sql<Option<String>> {
        self.conn()
            .query_row(
                "SELECT password_hash FROM users WHERE username = ?1",
                [username],
                |r| r.get(0),
            )
            .optional()
    }

    pub fn set_password_hash(&self, username: &str, hash: &str) -> Sql<()> {
        self.conn().execute(
            "UPDATE users SET password_hash = ?2 WHERE username = ?1",
            params![username, hash],
        )?;
        Ok(())
    }

    /// One account has one active device: logging in replaces its key and
    /// invalidates the previous session token.
    pub fn start_session(&self, username: &str, token_hash: &[u8], device_key: &str) -> Sql<()> {
        self.conn().execute(
            "UPDATE users SET token_hash = ?2, token_expires = ?3, device_key = ?4
             WHERE username = ?1",
            params![username, token_hash, now_secs() + TOKEN_TTL, device_key],
        )?;
        Ok(())
    }

    /// Validates a token and extends its lifetime.
    pub fn resume_session(&self, token_hash: &[u8]) -> Sql<Option<String>> {
        let conn = self.conn();
        let now = now_secs();
        let username = conn
            .query_row(
                "SELECT username FROM users WHERE token_hash = ?1 AND token_expires > ?2",
                params![token_hash, now],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        if let Some(username) = &username {
            conn.execute(
                "UPDATE users SET token_expires = ?2 WHERE username = ?1",
                params![username, now + TOKEN_TTL],
            )?;
        }
        Ok(username)
    }

    pub fn end_session(&self, username: &str) -> Sql<()> {
        self.conn().execute(
            "UPDATE users SET token_hash = NULL, token_expires = NULL WHERE username = ?1",
            [username],
        )?;
        Ok(())
    }

    pub fn friends(&self, username: &str) -> Sql<Vec<FriendRow>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT other.username, other.device_key, f.accepted, f.requester = me.id
             FROM users me
             JOIN friendships f ON me.id IN (f.requester, f.addressee)
             JOIN users other
               ON other.id = CASE WHEN f.requester = me.id THEN f.addressee ELSE f.requester END
             WHERE me.username = ?1
             ORDER BY other.username",
        )?;
        let rows = stmt.query_map([username], |r| {
            let accepted: bool = r.get(2)?;
            let outgoing: bool = r.get(3)?;
            Ok(FriendRow {
                username: r.get(0)?,
                device_key: r.get(1)?,
                status: match (accepted, outgoing) {
                    (true, _) => FriendStatus::Accepted,
                    (false, true) => FriendStatus::Outgoing,
                    (false, false) => FriendStatus::Incoming,
                },
            })
        })?;
        rows.collect()
    }

    pub fn are_friends(&self, a: &str, b: &str) -> Sql<bool> {
        self.conn().query_row(
            "SELECT EXISTS (
                SELECT 1 FROM friendships f
                JOIN users x ON x.id = f.requester
                JOIN users y ON y.id = f.addressee
                WHERE f.accepted = 1
                  AND ((x.username = ?1 AND y.username = ?2)
                    OR (x.username = ?2 AND y.username = ?1)))",
            params![a, b],
            |r| r.get(0),
        )
    }

    /// `None` when the target does not exist. A request crossing an earlier
    /// one from the other side completes the friendship.
    pub fn add_friend(&self, from: &str, to: &str) -> Sql<Option<FriendAdd>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let id = |name: &str| {
            tx.query_row("SELECT id FROM users WHERE username = ?1", [name], |r| {
                r.get::<_, i64>(0)
            })
            .optional()
        };
        let (Some(from_id), Some(to_id)) = (id(from)?, id(to)?) else {
            return Ok(None);
        };
        let existing = tx
            .query_row(
                "SELECT requester, accepted FROM friendships
                 WHERE (requester = ?1 AND addressee = ?2)
                    OR (requester = ?2 AND addressee = ?1)",
                params![from_id, to_id],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, bool>(1)?)),
            )
            .optional()?;
        let outcome = match existing {
            Some((requester, false)) if requester == to_id => {
                tx.execute(
                    "UPDATE friendships SET accepted = 1 WHERE requester = ?1 AND addressee = ?2",
                    params![to_id, from_id],
                )?;
                FriendAdd::Accepted
            }
            Some(_) => FriendAdd::AlreadyLinked,
            None => {
                tx.execute(
                    "INSERT INTO friendships (requester, addressee, created_at) VALUES (?1, ?2, ?3)",
                    params![from_id, to_id, now_secs()],
                )?;
                FriendAdd::Requested
            }
        };
        tx.commit()?;
        Ok(Some(outcome))
    }

    /// Resolves a request addressed to `me`. Returns false if none is pending.
    pub fn respond_friend(&self, me: &str, requester: &str, accept: bool) -> Sql<bool> {
        let filter = "requester = (SELECT id FROM users WHERE username = ?1)
                      AND addressee = (SELECT id FROM users WHERE username = ?2)
                      AND accepted = 0";
        let sql = if accept {
            format!("UPDATE friendships SET accepted = 1 WHERE {filter}")
        } else {
            format!("DELETE FROM friendships WHERE {filter}")
        };
        Ok(self.conn().execute(&sql, params![requester, me])? == 1)
    }

    pub fn remove_friend(&self, a: &str, b: &str) -> Sql<bool> {
        let removed = self.conn().execute(
            "DELETE FROM friendships WHERE
               (requester = (SELECT id FROM users WHERE username = ?1)
                AND addressee = (SELECT id FROM users WHERE username = ?2))
            OR (requester = (SELECT id FROM users WHERE username = ?2)
                AND addressee = (SELECT id FROM users WHERE username = ?1))",
            params![a, b],
        )?;
        Ok(removed > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Db {
        let db = Db::open(Path::new(":memory:")).unwrap();
        for name in ["ana", "bob"] {
            assert!(db.create_user(name, "hash", "key").unwrap());
        }
        db
    }

    #[test]
    fn usernames_are_unique() {
        assert!(!db().create_user("ana", "hash", "key").unwrap());
    }

    #[test]
    fn friendship_needs_acceptance() {
        let db = db();
        assert!(matches!(db.add_friend("ana", "bob").unwrap(), Some(FriendAdd::Requested)));
        assert!(!db.are_friends("ana", "bob").unwrap());
        assert_eq!(db.friends("bob").unwrap()[0].status, FriendStatus::Incoming);
        assert_eq!(db.friends("ana").unwrap()[0].status, FriendStatus::Outgoing);
        // The requester cannot accept their own request.
        assert!(!db.respond_friend("ana", "bob", true).unwrap());
        assert!(db.respond_friend("bob", "ana", true).unwrap());
        assert!(db.are_friends("bob", "ana").unwrap());
    }

    #[test]
    fn crossing_requests_become_friendship() {
        let db = db();
        db.add_friend("ana", "bob").unwrap();
        assert!(matches!(db.add_friend("bob", "ana").unwrap(), Some(FriendAdd::Accepted)));
        assert!(db.are_friends("ana", "bob").unwrap());
    }

    #[test]
    fn unknown_friend_is_none() {
        assert!(db().add_friend("ana", "zoe").unwrap().is_none());
    }

    #[test]
    fn expired_or_replaced_tokens_do_not_resume() {
        let db = db();
        db.start_session("ana", b"one", "key").unwrap();
        assert_eq!(db.resume_session(b"one").unwrap().as_deref(), Some("ana"));
        db.start_session("ana", b"two", "key").unwrap();
        assert!(db.resume_session(b"one").unwrap().is_none());
        db.end_session("ana").unwrap();
        assert!(db.resume_session(b"two").unwrap().is_none());
    }
}
