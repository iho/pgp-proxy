pub mod account_store;
pub mod imap_client;
pub mod pop3_client;
pub mod poller;

/// A message fetched from a remote IMAP or POP3 account.
pub struct FetchedMessage {
    /// Server-assigned identifier: UID (IMAP) or UIDL (POP3).
    pub remote_id: String,
    /// Raw RFC 2822 message bytes as a UTF-8 string.
    pub raw_rfc822: String,
    pub sender: String,
    pub subject: String,
}
