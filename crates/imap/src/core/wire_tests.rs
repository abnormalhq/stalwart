/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

use super::{ImapSessionManager, Session, SessionData as ImapSessionData, State};
use common::{
    auth::AccessToken,
    config::server::ServerProtocol,
    network::{
        ServerInstance, SessionData as NetworkSessionData, TcpAcceptor,
        limiter::{ConcurrencyLimiter, LimiterResult},
    },
    test_utils::ServerFixture,
};
use email::{cache::MessageCacheFetch, mailbox::manage::MailboxFnc};
use registry::schema::enums::Permission;
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, duplex},
    sync::watch,
    task::JoinHandle,
};
use utils::snowflake::SnowflakeIdGenerator;

const REMOTE_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const SESSION_IO_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn selected_mailbox_refreshes_exist_before_fetch_and_search_and_expunges() {
    let fixture = ServerFixture::new().await;
    let account_id = fixture
        .create_user_account("wire-test", "imap-wire.test")
        .await;
    fixture
        .server
        .create_system_folders(account_id)
        .await
        .expect("create production INBOX mailbox");

    let mut initial_append = ImapClient::connect(&fixture, account_id, 1).await;
    let initial_message = message("initial", "first body");
    let initial_wire = initial_append.append("A1", &initial_message).await;
    let (uid_validity, initial_uid) =
        assert_append_wire(&initial_wire, "A1", initial_message.len());
    assert_eq!(initial_uid, 1);
    initial_append.logout("A2").await;

    let mut selected = ImapClient::connect(&fixture, account_id, 2).await;
    let select = selected.command("S1", "SELECT INBOX").await;
    assert!(select.contains("* 1 EXISTS\r\n"), "{select:?}");
    assert!(
        select.ends_with("S1 OK [READ-WRITE] SELECT completed\r\n"),
        "{select:?}"
    );

    let mut append_session = ImapClient::connect(&fixture, account_id, 3).await;
    let second_message = message("second", "second body");
    let second_wire = append_session.append("A3", &second_message).await;
    let (second_validity, second_uid) =
        assert_append_wire(&second_wire, "A3", second_message.len());
    assert_eq!(second_validity, uid_validity);
    assert_eq!(second_uid, 2);
    append_session.logout("A4").await;

    let fetch_once = selected.command("F1", "FETCH 1 (FLAGS)").await;
    assert_eq!(
        fetch_once,
        "* 2 EXISTS\r\n* 1 FETCH (FLAGS ($hasnoattachment))\r\nF1 OK FETCH completed\r\n"
    );
    assert_eq!(
        fetch_once.matches("* 2 EXISTS\r\n").count(),
        1,
        "{fetch_once:?}"
    );

    let fetch_twice = selected.command("F2", "FETCH 1 (FLAGS)").await;
    assert_eq!(
        fetch_twice,
        "* 1 FETCH (FLAGS ($hasnoattachment))\r\nF2 OK FETCH completed\r\n"
    );
    assert!(!fetch_twice.contains("EXISTS"), "{fetch_twice:?}");

    let mut second_append_session = ImapClient::connect(&fixture, account_id, 4).await;
    let third_message = message("third", "third body");
    let third_wire = second_append_session.append("A5", &third_message).await;
    let (third_validity, third_uid) = assert_append_wire(&third_wire, "A5", third_message.len());
    assert_eq!(third_validity, uid_validity);
    assert_eq!(third_uid, 3);
    second_append_session.logout("A6").await;

    let search = selected.command("Q1", "SEARCH ALL").await;
    assert_eq!(
        search,
        "* 3 EXISTS\r\n* SEARCH 1 2 3\r\nQ1 OK SEARCH completed\r\n"
    );

    let store = selected.command("D1", "STORE 2 +FLAGS (\\Deleted)").await;
    assert_eq!(
        store,
        "* 2 FETCH (FLAGS ($hasnoattachment \\Deleted))\r\nD1 OK STORE completed\r\n"
    );

    let expunge = selected.command("D2", "EXPUNGE").await;
    assert_eq!(
        expunge,
        "* 2 EXPUNGE\r\n* 2 EXISTS\r\nD2 OK EXPUNGE completed\r\n"
    );

    let cache = fixture
        .server
        .get_cached_messages(account_id)
        .await
        .expect("read final production message cache");
    assert_eq!(cache.emails.len(), 2);

    selected.logout("S2").await;
}

struct ImapClient {
    stream: BufReader<DuplexStream>,
    task: Option<JoinHandle<bool>>,
    _shutdown_tx: watch::Sender<bool>,
}

impl ImapClient {
    async fn connect(fixture: &ServerFixture, account_id: u32, session_id: u64) -> Self {
        let (client_stream, server_stream) = duplex(64 * 1024);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let limiter = ConcurrencyLimiter::new(8);
        let in_flight = match limiter.is_allowed() {
            LimiterResult::Allowed(in_flight) => in_flight,
            _ => panic!("test session was rejected by its local limiter"),
        };
        let instance = Arc::new(ServerInstance {
            id: "local-test".to_string(),
            protocol: ServerProtocol::Imap,
            acceptor: TcpAcceptor::Plain,
            limiter,
            proxy_networks: Vec::new(),
            tls_timeout: Duration::from_secs(1),
            shutdown_rx,
            span_id_gen: Arc::new(SnowflakeIdGenerator::new()),
        });
        let session_data = NetworkSessionData {
            stream: server_stream,
            local_ip: REMOTE_IP,
            local_port: 143,
            remote_ip: REMOTE_IP,
            remote_port: 40000,
            protocol: ServerProtocol::Imap,
            session_id,
            in_flight,
            instance,
        };
        let manager = ImapSessionManager::new(fixture.server.inner.clone());
        let mut session = Session::new(session_data, manager)
            .await
            .expect("create production IMAP session");
        let access_token = AccessToken::from_permissions(
            account_id,
            [
                Permission::ImapAppend,
                Permission::ImapExpunge,
                Permission::ImapFetch,
                Permission::ImapSearch,
                Permission::ImapSelect,
                Permission::ImapStore,
            ],
        );
        let data = ImapSessionData::new(&session, access_token, None)
            .await
            .expect("build authenticated production session data");
        session.state = State::Authenticated {
            data: Arc::new(data),
        };
        let task = tokio::spawn(async move { session.handle_conn().await });
        let mut client = Self {
            stream: BufReader::new(client_stream),
            task: Some(task),
            _shutdown_tx: shutdown_tx,
        };
        let greeting = client.read_line().await;
        assert!(greeting.starts_with("* OK"), "{greeting:?}");
        client
    }

    async fn command(&mut self, tag: &str, command: &str) -> String {
        self.stream
            .get_mut()
            .write_all(format!("{tag} {command}\r\n").as_bytes())
            .await
            .expect("write IMAP command");
        self.read_until_tag(tag).await
    }

    async fn append(&mut self, tag: &str, message: &[u8]) -> String {
        self.stream
            .get_mut()
            .write_all(format!("{tag} APPEND INBOX {{{}}}\r\n", message.len()).as_bytes())
            .await
            .expect("write APPEND command");
        let continuation = self.read_line().await;
        assert_eq!(
            continuation,
            format!("+ Ready for {} bytes.\r\n", message.len())
        );
        self.stream
            .get_mut()
            .write_all(message)
            .await
            .expect("write APPEND literal");
        self.stream
            .get_mut()
            .write_all(b"\r\n")
            .await
            .expect("terminate APPEND literal");
        let mut response = continuation;
        response.push_str(&self.read_until_tag(tag).await);
        response
    }

    async fn logout(&mut self, tag: &str) {
        let response = self.command(tag, "LOGOUT").await;
        assert!(
            response.starts_with("* BYE Logging out.\r\n"),
            "{response:?}"
        );
        assert!(
            response.ends_with(&format!("{tag} OK LOGOUT completed\r\n")),
            "{response:?}"
        );
        let task = self.task.take().expect("IMAP session task");
        let keep_running = tokio::time::timeout(SESSION_IO_TIMEOUT, task)
            .await
            .expect("timed out joining IMAP session")
            .expect("join IMAP session");
        assert!(!keep_running);
    }

    async fn read_line(&mut self) -> String {
        let mut line = Vec::new();
        let read =
            tokio::time::timeout(SESSION_IO_TIMEOUT, self.stream.read_until(b'\n', &mut line))
                .await
                .expect("timed out waiting for IMAP wire response")
                .expect("read IMAP response line");
        assert_ne!(read, 0, "IMAP session closed before a response");
        String::from_utf8(line).expect("IMAP response is UTF-8")
    }

    async fn read_until_tag(&mut self, tag: &str) -> String {
        let terminator = format!("{tag} ");
        let mut response = String::new();
        loop {
            let line = self.read_line().await;
            let done = line.starts_with(&terminator);
            response.push_str(&line);
            if done {
                return response;
            }
        }
    }
}

impl Drop for ImapClient {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn message(subject: &str, body: &str) -> Vec<u8> {
    format!(
        "From: sender@imap-wire.test\r\nTo: wire-test@imap-wire.test\r\nSubject: {subject}\r\n\r\n{body}\r\n"
    )
    .into_bytes()
}

fn assert_append_wire(response: &str, tag: &str, message_len: usize) -> (u32, u32) {
    let lines = response.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2, "{response:?}");
    assert_eq!(lines[0], format!("+ Ready for {message_len} bytes."));
    let fields = lines[1].split_whitespace().collect::<Vec<_>>();
    assert_eq!(fields[0], tag, "{response:?}");
    assert_eq!(fields[1], "OK", "{response:?}");
    assert_eq!(fields[2], "[APPENDUID", "{response:?}");
    assert_eq!(fields[5], "APPEND", "{response:?}");
    assert_eq!(fields[6], "completed", "{response:?}");
    let uid = fields[4]
        .strip_suffix(']')
        .expect("APPENDUID closing bracket")
        .parse()
        .expect("numeric APPEND UID");
    (fields[3].parse().expect("numeric UID validity"), uid)
}
