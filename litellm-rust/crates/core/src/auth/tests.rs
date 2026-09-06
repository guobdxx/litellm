use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

async fn server() -> (Url, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!(
        "http://{}/request?version=one",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut wire = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let count = socket.read(&mut buffer).await.unwrap();
            assert_ne!(count, 0);
            wire.extend_from_slice(&buffer[..count]);
            let text = String::from_utf8_lossy(&wire);
            if let Some((headers, body)) = text.split_once("\r\n\r\n") {
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if body.len() >= length {
                    break;
                }
            }
        }
        socket
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}")
            .await
            .unwrap();
        wire
    });
    (url, task)
}

fn client() -> Client {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

fn request(url: Url, body: AttemptBody) -> AttemptRequest {
    AttemptRequest {
        method: Method::POST,
        url,
        headers: HeaderMap::from_iter([(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )]),
        body,
        operation: AttemptOperation::Initial,
        follow_up_destination: FollowUpDestinationPolicy::Deny,
        retry: AttemptRetryPolicy::Never,
        body_replay: BodyReplayPolicy::Never,
    }
}

struct RecordingHeaderAuthorizer {
    calls: AtomicUsize,
    bodies: Mutex<Vec<Option<Vec<u8>>>>,
}

impl RequestAuthorizer for RecordingHeaderAuthorizer {
    fn declared_headers(&self) -> &[HeaderName] {
        std::slice::from_ref(&AUTHORIZATION)
    }

    fn authorize<'a>(
        &'a self,
        input: AuthorizationInput<'a>,
    ) -> AttemptFuture<'a, AuthorizationMutation> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.bodies.lock().unwrap().push(input.body.map(Vec::from));
            Ok(AuthorizationMutation {
                set_headers: vec![(AUTHORIZATION, HeaderValue::from_static("Bearer recorded"))],
                remove_headers: Vec::new(),
            })
        })
    }
}

struct BodySigner;

impl RequestAuthorizer for BodySigner {
    fn declared_headers(&self) -> &[HeaderName] {
        static SIGNATURE: HeaderName = HeaderName::from_static("x-body-signature");
        std::slice::from_ref(&SIGNATURE)
    }

    fn authorize<'a>(
        &'a self,
        input: AuthorizationInput<'a>,
    ) -> AttemptFuture<'a, AuthorizationMutation> {
        Box::pin(async move {
            let signature = format!("{:x}", Sha256::digest(input.body.unwrap_or_default()));
            Ok(AuthorizationMutation {
                set_headers: vec![(
                    HeaderName::from_static("x-body-signature"),
                    signature.parse().unwrap(),
                )],
                remove_headers: Vec::new(),
            })
        })
    }
}

#[derive(Default)]
struct Progress(Mutex<Vec<AttemptProgress>>);

impl AttemptProgressSink for Progress {
    fn record(&self, progress: AttemptProgress) {
        self.0.lock().unwrap().push(progress);
    }
}

#[tokio::test]
async fn header_authorizer_observes_final_replacement_and_progress_is_explicit() {
    let (url, server) = server().await;
    let authorizer = Arc::new(RecordingHeaderAuthorizer {
        calls: AtomicUsize::new(0),
        bodies: Mutex::new(Vec::new()),
    });
    let progress = Arc::new(Progress::default());
    let control = AttemptControl {
        deadline: Instant::now() + Duration::from_secs(2),
        cancellation: AttemptCancellation::default(),
        progress: progress.clone(),
    };
    let response = send_attempt(
        &client(),
        &url,
        request(url.clone(), AttemptBody::JsonObject(serde_json::Map::new())),
        |view| async move {
            assert_eq!(view.headers.get(AUTHORIZATION).unwrap(), "Bearer recorded");
            Ok(AttemptDecision::Replace(
                serde_json::json!({"masked": true}),
            ))
        },
        &FixedAuthorization::with_prepared_headers(
            authorizer.clone(),
            HeaderMap::from_iter([(AUTHORIZATION, HeaderValue::from_static("Bearer recorded"))]),
            Vec::new(),
        ),
        &control,
    )
    .await
    .unwrap();
    let wire = server.await.unwrap();
    assert_eq!(response.body, b"{}");
    assert_eq!(authorizer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        authorizer.bodies.lock().unwrap().as_slice(),
        [Some(br#"{"masked":true}"#.to_vec())]
    );
    assert!(String::from_utf8_lossy(&wire).contains("authorization: Bearer recorded\r\n"));
    assert_eq!(
        progress.0.lock().unwrap().as_slice(),
        [
            AttemptProgress::Validated,
            AttemptProgress::CredentialPreparationStarted,
            AttemptProgress::CallbackStarted,
            AttemptProgress::CallbackComplete,
            AttemptProgress::Encoded,
            AttemptProgress::AuthorizationStarted,
            AttemptProgress::Authorized,
            AttemptProgress::TransmissionStarted,
            AttemptProgress::ResponseStarted,
            AttemptProgress::ResponseBodyRead,
        ]
    );
}

#[tokio::test]
async fn body_sensitive_signer_signs_the_exact_wire_bytes() {
    let (url, server) = server().await;
    let final_body = br#"{"a":1,"z":"last"}"#;
    send_attempt(
        &client(),
        &url,
        request(
            url.clone(),
            AttemptBody::JsonObject(
                serde_json::json!({"private": true})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        ),
        |_| async {
            Ok(AttemptDecision::Replace(
                serde_json::json!({"a": 1, "z": "last"}),
            ))
        },
        &FixedAuthorization::new(Arc::new(BodySigner)),
        &AttemptControl::with_timeout(Duration::from_secs(2)),
    )
    .await
    .unwrap();
    let wire = server.await.unwrap();
    let header_end = wire
        .windows(4)
        .position(|value| value == b"\r\n\r\n")
        .unwrap()
        + 4;
    assert_eq!(&wire[header_end..], final_body);
    let expected = format!("{:x}", Sha256::digest(final_body));
    assert!(
        String::from_utf8_lossy(&wire[..header_end])
            .contains(&format!("x-body-signature: {expected}\r\n"))
    );
}

#[tokio::test]
async fn bodyless_rejection_and_invalid_replacement_never_authorize() {
    let authorizer = Arc::new(RecordingHeaderAuthorizer {
        calls: AtomicUsize::new(0),
        bodies: Mutex::new(Vec::new()),
    });
    let url = Url::parse("http://127.0.0.1:9/").unwrap();
    for (body, decision, expected) in [
        (
            AttemptBody::Bodyless,
            AttemptDecision::Replace(serde_json::json!({})),
            "bodyless",
        ),
        (
            AttemptBody::JsonObject(serde_json::Map::new()),
            AttemptDecision::Reject("blocked".into()),
            "blocked",
        ),
        (
            AttemptBody::JsonObject(serde_json::Map::new()),
            AttemptDecision::Replace(serde_json::json!([1, 2])),
            "JSON object",
        ),
    ] {
        let error = send_attempt(
            &client(),
            &url,
            request(url.clone(), body),
            |_| async { Ok(decision) },
            &FixedAuthorization::new(authorizer.clone()),
            &AttemptControl::with_timeout(Duration::from_secs(1)),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains(expected));
    }
    assert_eq!(authorizer.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn bodyless_request_is_authorized_and_sent_without_a_body() {
    let (url, server) = server().await;
    let authorizer = Arc::new(RecordingHeaderAuthorizer {
        calls: AtomicUsize::new(0),
        bodies: Mutex::new(Vec::new()),
    });
    let mut operation = request(url.clone(), AttemptBody::Bodyless);
    operation.method = Method::GET;
    operation.headers.clear();
    send_attempt(
        &client(),
        &url,
        operation,
        |_| async { Ok(AttemptDecision::Unchanged) },
        &FixedAuthorization::new(authorizer.clone()),
        &AttemptControl::with_timeout(Duration::from_secs(2)),
    )
    .await
    .unwrap();
    let wire = server.await.unwrap();
    let header_end = wire
        .windows(4)
        .position(|value| value == b"\r\n\r\n")
        .unwrap()
        + 4;
    assert!(wire[header_end..].is_empty());
    assert_eq!(authorizer.bodies.lock().unwrap().as_slice(), [None]);
}

struct UndeclaredAuthorizer;

impl RequestAuthorizer for UndeclaredAuthorizer {
    fn declared_headers(&self) -> &[HeaderName] {
        &[]
    }

    fn authorize<'a>(
        &'a self,
        _: AuthorizationInput<'a>,
    ) -> AttemptFuture<'a, AuthorizationMutation> {
        Box::pin(async {
            Ok(AuthorizationMutation {
                set_headers: vec![(AUTHORIZATION, HeaderValue::from_static("forbidden"))],
                remove_headers: Vec::new(),
            })
        })
    }
}

#[tokio::test]
async fn undeclared_auth_mutation_and_disallowed_destination_are_rejected() {
    let url = Url::parse("http://127.0.0.1:9/").unwrap();
    let error = send_attempt(
        &client(),
        &url,
        request(url.clone(), AttemptBody::Bodyless),
        |_| async { Ok(AttemptDecision::Unchanged) },
        &FixedAuthorization::new(Arc::new(UndeclaredAuthorizer)),
        &AttemptControl::with_timeout(Duration::from_secs(1)),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, Error::Auth(_)));

    let foreign = Url::parse("http://example.com/").unwrap();
    let authorizer = Arc::new(RecordingHeaderAuthorizer {
        calls: AtomicUsize::new(0),
        bodies: Mutex::new(Vec::new()),
    });
    let error = send_attempt(
        &client(),
        &url,
        request(foreign, AttemptBody::Bodyless),
        |_| async { Ok(AttemptDecision::Unchanged) },
        &FixedAuthorization::new(authorizer.clone()),
        &AttemptControl::with_timeout(Duration::from_secs(1)),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, Error::Auth(_)));
    assert_eq!(authorizer.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn follow_up_policy_is_independent_from_body_replay_policy() {
    let url = Url::parse("http://127.0.0.1:9/").unwrap();
    let mut follow_up = request(url.clone(), AttemptBody::Bodyless);
    follow_up.operation = AttemptOperation::FollowUp;
    follow_up.follow_up_destination = FollowUpDestinationPolicy::Deny;
    follow_up.retry = AttemptRetryPolicy::Retryable;
    follow_up.body_replay = BodyReplayPolicy::Replayable;
    let error = send_attempt(
        &client(),
        &url,
        follow_up,
        |_| async { Ok(AttemptDecision::Unchanged) },
        &FixedAuthorization::new(Arc::new(NoAuthorization)),
        &AttemptControl::with_timeout(Duration::from_secs(1)),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, Error::Auth(_)));
}

struct PendingAuthorization;

impl AuthorizationProvider for PendingAuthorization {
    fn prepare(&self) -> AttemptFuture<'_, AuthorizationPreparation> {
        Box::pin(async {
            std::future::pending::<()>().await;
            unreachable!()
        })
    }
}

#[tokio::test]
async fn deadline_and_cancellation_cover_credential_preparation() {
    let url = Url::parse("http://127.0.0.1:9/").unwrap();
    let callback_calls = Arc::new(AtomicUsize::new(0));
    let callback_counter = callback_calls.clone();
    let error = send_attempt(
        &client(),
        &url,
        request(url.clone(), AttemptBody::Bodyless),
        move |_| async move {
            callback_counter.fetch_add(1, Ordering::SeqCst);
            Ok(AttemptDecision::Unchanged)
        },
        &PendingAuthorization,
        &AttemptControl::with_timeout(Duration::from_millis(10)),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "upstream network error: Request timed out"
    );
    assert_eq!(callback_calls.load(Ordering::SeqCst), 0);

    let control = AttemptControl::with_timeout(Duration::from_secs(1));
    control.cancellation.cancel();
    let error = send_attempt(
        &client(),
        &url,
        request(url.clone(), AttemptBody::Bodyless),
        |_| async { Ok(AttemptDecision::Unchanged) },
        &PendingAuthorization,
        &control,
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "upstream network error: Request cancelled"
    );
}

struct FixedClock(Instant);

impl Clock for FixedClock {
    fn now(&self) -> Instant {
        self.0
    }
}

struct RotatingTokenProvider {
    calls: AtomicUsize,
    credential: Arc<dyn Fn(usize) -> TokenCredential + Send + Sync>,
}

impl TokenProvider for RotatingTokenProvider {
    fn token(&self) -> AttemptFuture<'_, TokenCredential> {
        Box::pin(async move {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            Ok((self.credential)(call))
        })
    }
}

async fn prepared_and_final_header(
    provider: &dyn AuthorizationProvider,
    name: HeaderName,
    initial: HeaderMap,
) -> (
    HeaderValue,
    HeaderValue,
    HeaderMap,
    Option<CredentialProvenance>,
) {
    let preparation = provider.prepare().await.unwrap();
    let mut visible = initial.clone();
    apply_preparation(&mut visible, &preparation).unwrap();
    let mutation = preparation
        .authorizer
        .authorize(AuthorizationInput {
            method: &Method::GET,
            url: &Url::parse("https://example.com/").unwrap(),
            headers: &visible,
            body: None,
        })
        .await
        .unwrap();
    let mut final_headers = visible.clone();
    for removed in mutation.remove_headers {
        final_headers.remove(removed);
    }
    for (set_name, value) in mutation.set_headers {
        final_headers.insert(set_name, value);
    }
    (
        visible[&name].clone(),
        final_headers[&name].clone(),
        final_headers,
        preparation.provenance,
    )
}

#[test]
fn secret_debug_output_is_always_redacted() {
    let secret = SecretString::new("private-token");
    let credential = TokenCredential::NoStore(secret.clone());
    assert_eq!(format!("{secret:?}"), "[redacted]");
    assert!(!format!("{credential:?}").contains("private-token"));
}

#[tokio::test]
async fn static_and_bearer_snapshots_remove_conflicting_credentials() {
    let api_key = HeaderName::from_static("x-api-key");
    let initial = HeaderMap::from_iter([
        (AUTHORIZATION, HeaderValue::from_static("Bearer stale")),
        (api_key.clone(), HeaderValue::from_static("stale-key")),
    ]);
    let static_provider = StaticHeaderAuthorizationProvider::new(
        api_key.clone(),
        SecretString::new("fresh-key"),
        vec![AUTHORIZATION],
        CredentialProvenance::CallerSupplied,
    );
    let (visible, final_value, final_headers, provenance) =
        prepared_and_final_header(&static_provider, api_key.clone(), initial.clone()).await;
    assert_eq!(visible, "fresh-key");
    assert_eq!(visible, final_value);
    assert!(visible.is_sensitive());
    assert!(!final_headers.contains_key(AUTHORIZATION));
    assert_eq!(provenance, Some(CredentialProvenance::CallerSupplied));

    let token_provider = Arc::new(RotatingTokenProvider {
        calls: AtomicUsize::new(0),
        credential: Arc::new(|call| {
            TokenCredential::NoStore(SecretString::new(format!("token-{call}")))
        }),
    });
    let bearer = BearerAuthorizationProvider::new(
        token_provider.clone(),
        Arc::new(SystemClock),
        vec![api_key.clone()],
        CredentialProvenance::ExternalProvider,
    );
    let (visible, final_value, final_headers, provenance) =
        prepared_and_final_header(&bearer, AUTHORIZATION, initial).await;
    assert_eq!(visible, "Bearer token-1");
    assert_eq!(visible, final_value);
    assert!(!final_headers.contains_key(api_key));
    assert_eq!(provenance, Some(CredentialProvenance::ExternalProvider));
    assert_eq!(token_provider.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn no_store_token_is_acquired_once_per_attempt_and_never_during_authorization() {
    let token_provider = Arc::new(RotatingTokenProvider {
        calls: AtomicUsize::new(0),
        credential: Arc::new(|call| {
            TokenCredential::NoStore(SecretString::new(format!("token-{call}")))
        }),
    });
    let bearer = BearerAuthorizationProvider::new(
        token_provider.clone(),
        Arc::new(SystemClock),
        Vec::new(),
        CredentialProvenance::ExternalProvider,
    );
    for expected in ["Bearer token-1", "Bearer token-2"] {
        let (visible, final_value, _, _) =
            prepared_and_final_header(&bearer, AUTHORIZATION, HeaderMap::new()).await;
        assert_eq!(visible, expected);
        assert_eq!(final_value, expected);
    }
    assert_eq!(token_provider.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn known_expiry_is_checked_with_the_injected_clock() {
    let now = Instant::now();
    let valid = Arc::new(RotatingTokenProvider {
        calls: AtomicUsize::new(0),
        credential: Arc::new(move |_| {
            TokenCredential::KnownExpiry(TokenLease {
                token: SecretString::new("valid"),
                expires_at: now + Duration::from_secs(1),
            })
        }),
    });
    let valid_bearer = BearerAuthorizationProvider::new(
        valid,
        Arc::new(FixedClock(now)),
        Vec::new(),
        CredentialProvenance::ExternalProvider,
    );
    assert_eq!(
        valid_bearer.prepare().await.unwrap().visible_headers[AUTHORIZATION],
        "Bearer valid"
    );

    let expired = Arc::new(RotatingTokenProvider {
        calls: AtomicUsize::new(0),
        credential: Arc::new(move |_| {
            TokenCredential::KnownExpiry(TokenLease {
                token: SecretString::new("expired"),
                expires_at: now,
            })
        }),
    });
    let expired_bearer = BearerAuthorizationProvider::new(
        expired,
        Arc::new(FixedClock(now)),
        Vec::new(),
        CredentialProvenance::ExternalProvider,
    );
    assert!(
        matches!(expired_bearer.prepare().await, Err(Error::Auth(message)) if message.contains("expired"))
    );
}

struct CountingCredentialAdapter {
    kind: CredentialKind,
    builds: Arc<AtomicUsize>,
}

impl CredentialAdapter for CountingCredentialAdapter {
    fn kind(&self) -> CredentialKind {
        self.kind
    }

    fn build(
        &self,
        spec: CredentialSpec,
        provenance: CredentialProvenance,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<dyn AuthorizationProvider>, Error> {
        self.builds.fetch_add(1, Ordering::SeqCst);
        match spec {
            CredentialSpec::StaticHeader {
                name,
                value,
                conflicts,
            } => Ok(Arc::new(StaticHeaderAuthorizationProvider::new(
                name, value, conflicts, provenance,
            ))),
            CredentialSpec::Bearer {
                provider,
                conflicts,
            } => Ok(Arc::new(BearerAuthorizationProvider::new(
                provider, clock, conflicts, provenance,
            ))),
        }
    }
}

#[tokio::test]
async fn declared_credential_precedence_selects_before_constructing_or_invoking_losers() {
    let static_builds = Arc::new(AtomicUsize::new(0));
    let bearer_builds = Arc::new(AtomicUsize::new(0));
    let losing_factory_calls = Arc::new(AtomicUsize::new(0));
    let registry = CredentialAdapterRegistry::new(
        [
            Arc::new(CountingCredentialAdapter {
                kind: CredentialKind::StaticHeader,
                builds: static_builds.clone(),
            }) as Arc<dyn CredentialAdapter>,
            Arc::new(CountingCredentialAdapter {
                kind: CredentialKind::Bearer,
                builds: bearer_builds.clone(),
            }),
        ],
        Arc::new(SystemClock),
    )
    .unwrap();
    let losing_calls = losing_factory_calls.clone();
    let selected = CredentialCandidate::new(
        CredentialProvenance::CallerSupplied,
        CredentialKind::StaticHeader,
        || {
            Box::pin(async {
                Ok(CredentialSpec::StaticHeader {
                    name: HeaderName::from_static("x-api-key"),
                    value: SecretString::new("winner"),
                    conflicts: vec![AUTHORIZATION],
                })
            })
        },
    );
    let losing = CredentialCandidate::new(
        CredentialProvenance::EnvironmentVariable("TOKEN".into()),
        CredentialKind::Bearer,
        move || {
            losing_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(Error::Auth("loser was constructed".into())) })
        },
    );
    let provider = registry.resolve([selected, losing]).await.unwrap();
    assert_eq!(
        provider.prepare().await.unwrap().visible_headers["x-api-key"],
        "winner"
    );
    assert_eq!(losing_factory_calls.load(Ordering::SeqCst), 0);
    assert_eq!(static_builds.load(Ordering::SeqCst), 1);
    assert_eq!(bearer_builds.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn builtin_registry_dispatches_static_header_and_bearer_specs() {
    let registry = CredentialAdapterRegistry::with_builtin_adapters(Arc::new(SystemClock));
    let static_provider = registry
        .resolve([CredentialCandidate::new(
            CredentialProvenance::CallerSupplied,
            CredentialKind::StaticHeader,
            || {
                Box::pin(async {
                    Ok(CredentialSpec::StaticHeader {
                        name: HeaderName::from_static("x-api-key"),
                        value: SecretString::new("static"),
                        conflicts: vec![AUTHORIZATION],
                    })
                })
            },
        )])
        .await
        .unwrap();
    assert_eq!(
        static_provider.prepare().await.unwrap().visible_headers["x-api-key"],
        "static"
    );

    let token_provider = Arc::new(RotatingTokenProvider {
        calls: AtomicUsize::new(0),
        credential: Arc::new(|_| TokenCredential::NoStore(SecretString::new("bearer"))),
    });
    let bearer_provider = registry
        .resolve([CredentialCandidate::new(
            CredentialProvenance::ExternalProvider,
            CredentialKind::Bearer,
            move || {
                Box::pin(async {
                    Ok(CredentialSpec::Bearer {
                        provider: token_provider,
                        conflicts: vec![HeaderName::from_static("x-api-key")],
                    })
                })
            },
        )])
        .await
        .unwrap();
    assert_eq!(
        bearer_provider.prepare().await.unwrap().visible_headers[AUTHORIZATION],
        "Bearer bearer"
    );
}

#[tokio::test]
async fn concurrent_attempts_keep_each_bearer_snapshot_isolated() {
    let token_provider = Arc::new(RotatingTokenProvider {
        calls: AtomicUsize::new(0),
        credential: Arc::new(|call| {
            TokenCredential::NoStore(SecretString::new(format!("token-{call}")))
        }),
    });
    let bearer = Arc::new(BearerAuthorizationProvider::new(
        token_provider.clone(),
        Arc::new(SystemClock),
        Vec::new(),
        CredentialProvenance::ExternalProvider,
    ));
    let attempts = (0..16).map(|_| {
        let bearer = bearer.clone();
        tokio::spawn(async move {
            let (visible, final_value, _, _) =
                prepared_and_final_header(bearer.as_ref(), AUTHORIZATION, HeaderMap::new()).await;
            (
                visible.to_str().unwrap().to_owned(),
                final_value.to_str().unwrap().to_owned(),
            )
        })
    });
    let results = futures_util::future::join_all(attempts).await;
    let snapshots: HashSet<_> = results
        .into_iter()
        .map(|result| {
            let (visible, final_value) = result.unwrap();
            assert_eq!(visible, final_value);
            visible
        })
        .collect();
    assert_eq!(snapshots.len(), 16);
    assert_eq!(token_provider.calls.load(Ordering::SeqCst), 16);
}
