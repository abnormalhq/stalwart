/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavError, DavErrorCondition, DavMethod, DavResourceName,
    calendar::{
        copy_move::CalendarCopyMoveRequestHandler, delete::CalendarDeleteRequestHandler,
        freebusy::CalendarFreebusyRequestHandler, get::CalendarGetRequestHandler,
        mkcol::CalendarMkColRequestHandler, proppatch::CalendarPropPatchRequestHandler,
        query::CalendarQueryRequestHandler, scheduling::CalendarEventNotificationHandler,
        update::CalendarUpdateRequestHandler,
    },
    card::{
        copy_move::CardCopyMoveRequestHandler, delete::CardDeleteRequestHandler,
        get::CardGetRequestHandler, mkcol::CardMkColRequestHandler,
        proppatch::CardPropPatchRequestHandler, query::CardQueryRequestHandler,
        update::CardUpdateRequestHandler,
    },
    common::{
        DavQuery,
        acl::DavAclHandler,
        lock::{LockRequest, LockRequestHandler},
        propfind::PropFindRequestHandler,
        uri::{DavUriResource, UriResource, canonical_dav_uri},
    },
    file::{
        copy_move::FileCopyMoveRequestHandler, delete::FileDeleteRequestHandler,
        get::FileGetRequestHandler, mkcol::FileMkColRequestHandler,
        proppatch::FilePropPatchRequestHandler, update::FileUpdateRequestHandler,
    },
    principal::{matching::PrincipalMatching, propsearch::PrincipalPropSearch},
};
use common::{Server, auth::AccessToken, network::memory::MEMORY_RETRY_AFTER};
use compact_str::{CompactString, ToCompactString};
use dav_proto::{
    RequestHeaders,
    parser::{DavParser, FilterError, header::strip_query_and_fragment, tokenizer::Tokenizer},
    schema::{
        Namespace,
        property::{DavProperty, PrincipalProperty, WebDavProperty},
        request::{Acl, LockInfo, MkCol, PropFind, PropertyUpdate, Report},
        response::{
            BaseCondition, CalCondition, CardCondition, ErrorResponse, PrincipalSearchProperty,
            PrincipalSearchPropertySet,
        },
    },
};
use http_proto::{HttpRequest, HttpResponse, HttpSessionData, request::fetch_body};
use hyper::{StatusCode, header};
use registry::schema::enums::Permission;
use std::{
    ops::RangeInclusive,
    time::{Duration, Instant},
};
use store::{
    rand::{self, RngExt},
    write::unavailable_retry_after,
};
use trc::{EventType, LimitEvent, StoreEvent, WebDavEvent};
use types::collection::{Collection, SyncCollection};

const MAX_CONFLICT_RETRIES: u32 = 3;
const CONFLICT_RETRY_BACKOFF_MS: RangeInclusive<u64> = 1..=15;
const CONFLICT_RETRY_AFTER: u64 = 1;

async fn dispatch_with_conflict_retries<F, Fut, R, RetryFut>(
    method: DavMethod,
    mut dispatch: F,
    mut on_conflict: R,
) -> crate::Result<HttpResponse>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = crate::Result<HttpResponse>>,
    R: FnMut() -> RetryFut,
    RetryFut: Future<Output = ()>,
{
    let mut retries = 0;
    loop {
        match dispatch().await {
            Err(DavError::Internal(err))
                if err.is_assertion_failure()
                    && method.is_write()
                    && retries < MAX_CONFLICT_RETRIES =>
            {
                retries += 1;
                on_conflict().await;
            }
            result => return result,
        }
    }
}

pub trait DavRequestHandler: Sync + Send {
    fn handle_dav_request(
        &self,
        request: HttpRequest,
        access_token: AccessToken,
        session: &HttpSessionData,
        resource: DavResourceName,
        method: DavMethod,
    ) -> impl Future<Output = HttpResponse> + Send;
}

pub(crate) trait DavRequestDispatcher: Sync + Send {
    fn dispatch_dav_request(
        &self,
        headers: &RequestHeaders<'_>,
        access_token: AccessToken,
        resource: DavResourceName,
        method: DavMethod,
        body: &[u8],
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl DavRequestDispatcher for Server {
    async fn dispatch_dav_request(
        &self,
        headers: &RequestHeaders<'_>,
        access_token: AccessToken,
        resource: DavResourceName,
        method: DavMethod,
        body: &[u8],
    ) -> crate::Result<HttpResponse> {
        // Dispatch
        match method {
            DavMethod::PROPFIND => {
                let request = PropFind::parse(&mut Tokenizer::new(body))?;

                self.handle_propfind_request(&access_token, headers, request)
                    .await
            }
            DavMethod::GET | DavMethod::HEAD => match resource {
                DavResourceName::Card => {
                    // Validate permissions
                    let access_token =
                        access_token.assert_has_permission(Permission::DavCardGet)?;

                    self.handle_card_get_request(
                        &access_token,
                        headers,
                        matches!(method, DavMethod::HEAD),
                    )
                    .await
                }
                DavResourceName::Cal => {
                    // Validate permissions
                    let access_token = access_token.assert_has_permission(Permission::DavCalGet)?;

                    self.handle_calendar_get_request(
                        &access_token,
                        headers,
                        matches!(method, DavMethod::HEAD),
                    )
                    .await
                }
                DavResourceName::File => {
                    // Validate permissions
                    let access_token =
                        access_token.assert_has_permission(Permission::DavFileGet)?;

                    // Deal with Litmus bug
                    /*self.handle_file_get_request(
                        &access_token,
                        headers,
                        matches!(method, DavMethod::HEAD)
                            && !request.headers().contains_key("x-litmus"),
                    )
                    .await*/
                    self.handle_file_get_request(
                        &access_token,
                        headers,
                        matches!(method, DavMethod::HEAD),
                    )
                    .await
                }
                DavResourceName::Scheduling => {
                    // Validate permissions
                    let access_token = access_token.assert_has_permission(Permission::DavCalGet)?;

                    self.handle_scheduling_get_request(
                        &access_token,
                        headers,
                        matches!(method, DavMethod::HEAD),
                    )
                    .await
                }
                DavResourceName::Principal => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
            },
            DavMethod::REPORT => match Report::parse(&mut Tokenizer::new(body))? {
                Report::SyncCollection(sync_collection) => {
                    // Validate permissions
                    let access_token =
                        access_token.assert_has_permission(Permission::DavSyncCollection)?;

                    let uri = self
                        .validate_uri(&access_token, headers.uri)
                        .await
                        .and_then(|d| d.into_owned_uri())?;
                    match resource {
                        DavResourceName::Card
                        | DavResourceName::Cal
                        | DavResourceName::File
                        | DavResourceName::Scheduling => {
                            self.handle_dav_query(
                                &access_token,
                                DavQuery::changes(uri, sync_collection, headers),
                            )
                            .await
                        }
                        DavResourceName::Principal => {
                            Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
                        }
                    }
                }
                Report::AclPrincipalPropSet(report) => {
                    // Validate permissions
                    let access_token =
                        access_token.assert_has_permission(Permission::DavPrincipalAcl)?;

                    self.handle_acl_prop_set(&access_token, headers, report)
                        .await
                }
                Report::PrincipalMatch(report) => {
                    // Validate permissions
                    let access_token =
                        access_token.assert_has_permission(Permission::DavPrincipalMatch)?;

                    self.handle_principal_match(&access_token, headers, report)
                        .await
                }
                Report::PrincipalPropertySearch(report) => {
                    if resource == DavResourceName::Principal {
                        // Validate permissions
                        let access_token =
                            access_token.assert_has_permission(Permission::DavPrincipalSearch)?;

                        self.handle_principal_property_search(&access_token, report)
                            .await
                    } else {
                        Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
                    }
                }
                Report::PrincipalSearchPropertySet => {
                    if resource == DavResourceName::Principal {
                        // Validate permissions
                        access_token
                            .assert_has_permission(Permission::DavPrincipalSearchPropSet)?;

                        Ok(HttpResponse::new(StatusCode::OK).with_xml_body(
                            PrincipalSearchPropertySet::new(vec![
                                PrincipalSearchProperty::new(
                                    WebDavProperty::DisplayName,
                                    "Account or Group name",
                                ),
                                PrincipalSearchProperty::new(
                                    DavProperty::Principal(
                                        PrincipalProperty::CalendarUserAddressSet,
                                    ),
                                    "Calendar user address",
                                ),
                            ])
                            .with_namespace(Namespace::CalDav)
                            .to_string(),
                        ))
                    } else {
                        Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
                    }
                }
                Report::AddressbookQuery(report) => {
                    // Validate permissions
                    let access_token =
                        access_token.assert_has_permission(Permission::DavCardQuery)?;

                    self.handle_card_query_request(&access_token, headers, report)
                        .await
                }
                Report::AddressbookMultiGet(report) => {
                    // Validate permissions
                    let access_token =
                        access_token.assert_has_permission(Permission::DavCardMultiGet)?;

                    self.handle_dav_query(
                        &access_token,
                        DavQuery::multiget(report, Collection::AddressBook, headers),
                    )
                    .await
                }
                Report::CalendarQuery(report) => {
                    // Validate permissions
                    let access_token =
                        access_token.assert_has_permission(Permission::DavCalQuery)?;

                    self.handle_calendar_query_request(&access_token, headers, report)
                        .await
                }
                Report::CalendarMultiGet(report) => {
                    // Validate permissions
                    let access_token =
                        access_token.assert_has_permission(Permission::DavCalMultiGet)?;

                    self.handle_dav_query(
                        &access_token,
                        DavQuery::multiget(
                            report,
                            if resource == DavResourceName::Scheduling {
                                Collection::CalendarEventNotification
                            } else {
                                Collection::Calendar
                            },
                            headers,
                        ),
                    )
                    .await
                }
                Report::FreeBusyQuery(report) => {
                    // Validate permissions
                    let access_token =
                        access_token.assert_has_permission(Permission::DavCalFreeBusyQuery)?;

                    self.handle_calendar_freebusy_request(&access_token, headers, report)
                        .await
                }
                Report::ExpandProperty(report) => {
                    let uri = self
                        .validate_uri(&access_token, headers.uri)
                        .await
                        .and_then(|d| d.into_owned_uri())?;

                    // Validate permissions
                    let access_token =
                        access_token.assert_has_permission(Permission::DavExpandProperty)?;

                    match resource {
                        DavResourceName::Card | DavResourceName::Cal | DavResourceName::File => {
                            self.handle_dav_query(
                                &access_token,
                                DavQuery::expand(uri, report, headers),
                            )
                            .await
                        }
                        DavResourceName::Principal | DavResourceName::Scheduling => {
                            Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
                        }
                    }
                }
            },
            DavMethod::PROPPATCH => {
                let request = PropertyUpdate::parse(&mut Tokenizer::new(body))?;
                match resource {
                    DavResourceName::Card => {
                        // Validate permissions
                        let access_token =
                            access_token.assert_has_permission(Permission::DavCardPropPatch)?;

                        self.handle_card_proppatch_request(&access_token, headers, request)
                            .await
                    }
                    DavResourceName::Cal => {
                        // Validate permissions
                        let access_token =
                            access_token.assert_has_permission(Permission::DavCalPropPatch)?;

                        self.handle_calendar_proppatch_request(&access_token, headers, request)
                            .await
                    }
                    DavResourceName::File => {
                        // Validate permissions
                        let access_token =
                            access_token.assert_has_permission(Permission::DavFilePropPatch)?;

                        self.handle_file_proppatch_request(&access_token, headers, request)
                            .await
                    }
                    DavResourceName::Principal | DavResourceName::Scheduling => {
                        Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
                    }
                }
            }
            DavMethod::MKCOL => {
                let request = if !body.is_empty() {
                    Some(MkCol::parse(&mut Tokenizer::new(body))?)
                } else {
                    None
                };

                match resource {
                    DavResourceName::Card => {
                        // Validate permissions
                        let access_token =
                            access_token.assert_has_permission(Permission::DavCardMkCol)?;

                        self.handle_card_mkcol_request(&access_token, headers, request)
                            .await
                    }
                    DavResourceName::Cal => {
                        // Validate permissions
                        let access_token =
                            access_token.assert_has_permission(Permission::DavCalMkCol)?;

                        self.handle_calendar_mkcol_request(&access_token, headers, request)
                            .await
                    }
                    DavResourceName::File => {
                        // Validate permissions
                        let access_token =
                            access_token.assert_has_permission(Permission::DavFileMkCol)?;

                        self.handle_file_mkcol_request(&access_token, headers, request)
                            .await
                    }
                    DavResourceName::Principal | DavResourceName::Scheduling => {
                        Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
                    }
                }
            }
            DavMethod::DELETE => match resource {
                DavResourceName::Card => {
                    // Validate permissions
                    let access_token =
                        access_token.assert_has_permission(Permission::DavCardDelete)?;

                    self.handle_card_delete_request(&access_token, headers)
                        .await
                }
                DavResourceName::Cal => {
                    // Validate permissions
                    let access_token =
                        access_token.assert_has_permission(Permission::DavCalDelete)?;

                    self.handle_calendar_delete_request(&access_token, headers)
                        .await
                }
                DavResourceName::File => {
                    // Validate permissions
                    let access_token =
                        access_token.assert_has_permission(Permission::DavFileDelete)?;

                    self.handle_file_delete_request(&access_token, headers)
                        .await
                }
                DavResourceName::Scheduling => {
                    // Validate permissions
                    let access_token =
                        access_token.assert_has_permission(Permission::DavCalDelete)?;

                    self.handle_scheduling_delete_request(&access_token, headers)
                        .await
                }
                DavResourceName::Principal => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
            },
            DavMethod::PUT | DavMethod::POST | DavMethod::PATCH => match resource {
                DavResourceName::Card => {
                    // Validate permissions
                    let access_token =
                        access_token.assert_has_permission(Permission::DavCardPut)?;

                    self.handle_card_update_request(
                        &access_token,
                        headers,
                        body,
                        matches!(method, DavMethod::PATCH),
                    )
                    .await
                }
                DavResourceName::Cal => {
                    // Validate permissions
                    let access_token = access_token.assert_has_permission(Permission::DavCalPut)?;

                    self.handle_calendar_update_request(
                        &access_token,
                        headers,
                        body,
                        matches!(method, DavMethod::PATCH),
                    )
                    .await
                }
                DavResourceName::File => {
                    // Validate permissions
                    let access_token =
                        access_token.assert_has_permission(Permission::DavFilePut)?;

                    self.handle_file_update_request(
                        &access_token,
                        headers,
                        body,
                        matches!(method, DavMethod::PATCH),
                    )
                    .await
                }
                DavResourceName::Scheduling => {
                    // Validate permissions
                    let access_token =
                        access_token.assert_has_permission(Permission::DavCalFreeBusyQuery)?;

                    self.handle_scheduling_post_request(&access_token, headers, body)
                        .await
                }
                DavResourceName::Principal => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
            },
            DavMethod::COPY | DavMethod::MOVE => {
                let is_move = matches!(method, DavMethod::MOVE);
                match resource {
                    DavResourceName::Card => {
                        // Validate permissions
                        let access_token = access_token.assert_has_permission(if is_move {
                            Permission::DavCardMove
                        } else {
                            Permission::DavCardCopy
                        })?;

                        self.handle_card_copy_move_request(&access_token, headers, is_move)
                            .await
                    }
                    DavResourceName::Cal => {
                        // Validate permissions
                        let access_token = access_token.assert_has_permission(if is_move {
                            Permission::DavCalMove
                        } else {
                            Permission::DavCalCopy
                        })?;
                        self.handle_calendar_copy_move_request(&access_token, headers, is_move)
                            .await
                    }
                    DavResourceName::File => {
                        // Validate permissions
                        let access_token = access_token.assert_has_permission(if is_move {
                            Permission::DavFileMove
                        } else {
                            Permission::DavFileCopy
                        })?;

                        self.handle_file_copy_move_request(&access_token, headers, is_move)
                            .await
                    }
                    DavResourceName::Principal | DavResourceName::Scheduling => {
                        Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
                    }
                }
            }
            DavMethod::MKCALENDAR => match resource {
                DavResourceName::Cal => {
                    // Validate permissions
                    let access_token =
                        access_token.assert_has_permission(Permission::DavCalMkCol)?;

                    self.handle_calendar_mkcol_request(
                        &access_token,
                        headers,
                        Some(MkCol::parse(&mut Tokenizer::new(body))?),
                    )
                    .await
                }
                _ => Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
            },
            DavMethod::LOCK => {
                // Validate permissions
                let access_token = access_token.assert_has_permission(match resource {
                    DavResourceName::File => Permission::DavFileLock,
                    DavResourceName::Cal => Permission::DavCalLock,
                    DavResourceName::Card => Permission::DavCardLock,
                    _ => return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
                })?;

                self.handle_lock_request(
                    &access_token,
                    headers,
                    if !body.is_empty() {
                        LockRequest::Lock(LockInfo::parse(&mut Tokenizer::new(body))?)
                    } else {
                        LockRequest::Refresh
                    },
                )
                .await
            }
            DavMethod::UNLOCK => {
                // Validate permissions
                let access_token = access_token.assert_has_permission(match resource {
                    DavResourceName::File => Permission::DavFileLock,
                    DavResourceName::Cal => Permission::DavCalLock,
                    DavResourceName::Card => Permission::DavCardLock,
                    _ => return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
                })?;

                self.handle_lock_request(&access_token, headers, LockRequest::Unlock)
                    .await
            }
            DavMethod::ACL => {
                // Validate permissions
                let access_token = access_token.assert_has_permission(match resource {
                    DavResourceName::File => Permission::DavFileAcl,
                    DavResourceName::Cal => Permission::DavCalAcl,
                    DavResourceName::Card => Permission::DavCardAcl,
                    _ => return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED)),
                })?;

                self.handle_acl_request(
                    &access_token,
                    headers,
                    Acl::parse(&mut Tokenizer::new(body))?,
                )
                .await
            }
            DavMethod::OPTIONS => unreachable!(),
        }
    }
}

impl DavRequestHandler for Server {
    async fn handle_dav_request(
        &self,
        mut request: HttpRequest,
        access_token: AccessToken,
        session: &HttpSessionData,
        resource: DavResourceName,
        method: DavMethod,
    ) -> HttpResponse {
        let body = if method.has_body()
            || request
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .is_some_and(|len| len > 0)
        {
            if let Some(body) = fetch_body(
                &mut request,
                if !access_token.has_permission(Permission::UnlimitedUploads) {
                    self.core.groupware.max_request_size
                } else {
                    0
                },
                session.session_id,
            )
            .await
            {
                body
            } else {
                trc::event!(
                    Limit(trc::LimitEvent::SizeRequest),
                    SpanId = session.session_id,
                    Contents = "Request body too large",
                );

                return HttpResponse::new(StatusCode::PAYLOAD_TOO_LARGE);
            }
        } else {
            Vec::new()
        };

        // Parse headers
        let mut destinations = request.headers().get_all("destination").iter();
        let destination = destinations.next().and_then(|value| value.to_str().ok());
        if destinations.next().is_some() {
            return HttpResponse::new(StatusCode::BAD_REQUEST);
        }
        let raw_uri = request.uri().path();
        let (uri, canonical_destination) = match (
            canonical_dav_uri(raw_uri),
            destination
                .map(|value| canonical_dav_uri(strip_query_and_fragment(value)))
                .transpose(),
        ) {
            (Ok(uri), Ok(destination)) => (uri, destination),
            _ => return HttpResponse::new(StatusCode::BAD_REQUEST),
        };
        let mut headers = RequestHeaders::new(&uri);
        headers.raw_uri = raw_uri;
        for (key, value) in request.headers() {
            headers.parse(key.as_str(), value.to_str().unwrap_or_default());
        }
        if let Some(destination) = canonical_destination.as_deref() {
            headers.destination = Some(destination);
        }

        let start_time = Instant::now();
        let result = dispatch_with_conflict_retries(
            method,
            || self.dispatch_dav_request(&headers, access_token.clone(), resource, method, &body),
            || async {
                let collection = SyncCollection::from(Collection::from(resource));
                for uri in [Some(headers.uri), headers.destination]
                    .into_iter()
                    .flatten()
                {
                    if let Ok(UriResource {
                        account_id: Some(account_id),
                        ..
                    }) = self.validate_uri(&access_token, uri).await
                    {
                        self.inner.mark_cache_stale(account_id, collection);
                    }
                }
                let backoff = rand::rng().random_range(CONFLICT_RETRY_BACKOFF_MS);
                tokio::time::sleep(Duration::from_millis(backoff)).await;
            },
        )
        .await;
        match result {
            Ok(response) => {
                let event = WebDavEvent::from(method);

                trc::event!(
                    WebDav(event),
                    SpanId = session.session_id,
                    Url = headers.uri.to_compact_string(),
                    Type = resource.name(),
                    Headers = &headers,
                    Result = response.status().as_u16(),
                    Elapsed = start_time.elapsed(),
                );

                response
            }
            Err(DavError::Internal(err)) => {
                let err_type = err.event_type();
                let retry_after = unavailable_retry_after(&err);

                trc::error!(
                    err.span_id(session.session_id)
                        .ctx(trc::Key::Url, headers.uri.to_compact_string())
                        .ctx(trc::Key::Type, resource.name())
                        .ctx(trc::Key::Elapsed, start_time.elapsed())
                );

                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                let is_over_quota = matches!(
                    err_type,
                    EventType::Limit(LimitEvent::Quota | LimitEvent::TenantQuota)
                );
                // SPDX-SnippetEnd
                #[cfg(not(feature = "enterprise"))]
                let is_over_quota = matches!(err_type, EventType::Limit(LimitEvent::Quota));

                match err_type {
                    _ if is_over_quota => HttpResponse::new(StatusCode::INSUFFICIENT_STORAGE)
                        .with_xml_body(
                            ErrorResponse::new(BaseCondition::QuotaNotExceeded)
                                .with_namespace(match resource {
                                    DavResourceName::Card => Namespace::CardDav,
                                    DavResourceName::Cal | DavResourceName::Scheduling => {
                                        Namespace::CalDav
                                    }
                                    DavResourceName::File | DavResourceName::Principal => {
                                        Namespace::Dav
                                    }
                                })
                                .to_string(),
                        )
                        .with_no_cache(),
                    EventType::Store(StoreEvent::AssertValueFailed) => {
                        HttpResponse::new(StatusCode::SERVICE_UNAVAILABLE)
                            .with_header("Retry-After", CONFLICT_RETRY_AFTER.to_string())
                    }
                    _ if let Some(retry_after) = retry_after => {
                        HttpResponse::new(StatusCode::SERVICE_UNAVAILABLE)
                            .with_header("Retry-After", retry_after.to_string())
                    }
                    EventType::Limit(LimitEvent::MemoryBudget) => {
                        HttpResponse::new(StatusCode::SERVICE_UNAVAILABLE)
                            .with_header("Retry-After", MEMORY_RETRY_AFTER.to_string())
                    }
                    EventType::Security(_) => HttpResponse::new(StatusCode::FORBIDDEN),
                    _ => HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR),
                }
            }
            Err(DavError::Parse(err)) => {
                let result = if headers.content_type.is_some_and(|h| h.contains("/xml")) {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::UNSUPPORTED_MEDIA_TYPE
                };

                trc::event!(
                    WebDav(WebDavEvent::Error),
                    SpanId = session.session_id,
                    Url = headers.uri.to_compact_string(),
                    Type = resource.name(),
                    Headers = &headers,
                    Result = result.as_u16(),
                    Reason = err.to_compact_string(),
                    Elapsed = start_time.elapsed(),
                );

                HttpResponse::new(result)
            }
            Err(DavError::Condition(condition)) => {
                let event = WebDavEvent::from(method);

                trc::event!(
                    WebDav(event),
                    SpanId = session.session_id,
                    Url = headers.uri.to_compact_string(),
                    Type = resource.name(),
                    Headers = &headers,
                    Code = condition.code.as_u16(),
                    Result = CompactString::const_new(condition.condition.display_name()),
                    Reason = condition.details,
                    Elapsed = start_time.elapsed(),
                );

                HttpResponse::new(condition.code)
                    .with_xml_body(
                        ErrorResponse::new(condition.condition)
                            .with_namespace(match resource {
                                DavResourceName::Card => Namespace::CardDav,
                                DavResourceName::Cal | DavResourceName::Scheduling => {
                                    Namespace::CalDav
                                }
                                DavResourceName::File | DavResourceName::Principal => {
                                    Namespace::Dav
                                }
                            })
                            .to_string(),
                    )
                    .with_no_cache()
            }
            Err(DavError::Code(code)) => {
                let event = WebDavEvent::from(method);

                trc::event!(
                    WebDav(event),
                    SpanId = session.session_id,
                    Url = headers.uri.to_compact_string(),
                    Type = resource.name(),
                    Headers = &headers,
                    Result = code.as_u16(),
                    Elapsed = start_time.elapsed(),
                );

                HttpResponse::new(code)
            }
        }
    }
}

impl From<dav_proto::parser::Error> for DavError {
    fn from(err: dav_proto::parser::Error) -> Self {
        match err {
            dav_proto::parser::Error::Filter(FilterError::Invalid(Namespace::CalDav)) => {
                DavErrorCondition::new(StatusCode::FORBIDDEN, CalCondition::ValidFilter).into()
            }
            dav_proto::parser::Error::Filter(FilterError::UnsupportedCollation(
                Namespace::CalDav,
                collation,
            )) => DavErrorCondition::new(
                StatusCode::FORBIDDEN,
                CalCondition::SupportedCollation(collation),
            )
            .into(),
            dav_proto::parser::Error::Filter(FilterError::UnsupportedCollation(_, collation)) => {
                DavErrorCondition::new(
                    StatusCode::FORBIDDEN,
                    CardCondition::SupportedCollation(collation),
                )
                .into()
            }
            dav_proto::parser::Error::Filter(FilterError::TooComplex(Namespace::CalDav)) => {
                DavErrorCondition::new(StatusCode::FORBIDDEN, CalCondition::SupportedFilter).into()
            }
            dav_proto::parser::Error::Filter(FilterError::TooComplex(_)) => {
                DavErrorCondition::new(StatusCode::FORBIDDEN, CardCondition::SupportedFilter).into()
            }
            err => DavError::Parse(err),
        }
    }
}

impl From<trc::Error> for DavError {
    fn from(err: trc::Error) -> Self {
        DavError::Internal(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::lock::if_exists_condition_matches;
    use dav_proto::{Condition, If, RequestHeaders};

    async fn retry_with_target_race(target_appears: bool) -> (crate::Result<HttpResponse>, usize) {
        let uri = "/dav/calendars/user/default/item.ics";
        let mut headers = RequestHeaders {
            uri,
            raw_uri: uri,
            ..Default::default()
        };
        headers.if_.push(If {
            resource: None,
            list: vec![Condition::Exists { is_not: true }],
        });
        let mut attempts = 0;
        let mut target_exists = false;
        let dispatch = || {
            attempts += 1;
            let attempt = attempts;
            let is_not = match &headers.if_[0].list[0] {
                Condition::Exists { is_not } => *is_not,
                _ => unreachable!(),
            };
            if attempt == 1 && target_appears {
                target_exists = true;
            }
            let exists = target_exists;
            async move {
                if attempt == 1 {
                    Err(DavError::Internal(
                        trc::StoreEvent::AssertValueFailed.into_err(),
                    ))
                } else if if_exists_condition_matches(is_not, exists) {
                    Ok(HttpResponse::new(StatusCode::CREATED))
                } else {
                    Err(DavError::Code(StatusCode::PRECONDITION_FAILED))
                }
            }
        };

        (
            dispatch_with_conflict_retries(DavMethod::PUT, dispatch, || async {}).await,
            attempts,
        )
    }

    #[tokio::test]
    async fn assertion_retry_rechecks_if_none_match_for_current_target() {
        let (result, attempts) = retry_with_target_race(false).await;
        assert_eq!(attempts, 2);
        match result {
            Ok(response) => assert_eq!(response.status(), StatusCode::CREATED),
            Err(_) => panic!("unrelated conflict incorrectly failed the absent target"),
        }

        let (result, attempts) = retry_with_target_race(true).await;
        assert_eq!(attempts, 2);
        assert!(matches!(
            result,
            Err(DavError::Code(StatusCode::PRECONDITION_FAILED))
        ));
    }
}

#[cfg(test)]
mod server_integration_tests {
    use super::*;
    use common::{
        auth::AccessToken, storage::index::ObjectIndexBuilder, test_utils::ServerFixture,
    };
    use dav_proto::RequestHeaders;
    use groupware::{
        DavResourceName,
        cache::GroupwareCache,
        file::{FileNode, FileNodeContent},
    };
    use registry::schema::enums::{Permission, StorageQuota};
    use std::{future::Future, sync::Arc};
    use store::{
        query::log::Query,
        write::{BatchBuilder, LogCollection},
    };
    use types::collection::SyncCollection;

    const OP_TIMEOUT: Duration = Duration::from_secs(20);
    const FILE_BODY: &[u8] = b"fenced file body\r\n";
    const CAL_BODY: &[u8] = b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//DAV//EN\r\nBEGIN:VEVENT\r\nUID:dav-race-event\r\nDTSTAMP:20260101T000000Z\r\nDTSTART:20260102T120000Z\r\nDTEND:20260102T130000Z\r\nSUMMARY:DAV race\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    const CARD_BODY: &[u8] = b"BEGIN:VCARD\r\nVERSION:4.0\r\nUID:dav-race-card\r\nFN:DAV race\r\nN:Race;DAV;;;;\r\nEND:VCARD\r\n";
    static INTEGRATION_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn bounded<T>(future: impl Future<Output = T>, operation: &'static str) -> T {
        tokio::time::timeout(OP_TIMEOUT, future)
            .await
            .unwrap_or_else(|_| panic!("timed out during {operation}"))
    }

    fn token(account_id: u32) -> AccessToken {
        AccessToken::from_permissions(
            account_id,
            [
                Permission::DavFileGet,
                Permission::DavFilePut,
                Permission::DavFileCopy,
                Permission::DavFileMove,
                Permission::DavFileMkCol,
                Permission::DavCalPut,
                Permission::DavCalCopy,
                Permission::DavCalMove,
                Permission::DavCalMkCol,
                Permission::DavCardPut,
                Permission::DavCardCopy,
                Permission::DavCardMove,
                Permission::DavCardMkCol,
            ],
        )
    }

    async fn dispatch_status(
        server: &Server,
        access_token: AccessToken,
        resource: DavResourceName,
        method: DavMethod,
        uri: &str,
        destination: Option<&str>,
        content_type: Option<&str>,
        body: &[u8],
        if_none_match: bool,
        overwrite_fail: bool,
    ) -> StatusCode {
        let mut headers = RequestHeaders {
            uri,
            raw_uri: uri,
            ..Default::default()
        };
        if if_none_match {
            headers.parse("If-None-Match", "*");
        }
        if let Some(content_type) = content_type {
            headers.parse("Content-Type", content_type);
        }
        if overwrite_fail {
            headers.parse("Overwrite", "F");
        }
        headers.destination = destination;
        let collection = SyncCollection::from(Collection::from(resource));
        let result = bounded(
            dispatch_with_conflict_retries(
                method,
                || {
                    server.dispatch_dav_request(
                        &headers,
                        access_token.clone(),
                        resource,
                        method,
                        body,
                    )
                },
                || async {
                    server
                        .inner
                        .mark_cache_stale(access_token.account_id(), collection);
                    tokio::time::sleep(Duration::from_millis(1)).await;
                },
            ),
            "actual DAV dispatcher and bounded conflict retry",
        )
        .await;

        match result {
            Ok(response) => response.status(),
            Err(DavError::Code(code)) => code,
            Err(DavError::Condition(condition)) => condition.code,
            Err(DavError::Internal(err)) => panic!("unexpected DAV store error: {err:?}"),
            Err(DavError::Parse(err)) => panic!("unexpected DAV parse error: {err:?}"),
        }
    }

    async fn dispatch_once(
        server: &Server,
        access_token: AccessToken,
        resource: DavResourceName,
        method: DavMethod,
        uri: &str,
        destination: Option<&str>,
    ) -> crate::Result<HttpResponse> {
        let mut headers = RequestHeaders {
            uri,
            raw_uri: uri,
            ..Default::default()
        };
        headers.destination = destination;
        bounded(
            server.dispatch_dav_request(&headers, access_token, resource, method, &[]),
            "single DAV dispatch without conflict retry",
        )
        .await
    }

    async fn stats(
        server: &Server,
        account_id: u32,
        sync_collection: SyncCollection,
        quota: StorageQuota,
    ) -> (usize, usize, i64) {
        let object_count = bounded(
            server.object_count(account_id, quota),
            "read DAV object quota",
        )
        .await
        .expect("read DAV object quota");
        let log_count = bounded(
            server
                .store()
                .changes(account_id, LogCollection::Sync(sync_collection), Query::All),
            "read DAV change log",
        )
        .await
        .expect("read DAV change log")
        .changes
        .len();
        let disk_quota = bounded(
            server.get_used_quota_account(account_id),
            "read DAV disk quota",
        )
        .await
        .expect("read DAV disk quota");
        (object_count, log_count, disk_quota)
    }

    async fn preload(
        server: &Server,
        account_id: u32,
        sync_collection: SyncCollection,
    ) -> Arc<common::GroupwareResources> {
        bounded(
            server.fetch_groupware_resources_at(account_id, account_id, sync_collection, u64::MAX),
            "preload independent DAV cache",
        )
        .await
        .expect("preload DAV resources")
    }

    async fn seed_large_file_directory(
        server: &Server,
        account_id: u32,
        access_token: &AccessToken,
        base: &str,
        name: &str,
        child_count: u32,
    ) -> u32 {
        let uri = format!("{base}{name}");
        assert_eq!(
            dispatch_status(
                server,
                access_token.clone(),
                DavResourceName::File,
                DavMethod::MKCOL,
                &uri,
                None,
                None,
                &[],
                false,
                false,
            )
            .await,
            StatusCode::CREATED
        );
        let resources = preload(server, account_id, SyncCollection::FileNode).await;
        let parent_id = resources
            .by_path(name)
            .expect("find newly-created source directory")
            .document_id()
            + 1;

        let mut batch = BatchBuilder::new();
        let mut slots = batch
            .reserve_document_ids(account_id, Collection::FileNode, child_count)
            .iter();
        for index in 0..child_count {
            let node = FileNode {
                parent_id,
                name: format!("child-{index:04}"),
                content: FileNodeContent::Directory,
                ..Default::default()
            };
            batch
                .with_account_id(account_id)
                .with_collection(Collection::FileNode)
                .create_document(slots.next().expect("reserved directory child ID"))
                .custom(
                    ObjectIndexBuilder::<(), _>::new()
                        .with_changes(node)
                        .with_changed_by(access_token.changed_by()),
                )
                .expect("index seeded directory child");
        }
        bounded(
            server.store().write_batch(&mut batch),
            "seed large directory children",
        )
        .await
        .expect("write large directory children");
        parent_id
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn real_dispatcher_retries_concurrent_puts_for_calendar_card_and_file() {
        let _test_lock = INTEGRATION_TEST_LOCK.lock().await;
        let primary = bounded(ServerFixture::new(), "build primary DAV server").await;
        let account_id = bounded(
            primary.create_user_account("dav-test", "dav-integration.test"),
            "seed DAV account",
        )
        .await;
        let quota_probe_id = bounded(
            primary.create_user_account("dav-quota-probe", "dav-integration.test"),
            "seed DAV quota reference account",
        )
        .await;
        let secondary = bounded(
            primary.new_with_shared_primary(),
            "build independent DAV server on shared SQLite primary",
        )
        .await;
        assert!(!Arc::ptr_eq(&primary.server.inner, &secondary.server.inner));

        let account = bounded(primary.server.account(account_id), "load DAV account")
            .await
            .expect("load DAV account");
        assert!(
            bounded(
                primary.server.create_default_calendar(&account, &account),
                "create default calendar",
            )
            .await
            .expect("create default calendar")
            .is_some()
        );
        assert!(
            bounded(
                primary
                    .server
                    .create_default_addressbook(&account, &account),
                "create default address book",
            )
            .await
            .expect("create default address book")
            .is_some()
        );
        let quota_probe = bounded(
            primary.server.account(quota_probe_id),
            "load DAV quota reference account",
        )
        .await
        .expect("load DAV quota reference account");
        assert!(
            bounded(
                primary
                    .server
                    .create_default_calendar(&quota_probe, &quota_probe),
                "create quota reference calendar",
            )
            .await
            .expect("create quota reference calendar")
            .is_some()
        );
        assert!(
            bounded(
                primary
                    .server
                    .create_default_addressbook(&quota_probe, &quota_probe),
                "create quota reference address book",
            )
            .await
            .expect("create quota reference address book")
            .is_some()
        );

        let account_name = "dav-test@dav-integration.test";
        let quota_probe_name = "dav-quota-probe@dav-integration.test";
        let calendar_name = primary
            .server
            .core
            .groupware
            .default_calendar_name
            .as_deref()
            .expect("default calendar name");
        let addressbook_name = primary
            .server
            .core
            .groupware
            .default_addressbook_name
            .as_deref()
            .expect("default address book name");

        let probe_uri = format!(
            "{}race.txt",
            DavResourceName::File.account_base_path(quota_probe_name)
        );
        let probe_before = bounded(
            primary.server.get_used_quota_account(quota_probe_id),
            "read file quota reference before write",
        )
        .await
        .expect("read file quota reference before write");
        assert_eq!(
            dispatch_status(
                &primary.server,
                token(quota_probe_id),
                DavResourceName::File,
                DavMethod::PUT,
                &probe_uri,
                None,
                Some("text/plain"),
                FILE_BODY,
                true,
                false,
            )
            .await,
            StatusCode::CREATED
        );
        let expected_file_quota_delta = bounded(
            primary.server.get_used_quota_account(quota_probe_id),
            "read file quota reference after write",
        )
        .await
        .expect("read file quota reference after write")
            - probe_before;
        let calendar_probe_uri = format!(
            "{}{}/race.ics",
            DavResourceName::Cal.account_base_path(quota_probe_name),
            calendar_name
        );
        let calendar_probe_before = bounded(
            primary.server.get_used_quota_account(quota_probe_id),
            "read calendar quota reference before write",
        )
        .await
        .expect("read calendar quota reference before write");
        assert_eq!(
            dispatch_status(
                &primary.server,
                token(quota_probe_id),
                DavResourceName::Cal,
                DavMethod::PUT,
                &calendar_probe_uri,
                None,
                Some("text/calendar"),
                CAL_BODY,
                true,
                false,
            )
            .await,
            StatusCode::CREATED
        );
        let expected_calendar_quota_delta = bounded(
            primary.server.get_used_quota_account(quota_probe_id),
            "read calendar quota reference after write",
        )
        .await
        .expect("read calendar quota reference after write")
            - calendar_probe_before;
        let card_probe_uri = format!(
            "{}{}/race.vcf",
            DavResourceName::Card.account_base_path(quota_probe_name),
            addressbook_name
        );
        let card_probe_before = bounded(
            primary.server.get_used_quota_account(quota_probe_id),
            "read card quota reference before write",
        )
        .await
        .expect("read card quota reference before write");
        assert_eq!(
            dispatch_status(
                &primary.server,
                token(quota_probe_id),
                DavResourceName::Card,
                DavMethod::PUT,
                &card_probe_uri,
                None,
                Some("text/vcard"),
                CARD_BODY,
                true,
                false,
            )
            .await,
            StatusCode::CREATED
        );
        let expected_card_quota_delta = bounded(
            primary.server.get_used_quota_account(quota_probe_id),
            "read card quota reference after write",
        )
        .await
        .expect("read card quota reference after write")
            - card_probe_before;
        let scenarios = [
            (
                DavResourceName::File,
                SyncCollection::FileNode,
                StorageQuota::MaxFiles,
                "",
                "race.txt",
                "text/plain",
                FILE_BODY,
                expected_file_quota_delta,
            ),
            (
                DavResourceName::Cal,
                SyncCollection::Calendar,
                StorageQuota::MaxCalendarEvents,
                calendar_name,
                "race.ics",
                "text/calendar",
                CAL_BODY,
                expected_calendar_quota_delta,
            ),
            (
                DavResourceName::Card,
                SyncCollection::AddressBook,
                StorageQuota::MaxContactCards,
                addressbook_name,
                "race.vcf",
                "text/vcard",
                CARD_BODY,
                expected_card_quota_delta,
            ),
        ];

        for (
            resource,
            sync_collection,
            object_quota,
            parent,
            name,
            content_type,
            body,
            expected_disk_quota_delta,
        ) in scenarios
        {
            let base = resource.account_base_path(account_name);
            let relative_path = if parent.is_empty() {
                name.to_string()
            } else {
                format!("{parent}/{name}")
            };
            let uri = format!("{base}{relative_path}");
            let before_resources = preload(&primary.server, account_id, sync_collection).await;
            let _ = preload(&secondary.server, account_id, sync_collection).await;
            let before_stats =
                stats(&primary.server, account_id, sync_collection, object_quota).await;
            let access = token(account_id);

            crate::common::create::set_test_prepare_barrier(2);
            let first = dispatch_status(
                &primary.server,
                access.clone(),
                resource,
                DavMethod::PUT,
                &uri,
                None,
                Some(content_type),
                body,
                true,
                false,
            );
            let second = dispatch_status(
                &secondary.server,
                access,
                resource,
                DavMethod::PUT,
                &uri,
                None,
                Some(content_type),
                body,
                true,
                false,
            );
            let (first_status, second_status) =
                bounded(async { tokio::join!(first, second) }, "concurrent DAV PUTs").await;
            let mut statuses = [first_status, second_status];
            statuses.sort();
            assert_eq!(
                statuses,
                [StatusCode::CREATED, StatusCode::PRECONDITION_FAILED]
            );

            let after_resources = preload(&secondary.server, account_id, sync_collection).await;
            assert_eq!(
                after_resources.resources.total,
                before_resources.resources.total + 1,
                "exactly one named DAV resource is stored at {relative_path}"
            );
            assert!(after_resources.by_path(&relative_path).is_some());
            let after_stats =
                stats(&primary.server, account_id, sync_collection, object_quota).await;
            if resource == DavResourceName::Cal {
                assert_eq!(
                    after_stats.0,
                    before_stats.0 + 1,
                    "calendar event object quota count"
                );
            }
            assert_eq!(after_stats.1, before_stats.1 + 1, "sync log count");
            assert_eq!(
                after_stats.2 - before_stats.2,
                expected_disk_quota_delta,
                "disk quota matches one production insertion"
            );
        }

        let sync_collection = SyncCollection::FileNode;
        let before_resources = preload(&primary.server, account_id, sync_collection).await;
        let before_stats = stats(
            &primary.server,
            account_id,
            sync_collection,
            StorageQuota::MaxFiles,
        )
        .await;
        let base = DavResourceName::File.account_base_path(account_name);
        let first_uri = format!("{base}unrelated-a.txt");
        let second_uri = format!("{base}unrelated-b.txt");
        let access = token(account_id);
        crate::common::create::set_test_prepare_barrier(2);
        let first = dispatch_status(
            &primary.server,
            access.clone(),
            DavResourceName::File,
            DavMethod::PUT,
            &first_uri,
            None,
            Some("text/plain"),
            FILE_BODY,
            true,
            false,
        );
        let second = dispatch_status(
            &secondary.server,
            access,
            DavResourceName::File,
            DavMethod::PUT,
            &second_uri,
            None,
            Some("text/plain"),
            FILE_BODY,
            true,
            false,
        );
        assert_eq!(
            bounded(
                async { tokio::join!(first, second) },
                "unrelated concurrent DAV PUTs",
            )
            .await,
            (StatusCode::CREATED, StatusCode::CREATED)
        );
        let after_resources = preload(&secondary.server, account_id, sync_collection).await;
        assert_eq!(
            after_resources.resources.total,
            before_resources.resources.total + 2
        );
        assert!(after_resources.by_path("unrelated-a.txt").is_some());
        assert!(after_resources.by_path("unrelated-b.txt").is_some());
        let after_stats = stats(
            &primary.server,
            account_id,
            sync_collection,
            StorageQuota::MaxFiles,
        )
        .await;
        assert_eq!(after_stats.1, before_stats.1 + 2);
        assert!(after_stats.2 > before_stats.2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn file_put_copy_move_and_mkcol_destination_collisions_store_one_target() {
        let _test_lock = INTEGRATION_TEST_LOCK.lock().await;
        let primary = bounded(ServerFixture::new(), "build primary file DAV server").await;
        let account_id = bounded(
            primary.create_user_account("dav-file", "dav-collision.test"),
            "seed file DAV account",
        )
        .await;
        let secondary = bounded(
            primary.new_with_shared_primary(),
            "build independent file DAV server",
        )
        .await;
        assert!(!Arc::ptr_eq(&primary.server.inner, &secondary.server.inner));
        let resource = DavResourceName::File;
        let base = resource.account_base_path("dav-file@dav-collision.test");
        let access = token(account_id);

        for method in [DavMethod::COPY, DavMethod::MOVE, DavMethod::MKCOL] {
            let suffix = match method {
                DavMethod::COPY => "copy",
                DavMethod::MOVE => "move",
                DavMethod::MKCOL => "mkcol",
                _ => unreachable!(),
            };
            let source_uri = format!("{base}source-{suffix}.txt");
            let target_name = format!("destination-{suffix}");
            let target_uri = format!("{base}{target_name}");
            if !matches!(method, DavMethod::MKCOL) {
                assert_eq!(
                    dispatch_status(
                        &primary.server,
                        access.clone(),
                        resource,
                        DavMethod::PUT,
                        &source_uri,
                        None,
                        Some("text/plain"),
                        FILE_BODY,
                        true,
                        false,
                    )
                    .await,
                    StatusCode::CREATED
                );
            }
            let before_resources =
                preload(&primary.server, account_id, SyncCollection::FileNode).await;
            let _ = preload(&secondary.server, account_id, SyncCollection::FileNode).await;
            crate::common::create::set_test_prepare_barrier(2);
            let put = dispatch_status(
                &primary.server,
                access.clone(),
                resource,
                DavMethod::PUT,
                &target_uri,
                None,
                Some("text/plain"),
                FILE_BODY,
                true,
                false,
            );
            let collision = if matches!(method, DavMethod::MKCOL) {
                dispatch_status(
                    &secondary.server,
                    access.clone(),
                    resource,
                    method,
                    &target_uri,
                    None,
                    None,
                    &[],
                    false,
                    false,
                )
            } else {
                dispatch_status(
                    &secondary.server,
                    access.clone(),
                    resource,
                    method,
                    &source_uri,
                    Some(&target_uri),
                    None,
                    &[],
                    false,
                    true,
                )
            };
            let (put_status, collision_status) = bounded(
                async { tokio::join!(put, collision) },
                "PUT versus DAV destination collision",
            )
            .await;
            match method {
                DavMethod::COPY | DavMethod::MOVE => assert!(matches!(
                    (put_status, collision_status),
                    (StatusCode::CREATED, StatusCode::PRECONDITION_FAILED)
                        | (StatusCode::PRECONDITION_FAILED, StatusCode::CREATED)
                )),
                DavMethod::MKCOL => assert!(matches!(
                    (put_status, collision_status),
                    (StatusCode::CREATED, StatusCode::METHOD_NOT_ALLOWED)
                        | (StatusCode::PRECONDITION_FAILED, StatusCode::CREATED)
                )),
                _ => unreachable!(),
            }

            let after_resources =
                preload(&secondary.server, account_id, SyncCollection::FileNode).await;
            assert!(
                after_resources.by_path(&target_name).is_some(),
                "missing single destination after {method:?} collision"
            );
            let move_won =
                matches!(method, DavMethod::MOVE) && collision_status == StatusCode::CREATED;
            assert_eq!(
                after_resources.resources.total,
                before_resources.resources.total + usize::from(!move_won),
                "unexpected resource delta after {method:?} collision"
            );
            if matches!(method, DavMethod::COPY | DavMethod::MOVE) {
                assert_eq!(
                    after_resources
                        .by_path(&format!("source-{suffix}.txt"))
                        .is_some(),
                    !move_won,
                    "unexpected source retention after {method:?} collision"
                );
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn file_copy_move_overwrite_folder_conflict_preserves_resources_until_retry() {
        let _test_lock = INTEGRATION_TEST_LOCK.lock().await;
        let primary = bounded(ServerFixture::new(), "build overwrite DAV server").await;
        let account_id = bounded(
            primary.create_user_account("dav-overwrite", "dav-overwrite.test"),
            "seed overwrite DAV account",
        )
        .await;
        let secondary = bounded(
            primary.new_with_shared_primary(),
            "build independent overwrite DAV server",
        )
        .await;
        let resource = DavResourceName::File;
        let base = resource.account_base_path("dav-overwrite@dav-overwrite.test");
        let access = token(account_id);

        for method in [DavMethod::COPY, DavMethod::MOVE] {
            let suffix = if matches!(method, DavMethod::COPY) {
                "copy"
            } else {
                "move"
            };
            let source_name = format!("source-{suffix}.txt");
            let destination_name = format!("destination-{suffix}");
            let source_uri = format!("{base}{source_name}");
            let destination_uri = format!("{base}{destination_name}");
            let old_child_uri = format!("{destination_uri}/old-child.txt");

            assert_eq!(
                dispatch_status(
                    &primary.server,
                    access.clone(),
                    resource,
                    DavMethod::MKCOL,
                    &destination_uri,
                    None,
                    None,
                    &[],
                    false,
                    false,
                )
                .await,
                StatusCode::CREATED
            );
            assert_eq!(
                dispatch_status(
                    &primary.server,
                    access.clone(),
                    resource,
                    DavMethod::PUT,
                    &source_uri,
                    None,
                    Some("text/plain"),
                    FILE_BODY,
                    true,
                    false,
                )
                .await,
                StatusCode::CREATED
            );
            assert_eq!(
                dispatch_status(
                    &primary.server,
                    access.clone(),
                    resource,
                    DavMethod::PUT,
                    &old_child_uri,
                    None,
                    Some("text/plain"),
                    b"old destination body\r\n",
                    true,
                    false,
                )
                .await,
                StatusCode::CREATED
            );
            let _ = preload(&primary.server, account_id, SyncCollection::FileNode).await;
            let _ = preload(&secondary.server, account_id, SyncCollection::FileNode).await;

            let (prepared, resume) = crate::file::copy_move::set_test_transfer_prepare_pause();
            let request_server = primary.server.clone();
            let request_access = access.clone();
            let request_source_uri = source_uri.clone();
            let request_destination_uri = destination_uri.clone();
            let overwrite = tokio::spawn(async move {
                dispatch_once(
                    &request_server,
                    request_access,
                    resource,
                    method,
                    &request_source_uri,
                    Some(&request_destination_uri),
                )
                .await
            });
            bounded(prepared, "wait for overwrite transaction staging")
                .await
                .expect("overwrite reached transaction staging");

            secondary
                .server
                .inner
                .mark_cache_stale(account_id, SyncCollection::FileNode);
            let paused_resources =
                preload(&secondary.server, account_id, SyncCollection::FileNode).await;
            assert!(paused_resources.by_path(&source_name).is_some());
            assert!(paused_resources.by_path(&destination_name).is_some());
            assert!(
                paused_resources
                    .by_path(&format!("{destination_name}/old-child.txt"))
                    .is_some(),
                "overwrite deleted the destination before its fenced commit"
            );

            let competing_uri = format!("{base}competing-{suffix}.txt");
            assert_eq!(
                dispatch_status(
                    &secondary.server,
                    access.clone(),
                    resource,
                    DavMethod::PUT,
                    &competing_uri,
                    None,
                    Some("text/plain"),
                    FILE_BODY,
                    true,
                    false,
                )
                .await,
                StatusCode::CREATED
            );
            resume.send(()).expect("resume fenced overwrite");
            let stale_attempt = bounded(overwrite, "finish stale overwrite attempt")
                .await
                .expect("overwrite task completed");
            assert!(matches!(
                stale_attempt,
                Err(DavError::Internal(err)) if err.is_assertion_failure()
            ));

            secondary
                .server
                .inner
                .mark_cache_stale(account_id, SyncCollection::FileNode);
            let after_conflict =
                preload(&secondary.server, account_id, SyncCollection::FileNode).await;
            assert!(after_conflict.by_path(&source_name).is_some());
            assert!(after_conflict.by_path(&destination_name).is_some());
            assert!(
                after_conflict
                    .by_path(&format!("{destination_name}/old-child.txt"))
                    .is_some(),
                "failed fenced overwrite removed the destination folder"
            );
            assert!(
                after_conflict
                    .by_path(&format!("competing-{suffix}.txt"))
                    .is_some()
            );

            assert_eq!(
                dispatch_status(
                    &secondary.server,
                    access.clone(),
                    resource,
                    method,
                    &source_uri,
                    Some(&destination_uri),
                    None,
                    &[],
                    false,
                    false,
                )
                .await,
                StatusCode::NO_CONTENT,
                "successful retry should complete {method:?} overwrite"
            );

            let after_retry =
                preload(&secondary.server, account_id, SyncCollection::FileNode).await;
            assert_eq!(
                after_retry.by_path(&source_name).is_some(),
                matches!(method, DavMethod::COPY),
                "unexpected source state after {method:?} retry"
            );
            assert!(after_retry.by_path(&destination_name).is_some());
            assert!(
                after_retry
                    .by_path(&format!("{destination_name}/old-child.txt"))
                    .is_none(),
                "successful retry left the overwritten folder child in place"
            );
            let response = match dispatch_once(
                &secondary.server,
                access.clone(),
                resource,
                DavMethod::GET,
                &destination_uri,
                None,
            )
            .await
            {
                Ok(response) => response,
                Err(_) => panic!("read overwritten file after retry"),
            };
            assert_eq!(response.status(), StatusCode::OK);
            assert!(matches!(
                response.body(),
                http_proto::HttpResponseBody::Binary(body) if body.as_ref() == FILE_BODY
            ));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn large_directory_copy_and_move_collisions_are_atomic() {
        let _test_lock = INTEGRATION_TEST_LOCK.lock().await;
        const CHILD_COUNT: u32 = 1100;

        let primary = bounded(ServerFixture::new(), "build large file DAV server").await;
        let account_id = bounded(
            primary.create_user_account("dav-large", "dav-large-collision.test"),
            "seed large file DAV account",
        )
        .await;
        let secondary = bounded(
            primary.new_with_shared_primary(),
            "build independent large file DAV server",
        )
        .await;
        assert!(!Arc::ptr_eq(&primary.server.inner, &secondary.server.inner));
        let resource = DavResourceName::File;
        let base = resource.account_base_path("dav-large@dav-large-collision.test");
        let access = token(account_id);

        for method in [DavMethod::COPY, DavMethod::MOVE] {
            let suffix = if matches!(method, DavMethod::COPY) {
                "copy"
            } else {
                "move"
            };
            let target_parent = format!("target-parent-{suffix}");
            assert_eq!(
                dispatch_status(
                    &primary.server,
                    access.clone(),
                    resource,
                    DavMethod::MKCOL,
                    &format!("{base}{target_parent}"),
                    None,
                    None,
                    &[],
                    false,
                    false,
                )
                .await,
                StatusCode::CREATED
            );
            let reference_source = format!("source-{suffix}-R");
            let reference_target = format!("{target_parent}/target-{suffix}-0");
            seed_large_file_directory(
                &primary.server,
                account_id,
                &access,
                &base,
                &reference_source,
                CHILD_COUNT,
            )
            .await;
            let _ = preload(&primary.server, account_id, SyncCollection::FileNode).await;
            let before_reference = stats(
                &primary.server,
                account_id,
                SyncCollection::FileNode,
                StorageQuota::MaxFiles,
            )
            .await;
            let reference_status = dispatch_status(
                &primary.server,
                access.clone(),
                resource,
                method,
                &format!("{base}{reference_source}"),
                Some(&format!("{base}{reference_target}")),
                None,
                &[],
                false,
                true,
            )
            .await;
            assert_eq!(reference_status, StatusCode::CREATED);
            let after_reference = stats(
                &primary.server,
                account_id,
                SyncCollection::FileNode,
                StorageQuota::MaxFiles,
            )
            .await;
            let expected_delta = (
                after_reference.0 as isize - before_reference.0 as isize,
                after_reference.1 as isize - before_reference.1 as isize,
                after_reference.2 - before_reference.2,
            );

            let source_a = format!("source-{suffix}-A");
            let source_b = format!("source-{suffix}-B");
            seed_large_file_directory(
                &primary.server,
                account_id,
                &access,
                &base,
                &source_a,
                CHILD_COUNT,
            )
            .await;
            seed_large_file_directory(
                &primary.server,
                account_id,
                &access,
                &base,
                &source_b,
                CHILD_COUNT,
            )
            .await;
            let before_resources =
                preload(&primary.server, account_id, SyncCollection::FileNode).await;
            let before_stats = stats(
                &primary.server,
                account_id,
                SyncCollection::FileNode,
                StorageQuota::MaxFiles,
            )
            .await;
            let _ = preload(&secondary.server, account_id, SyncCollection::FileNode).await;
            crate::common::create::set_test_prepare_barrier(2);

            let target_name = format!("target-{suffix}-1");
            let target_uri = format!("{base}{target_parent}/{target_name}");
            let source_a_uri = format!("{base}{source_a}");
            let source_b_uri = format!("{base}{source_b}");
            let first = dispatch_status(
                &primary.server,
                access.clone(),
                resource,
                method,
                &source_a_uri,
                Some(&target_uri),
                None,
                &[],
                false,
                true,
            );
            let second = dispatch_status(
                &secondary.server,
                access.clone(),
                resource,
                method,
                &source_b_uri,
                Some(&target_uri),
                None,
                &[],
                false,
                true,
            );
            let (first_status, second_status) = bounded(
                async { tokio::join!(first, second) },
                "large directory COPY/MOVE collision",
            )
            .await;
            assert!(matches!(
                (first_status, second_status),
                (StatusCode::CREATED, StatusCode::PRECONDITION_FAILED)
                    | (StatusCode::PRECONDITION_FAILED, StatusCode::CREATED)
            ));

            let after_resources =
                preload(&secondary.server, account_id, SyncCollection::FileNode).await;
            assert!(
                after_resources
                    .by_path(&format!("{target_parent}/{target_name}"))
                    .is_some()
            );
            assert!(
                after_resources
                    .by_path(&format!("{target_parent}/{target_name}/child-0000"))
                    .is_some()
            );
            assert!(
                after_resources
                    .by_path(&format!("{target_parent}/{target_name}/child-1099"))
                    .is_some()
            );

            let (winner_source, loser_source) = if first_status == StatusCode::CREATED {
                (&source_a, &source_b)
            } else {
                (&source_b, &source_a)
            };
            if matches!(method, DavMethod::COPY) {
                assert!(after_resources.by_path(&source_a).is_some());
                assert!(after_resources.by_path(&source_b).is_some());
                assert_eq!(
                    after_resources.resources.total,
                    before_resources.resources.total + CHILD_COUNT as usize + 1
                );
            } else {
                assert!(after_resources.by_path(winner_source).is_none());
                assert!(after_resources.by_path(loser_source).is_some());
                assert_eq!(
                    after_resources.resources.total,
                    before_resources.resources.total
                );
            }

            let after_stats = stats(
                &primary.server,
                account_id,
                SyncCollection::FileNode,
                StorageQuota::MaxFiles,
            )
            .await;
            assert_eq!(
                (
                    after_stats.0 as isize - before_stats.0 as isize,
                    after_stats.1 as isize - before_stats.1 as isize,
                    after_stats.2 - before_stats.2,
                ),
                expected_delta,
                "the losing request added no resource, log, or quota effects"
            );
        }
    }
}
