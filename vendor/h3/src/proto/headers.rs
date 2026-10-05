use std::{
    convert::TryFrom,
    fmt,
    iter::{IntoIterator, Iterator},
    str::FromStr,
};

use http::{
    header::{self, HeaderName, HeaderValue},
    uri::{self, Authority, Parts, PathAndQuery, Scheme, Uri},
    Extensions, HeaderMap, Method, StatusCode,
};

use crate::{
    ext::{OtherProtocol, Protocol},
    qpack::HeaderField,
};

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Clone))]
pub struct Header {
    pseudo: Pseudo,
    fields: HeaderMap,
}

#[allow(clippy::len_without_is_empty)]
impl Header {
    /// Creates a new `Header` frame data suitable for sending a request
    pub fn request(
        method: Method,
        uri: Uri,
        fields: HeaderMap,
        ext: Extensions,
    ) -> Result<Self, HeaderError> {
        match (uri.authority(), fields.get("host")) {
            (None, None) => Err(HeaderError::MissingAuthority),
            (Some(a), Some(h)) if a.as_str() != h => Err(HeaderError::ContradictedAuthority),
            _ => Ok(Self {
                pseudo: Pseudo::request(method, uri, ext),
                fields,
            }),
        }
    }

    pub fn response(status: StatusCode, fields: HeaderMap) -> Self {
        Self {
            pseudo: Pseudo::response(status),
            fields,
        }
    }

    pub fn trailer(fields: HeaderMap) -> Self {
        Self {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
            //# Pseudo-header fields MUST NOT appear in trailer
            //# sections.
            pseudo: Pseudo::default(),
            fields,
        }
    }

    pub fn into_request_parts(
        self,
    ) -> Result<
        (
            Method,
            Uri,
            Option<Protocol>,
            Option<OtherProtocol>,
            HeaderMap,
        ),
        HeaderError,
    > {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //# Pseudo-header fields defined for requests MUST NOT appear
        //# in responses; pseudo-header fields defined for responses MUST NOT
        //# appear in requests.
        if self.pseudo.status.is_some() {
            return Err(HeaderError::MalformedRequest(
                ":status in a request".into(),
            ));
        }
        let method = self.pseudo.method.ok_or(HeaderError::MissingMethod)?;
        let has_protocol = self.pseudo.protocol.is_some() || self.pseudo.other_protocol.is_some();
        if method == Method::CONNECT && !has_protocol {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.4
            //# The :scheme and :path pseudo-header fields are omitted.
            //# The :authority pseudo-header field contains the host and port
            //# to connect to
            //# A CONNECT request that does not conform to these restrictions
            //# is malformed; see Section 4.1.2.
            if self.pseudo.scheme.is_some() || self.pseudo.path.is_some() {
                return Err(HeaderError::MalformedRequest(
                    "CONNECT with :scheme or :path".into(),
                ));
            }
            if self.pseudo.authority.is_none() {
                return Err(HeaderError::MissingAuthority);
            }
        } else {
            //= https://www.rfc-editor.org/rfc/rfc8441#section-4
            //# A CONNECT request with :protocol (extended CONNECT, RFC 9220)
            //# includes :scheme and :path; :protocol is only defined for
            //# CONNECT.
            if has_protocol && method != Method::CONNECT {
                return Err(HeaderError::MalformedRequest(
                    ":protocol without CONNECT".into(),
                ));
            }
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
            //# All HTTP/3 requests MUST include exactly one value for the :method,
            //# :scheme, and :path pseudo-header fields, unless the request is a
            //# CONNECT request; see Section 4.4.
            let (Some(scheme), Some(path)) = (&self.pseudo.scheme, &self.pseudo.path) else {
                return Err(HeaderError::MalformedRequest(
                    "missing :scheme or :path".into(),
                ));
            };
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
            //# This pseudo-header field MUST NOT be empty for "http" or "https"
            //# URIs
            let http = *scheme == Scheme::HTTP || *scheme == Scheme::HTTPS;
            if http && self.pseudo.path_empty {
                return Err(HeaderError::MalformedRequest("empty :path".into()));
            }
            if http && path.as_str() == "*" && method != Method::OPTIONS {
                return Err(HeaderError::MalformedRequest(
                    "\"*\" :path without OPTIONS".into(),
                ));
            }
            if has_protocol && self.pseudo.authority.is_none() {
                return Err(HeaderError::MissingAuthority);
            }
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
        //# An endpoint MUST NOT generate an HTTP/3 field section containing
        //# connection-specific fields; any message containing
        //# connection-specific fields MUST be treated as malformed.
        //# The only exception to this is the TE header field, which MAY be
        //# present in an HTTP/3 request header; when it is, it MUST NOT contain
        //# any value other than "trailers".
        for name in ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"] {
            if self.fields.contains_key(name) {
                return Err(HeaderError::MalformedRequest(format!("connection-specific field {}", name)));
            }
        }
        if self.fields.get_all("te").iter().any(|v| v.as_bytes() != b"trailers") {
            return Err(HeaderError::MalformedRequest("TE other than trailers".into()));
        }

        let mut uri = Uri::builder();

        if let Some(path) = self.pseudo.path {
            uri = uri.path_and_query(path.as_str().as_bytes());
        }

        if let Some(scheme) = self.pseudo.scheme {
            uri = uri.scheme(scheme.as_str().as_bytes());
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=TODO
        //# If the scheme does not have a mandatory authority component and none
        //# is provided in the request target, the request MUST NOT contain the
        //# :authority pseudo-header or Host header fields.
        match (self.pseudo.authority, self.fields.get("host")) {
            (None, None) => return Err(HeaderError::MissingAuthority),
            (Some(a), None) => uri = uri.authority(a.as_str().as_bytes()),
            (None, Some(h)) => uri = uri.authority(h.as_bytes()),
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
            //# If both fields are present, they MUST contain the same value.
            (Some(a), Some(h)) if a.as_str() != h => {
                return Err(HeaderError::ContradictedAuthority)
            }
            (Some(_), Some(h)) => uri = uri.authority(h.as_bytes()),
        }

        Ok((
            method,
            // When empty host field is built into an uri it fails
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
            //# If these fields are present, they MUST NOT be
            //# empty.
            uri.build().map_err(HeaderError::InvalidRequest)?,
            self.pseudo.protocol,
            self.pseudo.other_protocol,
            self.fields,
        ))
    }

    pub fn into_response_parts(self) -> Result<(StatusCode, HeaderMap), HeaderError> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.2
        //= type=implication
        //# For responses, a single ":status" pseudo-header field is defined that
        //# carries the HTTP status code; see Section 15 of [HTTP].  This pseudo-
        //# header field MUST be included in all responses; otherwise, the
        //# response is malformed (see Section 4.1.2).
        let p = &self.pseudo;
        if p.method.is_some()
            || p.scheme.is_some()
            || p.authority.is_some()
            || p.path.is_some()
            || p.protocol.is_some()
            || p.other_protocol.is_some()
        {
            return Err(HeaderError::MalformedRequest(
                "request pseudo-header in a response".into(),
            ));
        }
        Ok((
            self.pseudo.status.ok_or(HeaderError::MissingStatus)?,
            self.fields,
        ))
    }

    pub fn into_fields(self) -> HeaderMap {
        self.fields
    }

    pub fn len(&self) -> usize {
        self.pseudo.len() + self.fields.len()
    }

    pub fn size(&self) -> usize {
        self.pseudo.len() + self.fields.len()
    }

    #[cfg(test)]
    pub(crate) fn authory_mut(&mut self) -> &mut Option<Authority> {
        &mut self.pseudo.authority
    }
}

impl IntoIterator for Header {
    type Item = HeaderField;
    type IntoIter = HeaderIter;
    fn into_iter(self) -> Self::IntoIter {
        HeaderIter {
            pseudo: Some(self.pseudo),
            last_header_name: None,
            fields: self.fields.into_iter(),
        }
    }
}

pub struct HeaderIter {
    pseudo: Option<Pseudo>,
    last_header_name: Option<HeaderName>,
    fields: header::IntoIter<HeaderValue>,
}

impl Iterator for HeaderIter {
    type Item = HeaderField;

    fn next(&mut self) -> Option<Self::Item> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //# All pseudo-header fields MUST appear in the header section before
        //# regular header fields.
        if let Some(ref mut pseudo) = self.pseudo {
            if let Some(method) = pseudo.method.take() {
                return Some((":method", method.as_str()).into());
            }

            if let Some(scheme) = pseudo.scheme.take() {
                return Some((":scheme", scheme.as_str().as_bytes()).into());
            }

            if let Some(authority) = pseudo.authority.take() {
                return Some((":authority", authority.as_str().as_bytes()).into());
            }

            if let Some(path) = pseudo.path.take() {
                return Some((":path", path.as_str().as_bytes()).into());
            }

            if let Some(status) = pseudo.status.take() {
                return Some((":status", status.as_str()).into());
            }

            if let Some(protocol) = pseudo.protocol.take() {
                return Some((":protocol", protocol.as_str().as_bytes()).into());
            }
        }

        self.pseudo = None;

        for (new_header_name, header_value) in self.fields.by_ref() {
            if let Some(new) = new_header_name {
                self.last_header_name = Some(new);
            }
            if let (Some(ref n), v) = (&self.last_header_name, header_value) {
                return Some((n.as_str(), v.as_bytes()).into());
            }
        }

        None
    }
}

impl TryFrom<Vec<HeaderField>> for Header {
    type Error = HeaderError;
    fn try_from(headers: Vec<HeaderField>) -> Result<Self, Self::Error> {
        let mut fields = HeaderMap::with_capacity(headers.len());
        let mut pseudo = Pseudo::default();
        let mut regular_field_seen = false;

        for field in headers.into_iter() {
            let (name, value) = field.into_inner();
            match Field::parse(name, value)? {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
                //# Any request or response that contains a
                //# pseudo-header field that appears in a header section after a regular
                //# header field MUST be treated as malformed.
                Field::Method(_)
                | Field::Scheme(_)
                | Field::Authority(_)
                | Field::Path(_)
                | Field::Status(_)
                | Field::Protocol(_)
                | Field::OtherProtocol(_)
                    if regular_field_seen =>
                {
                    return Err(HeaderError::PseudoAfterRegularField)
                }
                //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
                //# All HTTP/3 requests MUST include exactly one value for the :method,
                //# :scheme, and :path pseudo-header fields
                Field::Method(_) if pseudo.method.is_some() => return Err(HeaderError::DuplicatePseudo),
                Field::Scheme(_) if pseudo.scheme.is_some() => return Err(HeaderError::DuplicatePseudo),
                Field::Authority(_) if pseudo.authority.is_some() => {
                    return Err(HeaderError::DuplicatePseudo)
                }
                Field::Path(_) if pseudo.path.is_some() => return Err(HeaderError::DuplicatePseudo),
                Field::Status(_) if pseudo.status.is_some() => return Err(HeaderError::DuplicatePseudo),
                Field::Protocol(_) | Field::OtherProtocol(_)
                    if pseudo.protocol.is_some() || pseudo.other_protocol.is_some() =>
                {
                    return Err(HeaderError::DuplicatePseudo)
                }
                Field::Method(m) => {
                    pseudo.method = Some(m);
                    pseudo.len += 1;
                }
                Field::Scheme(s) => {
                    pseudo.scheme = Some(s);
                    pseudo.len += 1;
                }
                Field::Authority(a) => {
                    pseudo.authority = Some(a);
                    pseudo.len += 1;
                }
                Field::Path((p, empty)) => {
                    pseudo.path = Some(p);
                    pseudo.path_empty = empty;
                    pseudo.len += 1;
                }
                Field::Status(s) => {
                    pseudo.status = Some(s);
                    pseudo.len += 1;
                }
                Field::Header((n, v)) => {
                    regular_field_seen = true;
                    fields.append(n, v);
                }
                Field::Protocol(p) => {
                    pseudo.protocol = Some(p);
                    pseudo.len += 1;
                }
                Field::OtherProtocol(p) => {
                    pseudo.other_protocol = Some(p);
                    pseudo.len += 1;
                }
            }
        }

        Ok(Header { pseudo, fields })
    }
}

enum Field {
    Method(Method),
    Scheme(Scheme),
    Authority(Authority),
    /// The path, and whether the field was empty.
    Path((PathAndQuery, bool)),
    Status(StatusCode),
    Protocol(Protocol),
    OtherProtocol(OtherProtocol),
    Header((HeaderName, HeaderValue)),
}

impl Field {
    fn parse<N, V>(name: N, value: V) -> Result<Self, HeaderError>
    where
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let name = name.as_ref();
        if name.is_empty() {
            return Err(HeaderError::InvalidHeaderName("name is empty".into()));
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-10.3
        //# Requests or responses containing invalid field names MUST be treated
        //# as malformed.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-10.3
        //# Any request or response that contains a
        //# character not permitted in a field value MUST be treated as
        //# malformed.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
        //= type=implication
        //# A request or
        //# response containing uppercase characters in field names MUST be
        //# treated as malformed.

        if name[0] != b':' {
            return Ok(Field::Header((
                HeaderName::from_lowercase(name).map_err(|_| HeaderError::invalid_name(name))?,
                HeaderValue::from_bytes(value.as_ref())
                    .map_err(|_| HeaderError::invalid_value(name, value))?,
            )));
        }

        Ok(match name {
            b":scheme" => Field::Scheme(try_value(name, value)?),
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
            //# If these fields are present, they MUST NOT be
            //# empty.
            b":authority" => Field::Authority(try_value(name, value)?),
            b":path" => {
                let value = value.as_ref();
                Field::Path((try_value(name, value)?, value.is_empty()))
            }
            b":method" => Field::Method(
                Method::from_bytes(value.as_ref())
                    .map_err(|_| HeaderError::invalid_value(name, value))?,
            ),
            b":status" => Field::Status(
                StatusCode::from_bytes(value.as_ref())
                    .map_err(|_| HeaderError::invalid_value(name, value))?,
            ),
            //= https://www.rfc-editor.org/rfc/rfc8441#section-4
            //# The :protocol pseudo-header field takes values from the HTTP
            //# Upgrade Token Registry: any token is well-formed.
            b":protocol" => match try_value::<_, _, Protocol>(name, value.as_ref()) {
                Ok(p) => Field::Protocol(p),
                Err(_) if is_token(value.as_ref()) => Field::OtherProtocol(OtherProtocol(
                    String::from_utf8(value.as_ref().to_vec()).expect("tokens are ASCII"),
                )),
                Err(e) => return Err(e),
            },
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
            //# Endpoints MUST treat a request or response that contains
            //# undefined or invalid pseudo-header fields as malformed.
            _ => return Err(HeaderError::invalid_name(name)),
        })
    }
}

/// An RFC 9110 section 5.6.2 token.
fn is_token(value: &[u8]) -> bool {
    !value.is_empty()
        && value.iter().all(|c| {
            c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(c)
        })
}

fn try_value<N, V, R>(name: N, value: V) -> Result<R, HeaderError>
where
    N: AsRef<[u8]>,
    V: AsRef<[u8]>,
    R: FromStr,
{
    let (name, value) = (name.as_ref(), value.as_ref());
    let s = std::str::from_utf8(value).map_err(|_| HeaderError::invalid_value(name, value))?;
    R::from_str(s).map_err(|_| HeaderError::invalid_value(name, value))
}

/// Pseudo-header fields have the same purpose as data from the first line of HTTP/1.X,
/// but are conveyed along with other headers. For example ':method' and ':path' in a
/// request, and ':status' in a response. They must be placed before all other fields,
/// start with ':', and be lowercase.
/// See RFC7540 section 8.1.2.1. for more details.
#[derive(Debug, Default)]
#[cfg_attr(test, derive(PartialEq, Clone))]
struct Pseudo {
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
    //= type=implication
    //# Endpoints MUST NOT
    //# generate pseudo-header fields other than those defined in this
    //# document.

    // Request
    method: Option<Method>,
    scheme: Option<Scheme>,
    authority: Option<Authority>,
    path: Option<PathAndQuery>,

    // Response
    status: Option<StatusCode>,

    protocol: Option<Protocol>,
    /// A received `:protocol` that is not a known [`Protocol`].
    other_protocol: Option<OtherProtocol>,
    /// Whether a received `:path` was empty.
    path_empty: bool,

    len: usize,
}

#[allow(clippy::len_without_is_empty)]
impl Pseudo {
    fn request(method: Method, uri: Uri, ext: Extensions) -> Self {
        let Parts {
            scheme,
            authority,
            path_and_query,
            ..
        } = uri::Parts::from(uri);

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=implication
        //# This pseudo-header field MUST NOT be empty for "http" or "https"
        //# URIs; "http" or "https" URIs that do not contain a path component
        //# MUST include a value of / (ASCII 0x2f).
        let path = path_and_query.map_or_else(
            || PathAndQuery::from_static("/"),
            |path| {
                if path.path().is_empty() && method != Method::OPTIONS {
                    PathAndQuery::from_static("/")
                } else {
                    path
                }
            },
        );

        // If the method is connect, the `:protocol` pseudo-header MAY be defined
        //
        // See: [https://www.rfc-editor.org/rfc/rfc8441#section-4]
        let protocol = if method == Method::CONNECT {
            ext.get::<Protocol>().copied()
        } else {
            None
        };

        // For standard CONNECT (that is, without :protocol pseudo-header) scheme and path
        // are not set. See: [https://www.rfc-editor.org/rfc/rfc9114#section-4.4]
        let (scheme, path) = if method == Method::CONNECT && protocol.is_none() {
            (None, None)
        } else {
            (scheme.or(Some(Scheme::HTTPS)), Some(path))
        };

        let len = 3 + authority.is_some() as usize + protocol.is_some() as usize;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //= type=implication
        //# Pseudo-header fields defined for requests MUST NOT appear
        //# in responses; pseudo-header fields defined for responses MUST NOT
        //# appear in requests.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=implication
        //# All HTTP/3 requests MUST include exactly one value for the :method,
        //# :scheme, and :path pseudo-header fields, unless the request is a
        //# CONNECT request; see Section 4.4.
        Self {
            method: Some(method),
            scheme,
            authority,
            path,
            status: None,
            protocol,
            other_protocol: None,
            path_empty: false,
            len,
        }
    }

    fn response(status: StatusCode) -> Self {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //= type=implication
        //# Pseudo-header fields defined for requests MUST NOT appear
        //# in responses; pseudo-header fields defined for responses MUST NOT
        //# appear in requests.
        Pseudo {
            method: None,
            scheme: None,
            authority: None,
            path: None,
            status: Some(status),
            len: 1,
            protocol: None,
            other_protocol: None,
            path_empty: false,
        }
    }

    fn len(&self) -> usize {
        self.len
    }
}

#[derive(Debug)]
pub enum HeaderError {
    InvalidHeaderName(String),
    InvalidHeaderValue(String),
    InvalidRequest(http::Error),
    MissingMethod,
    MissingStatus,
    MissingAuthority,
    ContradictedAuthority,
    PseudoAfterRegularField,
    DuplicatePseudo,
    MalformedRequest(String),
}

impl HeaderError {
    fn invalid_name<N>(name: N) -> Self
    where
        N: AsRef<[u8]>,
    {
        HeaderError::InvalidHeaderName(format!("{:?}", name.as_ref()))
    }

    fn invalid_value<N, V>(name: N, value: V) -> Self
    where
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        HeaderError::InvalidHeaderValue(format!(
            "{:?} {:?}",
            String::from_utf8_lossy(name.as_ref()),
            value.as_ref()
        ))
    }
}

impl std::error::Error for HeaderError {}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderError::InvalidHeaderName(h) => write!(f, "invalid header name: {}", h),
            HeaderError::InvalidHeaderValue(v) => write!(f, "invalid header value: {}", v),
            HeaderError::InvalidRequest(r) => write!(f, "invalid request: {}", r),
            HeaderError::MissingMethod => write!(f, "missing method in request headers"),
            HeaderError::MissingStatus => write!(f, "missing status in response headers"),
            HeaderError::MissingAuthority => write!(f, "missing authority"),
            HeaderError::ContradictedAuthority => {
                write!(f, "uri and authority field are in contradiction")
            }
            HeaderError::PseudoAfterRegularField => {
                write!(
                    f,
                    "pseudo-header field appears after a regular header field"
                )
            }
            HeaderError::DuplicatePseudo => write!(f, "pseudo-header field appears twice"),
            HeaderError::MalformedRequest(why) => write!(f, "malformed request: {}", why),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;

    #[test]
    fn request_has_no_authority_nor_host() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":scheme", b"https").into(),
            (b":path", b"/").into(),
        ])
        .unwrap();
        assert!(headers.pseudo.authority.is_none());
        assert_matches!(
            headers.into_request_parts(),
            Err(HeaderError::MissingAuthority)
        );
    }

    #[test]
    fn request_has_empty_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If these fields are present, they MUST NOT be
        //# empty.
        assert_matches!(
            Header::try_from(vec![
                (b":method", Method::GET.as_str()).into(),
                (b":authority", b"").into(),
            ]),
            Err(HeaderError::InvalidHeaderValue(_))
        );
    }

    #[test]
    fn request_has_empty_host() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If these fields are present, they MUST NOT be
        //# empty.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":scheme", b"https").into(),
            (b":path", b"/").into(),
            (b"host", b"").into(),
        ])
        .unwrap();
        assert_matches!(
            headers.into_request_parts(),
            Err(HeaderError::InvalidRequest(_))
        );
    }

    #[test]
    fn request_has_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":scheme", b"https").into(),
            (b":path", b"/").into(),
            (b":authority", b"test.com").into(),
        ])
        .unwrap();
        assert_matches!(headers.into_request_parts(), Ok(_));
    }

    #[test]
    fn request_has_host() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":scheme", b"https").into(),
            (b":path", b"/").into(),
            (b"host", b"test.com").into(),
        ])
        .unwrap();
        assert!(headers.pseudo.authority.is_none());
        assert_matches!(headers.into_request_parts(), Ok(_));
    }

    #[test]
    fn request_has_same_host_and_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If both fields are present, they MUST contain the same value.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":scheme", b"https").into(),
            (b":path", b"/").into(),
            (b":authority", b"test.com").into(),
            (b"host", b"test.com").into(),
        ])
        .unwrap();
        assert_matches!(headers.into_request_parts(), Ok(_));
    }
    #[test]
    fn request_has_different_host_and_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If both fields are present, they MUST contain the same value.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":scheme", b"https").into(),
            (b":path", b"/").into(),
            (b":authority", b"authority.com").into(),
            (b"host", b"host.com").into(),
        ])
        .unwrap();
        assert_matches!(
            headers.into_request_parts(),
            Err(HeaderError::ContradictedAuthority)
        );
    }

    #[test]
    fn preserves_duplicate_headers() {
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":scheme", b"https").into(),
            (b":path", b"/").into(),
            (b":authority", b"test.com").into(),
            (b"set-cookie", b"foo=foo").into(),
            (b"set-cookie", b"bar=bar").into(),
            (b"other-header", b"other-header-value").into(),
        ])
        .unwrap();

        assert_eq!(
            headers
                .clone()
                .into_iter()
                .filter(|h| h.name.as_ref() == b"set-cookie")
                .collect::<Vec<_>>(),
            vec![
                HeaderField {
                    name: std::borrow::Cow::Borrowed(b"set-cookie"),
                    value: std::borrow::Cow::Borrowed(b"foo=foo")
                },
                HeaderField {
                    name: std::borrow::Cow::Borrowed(b"set-cookie"),
                    value: std::borrow::Cow::Borrowed(b"bar=bar")
                }
            ]
        );
        assert_eq!(
            headers
                .into_iter()
                .filter(|h| h.name.as_ref() == b"other-header")
                .collect::<Vec<_>>(),
            vec![HeaderField {
                name: std::borrow::Cow::Borrowed(b"other-header"),
                value: std::borrow::Cow::Borrowed(b"other-header-value")
            },]
        );
    }

    #[test]
    fn rejects_undefined_pseudo_header() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //= type=test
        //# Endpoints MUST treat a request or response that contains
        //# undefined or invalid pseudo-header fields as malformed.
        assert_matches!(
            Header::try_from(vec![(b":unknown", b"value").into()]),
            Err(HeaderError::InvalidHeaderName(_))
        );
    }

    #[test]
    fn rejects_pseudo_header_after_regular_header() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //= type=test
        //# Any request or response that contains a
        //# pseudo-header field that appears in a header section after a regular
        //# header field MUST be treated as malformed.
        assert_matches!(
            Header::try_from(vec![
                (b"regular", b"value").into(),
                (b":method", b"GET").into(),
            ]),
            Err(HeaderError::PseudoAfterRegularField)
        );
    }

    fn request(fields: &[(&str, &str)]) -> Result<Header, HeaderError> {
        Header::try_from(
            fields
                .iter()
                .map(|(n, v)| HeaderField::new(n.as_bytes().to_vec(), v.as_bytes().to_vec()))
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn classic_connect_has_only_method_and_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.4
        //= type=test
        //# A CONNECT request that does not conform to these restrictions is
        //# malformed
        let ok = request(&[(":method", "CONNECT"), (":authority", "example.com:443")]).unwrap();
        let (method, uri, ..) = ok.into_request_parts().unwrap();
        assert_eq!((method, uri.authority().unwrap().as_str()), (Method::CONNECT, "example.com:443"));
        for extra in [(":scheme", "https"), (":path", "/")] {
            let h = request(&[(":method", "CONNECT"), extra, (":authority", "example.com:443")]).unwrap();
            assert_matches!(h.into_request_parts(), Err(HeaderError::MalformedRequest(_)));
        }
        let host_only = request(&[(":method", "CONNECT"), ("host", "example.com:443")]).unwrap();
        assert_matches!(host_only.into_request_parts(), Err(HeaderError::MissingAuthority));
    }

    #[test]
    fn extended_connect_needs_scheme_path_and_authority() {
        //= https://www.rfc-editor.org/rfc/rfc8441#section-4
        //= type=test
        //# On requests that contain the :protocol pseudo-header field, the
        //# :scheme and :path pseudo-header fields of the target URI MUST also
        //# be included.
        let full = [
            (":method", "CONNECT"),
            (":protocol", "connect-udp"),
            (":scheme", "https"),
            (":path", "/.well-known/masque/udp/192.0.2.1/443/"),
            (":authority", "relay.example"),
        ];
        let (_, _, protocol, other, _) = request(&full).unwrap().into_request_parts().unwrap();
        assert_eq!((protocol, other), (Some(Protocol::CONNECT_UDP), None));
        for skip in [2, 3, 4] {
            let partial: Vec<_> = full.iter().enumerate().filter(|(i, _)| *i != skip).map(|(_, f)| *f).collect();
            assert!(request(&partial).unwrap().into_request_parts().is_err(), "without {:?}", full[skip]);
        }
        let get = [(":method", "GET"), (":protocol", "connect-udp"), (":scheme", "https"), (":path", "/"), (":authority", "a")];
        assert_matches!(request(&get).unwrap().into_request_parts(), Err(HeaderError::MalformedRequest(_)));
    }

    #[test]
    fn unknown_protocol_tokens_reach_the_application() {
        let h = request(&[
            (":method", "CONNECT"),
            (":protocol", "connect-tcp"),
            (":scheme", "https"),
            (":path", "/"),
            (":authority", "relay.example"),
        ])
        .unwrap();
        let (_, _, protocol, other, _) = h.into_request_parts().unwrap();
        assert_eq!(protocol, None);
        assert_eq!(other.unwrap().as_str(), "connect-tcp");
        assert!(request(&[(":method", "CONNECT"), (":protocol", "not a token")]).is_err());
    }

    #[test]
    fn requests_need_exactly_one_method_scheme_and_path() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# All HTTP/3 requests MUST include exactly one value for the :method,
        //# :scheme, and :path pseudo-header fields, unless the request is a
        //# CONNECT request
        let missing_path = request(&[(":method", "GET"), (":scheme", "https"), (":authority", "a")]).unwrap();
        assert_matches!(missing_path.into_request_parts(), Err(HeaderError::MalformedRequest(_)));
        let missing_scheme = request(&[(":method", "GET"), (":path", "/"), (":authority", "a")]).unwrap();
        assert_matches!(missing_scheme.into_request_parts(), Err(HeaderError::MalformedRequest(_)));
        for twice in [":method", ":scheme", ":path", ":authority"] {
            let mut fields = vec![(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a")];
            let value = fields.iter().find(|(n, _)| *n == twice).unwrap().1;
            fields.insert(1, (twice, value));
            assert_matches!(request(&fields), Err(HeaderError::DuplicatePseudo), "{}", twice);
        }
        let empty_path = request(&[(":method", "GET"), (":scheme", "https"), (":path", ""), (":authority", "a")]);
        assert!(empty_path.map_or(true, |h| h.into_request_parts().is_err()));
        let status = request(&[(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a"), (":status", "200")]).unwrap();
        assert_matches!(status.into_request_parts(), Err(HeaderError::MalformedRequest(_)));
    }

    #[test]
    fn connection_specific_fields_are_malformed() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
        //= type=test
        //# any message containing connection-specific fields MUST be treated
        //# as malformed.
        let base = [(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a")];
        for field in [
            ("connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("proxy-connection", "keep-alive"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "connect-udp"),
            ("te", "gzip"),
        ] {
            let mut fields = base.to_vec();
            fields.push(field);
            assert_matches!(request(&fields).unwrap().into_request_parts(), Err(HeaderError::MalformedRequest(_)), "{:?}", field);
        }
        let mut fields = base.to_vec();
        fields.push(("te", "trailers"));
        assert!(request(&fields).unwrap().into_request_parts().is_ok(), "TE: trailers is allowed");
    }
}
