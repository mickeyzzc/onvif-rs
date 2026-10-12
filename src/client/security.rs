//! Device security client family — the Rust twin of the Go library's
//! `security` package: user management (GetUsers/CreateUsers/DeleteUsers/
//! SetUser), remote user, the IP-address filter trio plus its read form,
//! password complexity/history and auth-failure policy, and the
//! certificate lifecycle (load/create/delete/status/PKCS#10/client-cert
//! mode/access policy).
//!
//! All operations ride the device endpoint. Request envelopes mirror what
//! the Go package marshals byte-for-byte — including its two deliberate
//! namespace shapes: the users-family `tds:User` wrapper carries
//! `tt:`-prefixed children (WSDL fact: the wrapper is locally declared in
//! tds but typed `tt:User`), while the Go `LoadCACertificates` /
//! `SetAccessPolicy` / `SetCertificatesStatus` types marshal unprefixed
//! children because the Go structs carry no XML tags. Response decoding
//! is local-name tolerant via the shared walk in [`super::device`], and —
//! where the Go decode misses the schema shape (attributes such as
//! `ContentType`/`critical`) — accepts both spellings.

use base64::Engine as _;

use super::device::{
    attr_get, b64_bytes, esc, netmask_from_prefix_length, tail_is, tds_action, walk_local,
    xml_bool, xml_int, PrefixedIpv4Address, Step,
};
use super::{parse_xsd_datetime, ClientError, SoapClient, UtcStamp};

/// tds (device service) namespace.
const TDS_NS: &str = "http://www.onvif.org/ver10/device/wsdl";
/// tt (schema) namespace.
const TT_NS: &str = "http://www.onvif.org/ver10/schema";

// ---------------------------------------------------------------------------
// Types (mirroring the Go security package's types)
// ---------------------------------------------------------------------------

/// One user account. The GetUsers decode fills username and level only
/// (devices never return passwords); password matters for the writers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct User {
    /// Account name.
    pub username: String,
    /// Password (write-only on the wire; omitted from SetUser when empty).
    pub password: String,
    /// `Administrator`, `Operator` or `User`.
    pub user_level: String,
}

/// Remote (derived-credential) user configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteUser {
    /// Account name.
    pub username: String,
    /// Password.
    pub password: String,
    /// Whether the device derives passwords per-session.
    pub use_derived_password: bool,
}

/// An IPv6 address with prefix (Go `types.PrefixedIPv6Address`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrefixedIpv6Address {
    /// The IPv6 address.
    pub address: String,
    /// Prefix length.
    pub prefix_length: i32,
}

/// IP-address filter state: type plus the filtered address ranges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpAddressFilter {
    /// `Allow` or `Deny`.
    pub kind: String,
    /// IPv4 ranges.
    pub ipv4_address: Vec<PrefixedIpv4Address>,
    /// IPv6 ranges.
    pub ipv6_address: Vec<PrefixedIpv6Address>,
}

/// `Allow` filter type.
pub const IP_ADDRESS_FILTER_ALLOW: &str = "Allow";
/// `Deny` filter type.
pub const IP_ADDRESS_FILTER_DENY: &str = "Deny";

/// Binary payload (`xs:base64Binary` + content type).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BinaryData {
    /// MIME content type.
    pub content_type: String,
    /// Payload bytes.
    pub data: Vec<u8>,
}

/// One device certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Certificate {
    /// Certificate id.
    pub certificate_id: String,
    /// The certificate payload.
    pub certificate: BinaryData,
}

/// Certificate status entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificateStatus {
    /// Certificate id.
    pub certificate_id: String,
    /// Whether the certificate is in use / valid.
    pub status: bool,
}

/// A key-usage restriction (simpleContent: value text plus a `critical`
/// flag). Both the attribute shape and Go's element shape decode.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificateUsage {
    /// The `critical` attribute.
    pub critical: bool,
    /// The usage OID / keyword.
    pub value: String,
}

/// Certificate validity window; `None` ends mean "not reported".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DateTimeRange {
    /// Not-before instant.
    pub from: Option<UtcStamp>,
    /// Not-after instant.
    pub until: Option<UtcStamp>,
}

/// Certificate metadata (Go `CertificateInformation`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificateInformation {
    /// Certificate id.
    pub certificate_id: String,
    /// Issuer distinguished name.
    pub issuer_dn: String,
    /// Subject distinguished name.
    pub subject_dn: String,
    /// Key usage restriction.
    pub key_usage: Option<CertificateUsage>,
    /// Extended key usage restriction.
    pub extended_key_usage: Option<CertificateUsage>,
    /// Key length in bits.
    pub key_length: i32,
    /// Certificate version.
    pub version: String,
    /// Serial number.
    pub serial_num: String,
    /// Signature algorithm name.
    pub signature_algorithm: String,
    /// Validity window.
    pub validity: Option<DateTimeRange>,
}

/// Device access policy: an opaque policy-file payload.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessPolicy {
    /// The policy file (XACML) payload.
    pub policy_file: Option<BinaryData>,
}

/// Password complexity policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PasswordComplexityConfiguration {
    /// Minimum length.
    pub min_len: i32,
    /// Required uppercase characters.
    pub uppercase: i32,
    /// Required digits.
    pub number: i32,
    /// Required special characters.
    pub special_chars: i32,
    /// Whether the account name may not occur in the password.
    pub block_username_occurrence: bool,
    /// Whether the policy is locked (read-only).
    pub policy_configuration_locked: bool,
}

/// Password history policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PasswordHistoryConfiguration {
    /// Whether history is enforced.
    pub enabled: bool,
    /// Number of remembered passwords.
    pub length: i32,
}

/// Authentication-failure lockout policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthFailureWarningConfiguration {
    /// Whether the warning is enabled.
    pub enabled: bool,
    /// Monitor period.
    pub monitor_period: i32,
    /// Failures allowed within the period.
    pub max_auth_failures: i32,
}

// ---------------------------------------------------------------------------
// Request building
// ---------------------------------------------------------------------------

/// The users-family envelope open tag (tds + tt namespaces — the `tds:User`
/// wrapper's children are schema-typed; see the module docs).
fn users_open(action: &str) -> String {
    format!("<tds:{action} xmlns:tds=\"{TDS_NS}\" xmlns:tt=\"{TT_NS}\">")
}

/// tt:-prefixed BinaryData serialization (ContentType omitempty, Data
/// always — the LoadCertificates wire shape).
fn tt_binary_data(b: &BinaryData) -> String {
    let content_type = if b.content_type.is_empty() {
        String::new()
    } else {
        format!("<tt:ContentType>{}</tt:ContentType>", esc(&b.content_type))
    };
    format!(
        "{content_type}<tt:Data>{}</tt:Data>",
        base64::engine::general_purpose::STANDARD.encode(&b.data)
    )
}

/// Unprefixed BinaryData serialization (no omitempty — the Go plain-type
/// wire shape used by LoadCACertificates / SetAccessPolicy /
/// GetPkcs10Request attributes).
fn plain_binary_data(b: &BinaryData) -> String {
    format!(
        "<ContentType>{}</ContentType><Data>{}</Data>",
        esc(&b.content_type),
        base64::engine::general_purpose::STANDARD.encode(&b.data)
    )
}

/// Build a CreateUsers body.
fn build_create_users_request(users: &[User]) -> String {
    let items: String = users
        .iter()
        .map(|u| {
            format!(
                "<tds:User><tt:Username>{}</tt:Username><tt:Password>{}</tt:Password><tt:UserLevel>{}</tt:UserLevel></tds:User>",
                esc(&u.username),
                esc(&u.password),
                esc(&u.user_level)
            )
        })
        .collect();
    format!("{}{items}</tds:CreateUsers>", users_open("CreateUsers"))
}

/// Build a SetUser body — the password element drops out when empty (the
/// Go pointer-omitempty behavior).
fn build_set_user_request(user: &User) -> String {
    let password = if user.password.is_empty() {
        String::new()
    } else {
        format!("<tt:Password>{}</tt:Password>", esc(&user.password))
    };
    format!(
        "{}<tds:User><tt:Username>{}</tt:Username>{password}<tt:UserLevel>{}</tt:UserLevel></tds:User></tds:SetUser>",
        users_open("SetUser"),
        esc(&user.username),
        esc(&user.user_level)
    )
}

/// Build the shared IP-address-filter body (Set/Add/RemoveIPAddressFilter).
fn build_ip_filter_request(action: &str, filter: &IpAddressFilter) -> String {
    let v4: String = filter
        .ipv4_address
        .iter()
        .map(|a| {
            format!(
                "<tds:IPv4Address><tds:Address>{}</tds:Address><tds:PrefixLength>{}</tds:PrefixLength></tds:IPv4Address>",
                esc(&a.address),
                a.prefix_length
            )
        })
        .collect();
    let v6: String = filter
        .ipv6_address
        .iter()
        .map(|a| {
            format!(
                "<tds:IPv6Address><tds:Address>{}</tds:Address><tds:PrefixLength>{}</tds:PrefixLength></tds:IPv6Address>",
                esc(&a.address),
                a.prefix_length
            )
        })
        .collect();
    format!(
        "<tds:{action} xmlns:tds=\"{TDS_NS}\">\
         <tds:IPAddressFilter><tds:Type>{}</tds:Type>{v4}{v6}</tds:IPAddressFilter></tds:{action}>",
        esc(&filter.kind)
    )
}

/// Build a SetPasswordComplexityConfiguration body — every field carries
/// Go `omitempty`, so zero ints and false bools drop out.
fn build_set_password_complexity_request(cfg: &PasswordComplexityConfiguration) -> String {
    let mut children = String::new();
    let mut push = |tag: &str, rendered: String| {
        if !rendered.is_empty() {
            children.push_str(&format!("<tds:{tag}>{rendered}</tds:{tag}>"));
        }
    };
    if cfg.min_len != 0 {
        push("MinLen", cfg.min_len.to_string());
    }
    if cfg.uppercase != 0 {
        push("Uppercase", cfg.uppercase.to_string());
    }
    if cfg.number != 0 {
        push("Number", cfg.number.to_string());
    }
    if cfg.special_chars != 0 {
        push("SpecialChars", cfg.special_chars.to_string());
    }
    if cfg.block_username_occurrence {
        push("BlockUsernameOccurrence", "true".into());
    }
    if cfg.policy_configuration_locked {
        push("PolicyConfigurationLocked", "true".into());
    }
    format!(
        "<tds:SetPasswordComplexityConfiguration xmlns:tds=\"{TDS_NS}\">{children}</tds:SetPasswordComplexityConfiguration>"
    )
}

/// Build a LoadCertificates body (tt:-prefixed certificate entries).
fn build_load_certificates_request(certificates: &[Certificate]) -> String {
    let items: String = certificates
        .iter()
        .map(|c| {
            format!(
                "<tds:Certificate><tt:CertificateID>{}</tt:CertificateID><tt:Certificate>{}</tt:Certificate></tds:Certificate>",
                esc(&c.certificate_id),
                tt_binary_data(&c.certificate)
            )
        })
        .collect();
    format!(
        "<tds:LoadCertificates xmlns:tds=\"{TDS_NS}\" xmlns:tt=\"{TT_NS}\">{items}</tds:LoadCertificates>"
    )
}

/// Build a LoadCACertificates body — the Go plain `Certificate` type
/// marshals unprefixed children with no omitempty (quirk preserved).
fn build_load_ca_certificates_request(certificates: &[Certificate]) -> String {
    let items: String = certificates
        .iter()
        .map(|c| {
            format!(
                "<tds:Certificate><CertificateID>{}</CertificateID><Certificate>{}</Certificate></tds:Certificate>",
                esc(&c.certificate_id),
                plain_binary_data(&c.certificate)
            )
        })
        .collect();
    format!("<tds:LoadCACertificates xmlns:tds=\"{TDS_NS}\">{items}</tds:LoadCACertificates>")
}

/// Build a LoadCertificateWithPrivateKey body. `certificate_ids` supplies
/// the per-entry outer id (the Go twin indexes the parallel array; here a
/// short array is rejected up front instead of panicking).
fn build_load_certificate_with_private_key_request(
    certificates: &[Certificate],
    private_keys: &[BinaryData],
    certificate_ids: &[String],
) -> Result<String, ClientError> {
    if certificate_ids.len() < certificates.len() {
        return Err(ClientError::InvalidArgument(
            "LoadCertificateWithPrivateKey: invalid parameter: certificateIDs must cover every certificate"
                .into(),
        ));
    }
    let items: String = certificates
        .iter()
        .enumerate()
        .map(|(i, cert)| {
            let private_key = match private_keys.get(i) {
                Some(key) => format!("<tt:PrivateKey>{}</tt:PrivateKey>", tt_binary_data(key)),
                None => String::new(),
            };
            format!(
                "<tds:CertificateWithPrivateKey><tt:CertificateID>{}</tt:CertificateID>\
                 <tt:Certificate><tt:CertificateID>{}</tt:CertificateID><tt:Certificate>{}</tt:Certificate></tt:Certificate>\
                 {private_key}</tds:CertificateWithPrivateKey>",
                esc(&certificate_ids[i]),
                esc(&cert.certificate_id),
                tt_binary_data(&cert.certificate)
            )
        })
        .collect();
    Ok(format!(
        "<tds:LoadCertificateWithPrivateKey xmlns:tds=\"{TDS_NS}\" xmlns:tt=\"{TT_NS}\">{items}</tds:LoadCertificateWithPrivateKey>"
    ))
}

/// Build a CreateCertificate body (CertificateID omitempty; subject and
/// validity windows always ride along).
fn build_create_certificate_request(
    certificate_id: &str,
    subject: &str,
    valid_not_before: &str,
    valid_not_after: &str,
) -> String {
    let id = if certificate_id.is_empty() {
        String::new()
    } else {
        format!(
            "<tds:CertificateID>{}</tds:CertificateID>",
            esc(certificate_id)
        )
    };
    format!(
        "<tds:CreateCertificate xmlns:tds=\"{TDS_NS}\">{id}\
         <tds:Subject>{}</tds:Subject><tds:ValidNotBefore>{}</tds:ValidNotBefore>\
         <tds:ValidNotAfter>{}</tds:ValidNotAfter></tds:CreateCertificate>",
        esc(subject),
        esc(valid_not_before),
        esc(valid_not_after)
    )
}

/// Build a SetAccessPolicy body (PolicyFile omitempty as a whole).
fn build_set_access_policy_request(policy: &AccessPolicy) -> String {
    let policy_file = policy
        .policy_file
        .as_ref()
        .map(|b| format!("<tds:PolicyFile>{}</tds:PolicyFile>", plain_binary_data(b)))
        .unwrap_or_default();
    format!("<tds:SetAccessPolicy xmlns:tds=\"{TDS_NS}\">{policy_file}</tds:SetAccessPolicy>")
}

/// Build a SetRemoteUser body (RemoteUser omitted entirely for `None`).
fn build_set_remote_user_request(user: Option<&RemoteUser>) -> String {
    let inner = user
        .map(|u| {
            let password = if u.password.is_empty() {
                String::new()
            } else {
                format!("<tds:Password>{}</tds:Password>", esc(&u.password))
            };
            format!(
                "<tds:RemoteUser><tds:Username>{}</tds:Username>{password}<tds:UseDerivedPassword>{}</tds:UseDerivedPassword></tds:RemoteUser>",
                esc(&u.username),
                u.use_derived_password
            )
        })
        .unwrap_or_default();
    format!("<tds:SetRemoteUser xmlns:tds=\"{TDS_NS}\">{inner}</tds:SetRemoteUser>")
}

/// Build a GetPkcs10Request body (CertificateID/Attributes omitempty).
fn build_get_pkcs10_request_request(
    certificate_id: &str,
    subject: &str,
    attributes: Option<&BinaryData>,
) -> String {
    let id = if certificate_id.is_empty() {
        String::new()
    } else {
        format!(
            "<tds:CertificateID>{}</tds:CertificateID>",
            esc(certificate_id)
        )
    };
    let attributes = attributes
        .map(|b| format!("<tds:Attributes>{}</tds:Attributes>", plain_binary_data(b)))
        .unwrap_or_default();
    format!(
        "<tds:GetPkcs10Request xmlns:tds=\"{TDS_NS}\">{id}<tds:Subject>{}</tds:Subject>{attributes}</tds:GetPkcs10Request>",
        esc(subject)
    )
}

/// Build a SetCertificatesStatus body (unprefixed children — the Go plain
/// type).
fn build_set_certificates_status_request(statuses: &[CertificateStatus]) -> String {
    let items: String = statuses
        .iter()
        .map(|s| {
            format!(
                "<tds:CertificateStatus><CertificateID>{}</CertificateID><Status>{}</Status></tds:CertificateStatus>",
                esc(&s.certificate_id),
                s.status
            )
        })
        .collect();
    format!("<tds:SetCertificatesStatus xmlns:tds=\"{TDS_NS}\">{items}</tds:SetCertificatesStatus>")
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

impl SoapClient {
    /// GetUsers — usernames and levels (passwords are never returned).
    pub async fn get_users(&self) -> Result<Vec<User>, ClientError> {
        let resp = self.device_call(&tds_action("GetUsers")).await?;
        parse_users(&resp)
    }

    /// CreateUsers.
    pub async fn create_users(&self, users: &[User]) -> Result<(), ClientError> {
        let body = build_create_users_request(users);
        self.device_call(&body).await?;
        Ok(())
    }

    /// DeleteUsers.
    pub async fn delete_users(&self, usernames: &[String]) -> Result<(), ClientError> {
        let items: String = usernames
            .iter()
            .map(|name| format!("<tds:Username>{}</tds:Username>", esc(name)))
            .collect();
        let body = format!("<tds:DeleteUsers xmlns:tds=\"{TDS_NS}\">{items}</tds:DeleteUsers>");
        self.device_call(&body).await?;
        Ok(())
    }

    /// SetUser — modifies one account; an empty password omits the element
    /// (level-only update).
    pub async fn set_user(&self, user: &User) -> Result<(), ClientError> {
        let body = build_set_user_request(user);
        self.device_call(&body).await?;
        Ok(())
    }

    /// GetAccessPolicy.
    pub async fn get_access_policy(&self) -> Result<AccessPolicy, ClientError> {
        let resp = self.device_call(&tds_action("GetAccessPolicy")).await?;
        parse_access_policy(&resp)
    }

    /// SetAccessPolicy.
    pub async fn set_access_policy(&self, policy: &AccessPolicy) -> Result<(), ClientError> {
        let body = build_set_access_policy_request(policy);
        self.device_call(&body).await?;
        Ok(())
    }

    /// GetRemoteUser — `None` when the device has no remote user
    /// configured.
    pub async fn get_remote_user(&self) -> Result<Option<RemoteUser>, ClientError> {
        let resp = self.device_call(&tds_action("GetRemoteUser")).await?;
        parse_remote_user(&resp)
    }

    /// SetRemoteUser — `None` sends the empty form (the Go nil-pointer
    /// shape, which clears the element from the request).
    pub async fn set_remote_user(&self, user: Option<&RemoteUser>) -> Result<(), ClientError> {
        let body = build_set_remote_user_request(user);
        self.device_call(&body).await?;
        Ok(())
    }

    /// GetIPAddressFilter.
    pub async fn get_ip_address_filter(&self) -> Result<IpAddressFilter, ClientError> {
        let resp = self.device_call(&tds_action("GetIPAddressFilter")).await?;
        parse_ip_address_filter(&resp)
    }

    /// SetIPAddressFilter.
    pub async fn set_ip_address_filter(&self, filter: &IpAddressFilter) -> Result<(), ClientError> {
        let body = build_ip_filter_request("SetIPAddressFilter", filter);
        self.device_call(&body).await?;
        Ok(())
    }

    /// AddIPAddressFilter.
    pub async fn add_ip_address_filter(&self, filter: &IpAddressFilter) -> Result<(), ClientError> {
        let body = build_ip_filter_request("AddIPAddressFilter", filter);
        self.device_call(&body).await?;
        Ok(())
    }

    /// RemoveIPAddressFilter.
    pub async fn remove_ip_address_filter(
        &self,
        filter: &IpAddressFilter,
    ) -> Result<(), ClientError> {
        let body = build_ip_filter_request("RemoveIPAddressFilter", filter);
        self.device_call(&body).await?;
        Ok(())
    }

    /// GetPasswordComplexityConfiguration.
    pub async fn get_password_complexity_configuration(
        &self,
    ) -> Result<PasswordComplexityConfiguration, ClientError> {
        let resp = self
            .device_call(&tds_action("GetPasswordComplexityConfiguration"))
            .await?;
        parse_password_complexity(&resp)
    }

    /// SetPasswordComplexityConfiguration.
    pub async fn set_password_complexity_configuration(
        &self,
        config: &PasswordComplexityConfiguration,
    ) -> Result<(), ClientError> {
        let body = build_set_password_complexity_request(config);
        self.device_call(&body).await?;
        Ok(())
    }

    /// GetPasswordHistoryConfiguration.
    pub async fn get_password_history_configuration(
        &self,
    ) -> Result<PasswordHistoryConfiguration, ClientError> {
        let resp = self
            .device_call(&tds_action("GetPasswordHistoryConfiguration"))
            .await?;
        let mut out = PasswordHistoryConfiguration::default();
        walk_local(&resp, "GetPasswordHistoryConfigurationResponse", |step| {
            if let Step::Text { path, text } = step {
                if tail_is(path, &["Enabled"]) {
                    out.enabled = xml_bool(text);
                } else if tail_is(path, &["Length"]) {
                    out.length = xml_int(text);
                }
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// SetPasswordHistoryConfiguration.
    pub async fn set_password_history_configuration(
        &self,
        config: &PasswordHistoryConfiguration,
    ) -> Result<(), ClientError> {
        let body = format!(
            "<tds:SetPasswordHistoryConfiguration xmlns:tds=\"{TDS_NS}\">\
             <tds:Enabled>{}</tds:Enabled><tds:Length>{}</tds:Length></tds:SetPasswordHistoryConfiguration>",
            config.enabled, config.length
        );
        self.device_call(&body).await?;
        Ok(())
    }

    /// GetAuthFailureWarningConfiguration.
    pub async fn get_auth_failure_warning_configuration(
        &self,
    ) -> Result<AuthFailureWarningConfiguration, ClientError> {
        let resp = self
            .device_call(&tds_action("GetAuthFailureWarningConfiguration"))
            .await?;
        let mut out = AuthFailureWarningConfiguration::default();
        walk_local(
            &resp,
            "GetAuthFailureWarningConfigurationResponse",
            |step| {
                if let Step::Text { path, text } = step {
                    if tail_is(path, &["Enabled"]) {
                        out.enabled = xml_bool(text);
                    } else if tail_is(path, &["MonitorPeriod"]) {
                        out.monitor_period = xml_int(text);
                    } else if tail_is(path, &["MaxAuthFailures"]) {
                        out.max_auth_failures = xml_int(text);
                    }
                }
                Ok(())
            },
        )?;
        Ok(out)
    }

    /// SetAuthFailureWarningConfiguration.
    pub async fn set_auth_failure_warning_configuration(
        &self,
        config: &AuthFailureWarningConfiguration,
    ) -> Result<(), ClientError> {
        let body = format!(
            "<tds:SetAuthFailureWarningConfiguration xmlns:tds=\"{TDS_NS}\">\
             <tds:Enabled>{}</tds:Enabled><tds:MonitorPeriod>{}</tds:MonitorPeriod>\
             <tds:MaxAuthFailures>{}</tds:MaxAuthFailures></tds:SetAuthFailureWarningConfiguration>",
            config.enabled, config.monitor_period, config.max_auth_failures
        );
        self.device_call(&body).await?;
        Ok(())
    }

    /// GetCertificates.
    pub async fn get_certificates(&self) -> Result<Vec<Certificate>, ClientError> {
        let resp = self.device_call(&tds_action("GetCertificates")).await?;
        parse_certificates(&resp)
    }

    /// GetCACertificates (same response shape as GetCertificates).
    pub async fn get_ca_certificates(&self) -> Result<Vec<Certificate>, ClientError> {
        let resp = self.device_call(&tds_action("GetCACertificates")).await?;
        parse_certificates(&resp)
    }

    /// LoadCertificates.
    pub async fn load_certificates(&self, certificates: &[Certificate]) -> Result<(), ClientError> {
        let body = build_load_certificates_request(certificates);
        self.device_call(&body).await?;
        Ok(())
    }

    /// LoadCACertificates.
    pub async fn load_ca_certificates(
        &self,
        certificates: &[Certificate],
    ) -> Result<(), ClientError> {
        let body = build_load_ca_certificates_request(certificates);
        self.device_call(&body).await?;
        Ok(())
    }

    /// CreateCertificate — server-side key generation; returns the created
    /// certificate descriptor (`None` when the device returns none).
    pub async fn create_certificate(
        &self,
        certificate_id: &str,
        subject: &str,
        valid_not_before: &str,
        valid_not_after: &str,
    ) -> Result<Option<Certificate>, ClientError> {
        let body = build_create_certificate_request(
            certificate_id,
            subject,
            valid_not_before,
            valid_not_after,
        );
        let resp = self.device_call(&body).await?;
        Ok(parse_certificates(&resp)?.into_iter().next())
    }

    /// DeleteCertificates.
    pub async fn delete_certificates(&self, certificate_ids: &[String]) -> Result<(), ClientError> {
        let items: String = certificate_ids
            .iter()
            .map(|id| format!("<tds:CertificateID>{}</tds:CertificateID>", esc(id)))
            .collect();
        let body = format!(
            "<tds:DeleteCertificates xmlns:tds=\"{TDS_NS}\">{items}</tds:DeleteCertificates>"
        );
        self.device_call(&body).await?;
        Ok(())
    }

    /// GetCertificateInformation — `None` when the device reports none.
    pub async fn get_certificate_information(
        &self,
        certificate_id: &str,
    ) -> Result<Option<CertificateInformation>, ClientError> {
        let body = format!(
            "<tds:GetCertificateInformation xmlns:tds=\"{TDS_NS}\">\
             <tds:CertificateID>{}</tds:CertificateID></tds:GetCertificateInformation>",
            esc(certificate_id)
        );
        let resp = self.device_call(&body).await?;
        parse_certificate_information(&resp)
    }

    /// GetCertificatesStatus.
    pub async fn get_certificates_status(&self) -> Result<Vec<CertificateStatus>, ClientError> {
        let resp = self
            .device_call(&tds_action("GetCertificatesStatus"))
            .await?;
        parse_certificates_status(&resp)
    }

    /// SetCertificatesStatus.
    pub async fn set_certificates_status(
        &self,
        statuses: &[CertificateStatus],
    ) -> Result<(), ClientError> {
        let body = build_set_certificates_status_request(statuses);
        self.device_call(&body).await?;
        Ok(())
    }

    /// GetPkcs10Request — a certificate signing request for a device-held
    /// key pair; `attributes` is optional DER-encoded attributes payload.
    pub async fn get_pkcs10_request(
        &self,
        certificate_id: &str,
        subject: &str,
        attributes: Option<&BinaryData>,
    ) -> Result<Option<BinaryData>, ClientError> {
        let body = build_get_pkcs10_request_request(certificate_id, subject, attributes);
        let resp = self.device_call(&body).await?;
        parse_pkcs10_request(&resp)
    }

    /// LoadCertificateWithPrivateKey — parallel arrays: `certificate_ids`
    /// supplies each entry's outer id, `private_keys` may be shorter (the
    /// Go twin then omits the PrivateKey element for the tail entries; a
    /// short `certificate_ids` array is an error instead of Go's panic).
    pub async fn load_certificate_with_private_key(
        &self,
        certificates: &[Certificate],
        private_keys: &[BinaryData],
        certificate_ids: &[String],
    ) -> Result<(), ClientError> {
        let body = build_load_certificate_with_private_key_request(
            certificates,
            private_keys,
            certificate_ids,
        )?;
        self.device_call(&body).await?;
        Ok(())
    }

    /// GetClientCertificateMode.
    pub async fn get_client_certificate_mode(&self) -> Result<bool, ClientError> {
        let resp = self
            .device_call(&tds_action("GetClientCertificateMode"))
            .await?;
        let mut enabled = false;
        walk_local(&resp, "GetClientCertificateModeResponse", |step| {
            if let Step::Text { path, text } = step {
                if tail_is(path, &["Enabled"]) {
                    enabled = xml_bool(text);
                }
            }
            Ok(())
        })?;
        Ok(enabled)
    }

    /// SetClientCertificateMode.
    pub async fn set_client_certificate_mode(&self, enabled: bool) -> Result<(), ClientError> {
        let body = format!(
            "<tds:SetClientCertificateMode xmlns:tds=\"{TDS_NS}\">\
             <tds:Enabled>{enabled}</tds:Enabled></tds:SetClientCertificateMode>"
        );
        self.device_call(&body).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Response decoders
// ---------------------------------------------------------------------------

fn parse_users(resp: &str) -> Result<Vec<User>, ClientError> {
    let mut out: Vec<User> = Vec::new();
    walk_local(resp, "GetUsersResponse", |step| match step {
        Step::Start { path, .. } => {
            if tail_is(path, &["User"]) {
                out.push(User::default());
            }
            Ok(())
        }
        Step::Text { path, text } => {
            if let Some(last) = out.last_mut() {
                if tail_is(path, &["User", "Username"]) {
                    last.username = text.to_string();
                } else if tail_is(path, &["User", "UserLevel"]) {
                    last.user_level = text.to_string();
                }
            }
            Ok(())
        }
        Step::End { .. } => Ok(()),
    })?;
    Ok(out)
}

fn parse_remote_user(resp: &str) -> Result<Option<RemoteUser>, ClientError> {
    let mut out: Option<RemoteUser> = None;
    walk_local(resp, "GetRemoteUserResponse", |step| match step {
        Step::Start { path, .. } => {
            if tail_is(path, &["RemoteUser"]) {
                out = Some(RemoteUser::default());
            }
            Ok(())
        }
        Step::Text { path, text } => {
            if let Some(user) = out.as_mut() {
                if tail_is(path, &["RemoteUser", "Username"]) {
                    user.username = text.to_string();
                } else if tail_is(path, &["RemoteUser", "Password"]) {
                    user.password = text.to_string();
                } else if tail_is(path, &["RemoteUser", "UseDerivedPassword"]) {
                    user.use_derived_password = xml_bool(text);
                }
            }
            Ok(())
        }
        Step::End { .. } => Ok(()),
    })?;
    Ok(out)
}

fn parse_ip_address_filter(resp: &str) -> Result<IpAddressFilter, ClientError> {
    let mut out = IpAddressFilter::default();
    walk_local(resp, "GetIPAddressFilterResponse", |step| match step {
        Step::Start { path, .. } => {
            if tail_is(path, &["IPAddressFilter", "IPv4Address"]) {
                out.ipv4_address.push(PrefixedIpv4Address::default());
            } else if tail_is(path, &["IPAddressFilter", "IPv6Address"]) {
                out.ipv6_address.push(PrefixedIpv6Address::default());
            }
            Ok(())
        }
        Step::Text { path, text } => {
            if tail_is(path, &["IPAddressFilter", "Type"]) {
                out.kind = text.to_string();
            } else if tail_is(path, &["IPAddressFilter", "IPv4Address", "Address"]) {
                if let Some(last) = out.ipv4_address.last_mut() {
                    last.address = text.to_string();
                }
            } else if tail_is(path, &["IPAddressFilter", "IPv4Address", "PrefixLength"]) {
                if let Some(last) = out.ipv4_address.last_mut() {
                    last.prefix_length = xml_int(text);
                    last.netmask = netmask_from_prefix_length(last.prefix_length);
                }
            } else if tail_is(path, &["IPAddressFilter", "IPv6Address", "Address"]) {
                if let Some(last) = out.ipv6_address.last_mut() {
                    last.address = text.to_string();
                }
            } else if tail_is(path, &["IPAddressFilter", "IPv6Address", "PrefixLength"]) {
                if let Some(last) = out.ipv6_address.last_mut() {
                    last.prefix_length = xml_int(text);
                }
            }
            Ok(())
        }
        Step::End { .. } => Ok(()),
    })?;
    Ok(out)
}

fn parse_password_complexity(resp: &str) -> Result<PasswordComplexityConfiguration, ClientError> {
    let mut out = PasswordComplexityConfiguration::default();
    walk_local(resp, "GetPasswordComplexityConfigurationResponse", |step| {
        if let Step::Text { path, text } = step {
            if tail_is(path, &["MinLen"]) {
                out.min_len = xml_int(text);
            } else if tail_is(path, &["Uppercase"]) {
                out.uppercase = xml_int(text);
            } else if tail_is(path, &["Number"]) {
                out.number = xml_int(text);
            } else if tail_is(path, &["SpecialChars"]) {
                out.special_chars = xml_int(text);
            } else if tail_is(path, &["BlockUsernameOccurrence"]) {
                out.block_username_occurrence = xml_bool(text);
            } else if tail_is(path, &["PolicyConfigurationLocked"]) {
                out.policy_configuration_locked = xml_bool(text);
            }
        }
        Ok(())
    })?;
    Ok(out)
}

/// Certificate list decode. Item elements are named `Certificate`, whose
/// inner `Certificate` child is the tt:BinaryData payload — the two levels
/// share a local name, so the walk tracks which depth is which.
fn parse_certificates(resp: &str) -> Result<Vec<Certificate>, ClientError> {
    let mut out: Vec<Certificate> = Vec::new();
    let mut item_depth: Option<usize> = None;
    let mut binary_depth: Option<usize> = None;
    let mut binary_content_type = String::new();
    let mut binary_data = String::new();

    walk_local(resp, "GetCertificatesResponse", |step| {
        match step {
            Step::Start { path, attrs } => {
                let leaf_is_certificate = path.last().map(String::as_str) == Some("Certificate");
                if leaf_is_certificate && item_depth.is_none() {
                    item_depth = Some(path.len());
                    out.push(Certificate::default());
                } else if leaf_is_certificate && binary_depth.is_none() {
                    // Inner tt:Certificate (BinaryData): ContentType arrives
                    // as an attribute on real devices (the Go decode, which
                    // only matches elements, misses it — accepted here).
                    binary_depth = Some(path.len());
                    binary_content_type = attr_get(attrs, "ContentType").unwrap_or("").to_string();
                }
                Ok(())
            }
            Step::Text { path, text } => {
                let leaf = path.last().map(String::as_str);
                if binary_depth.is_some() {
                    if leaf == Some("Data") {
                        binary_data = text.to_string();
                    } else if leaf == Some("ContentType") {
                        binary_content_type = text.to_string();
                    }
                } else if item_depth.is_some() && leaf == Some("CertificateID") {
                    if let Some(last) = out.last_mut() {
                        last.certificate_id = text.to_string();
                    }
                }
                Ok(())
            }
            Step::End { path } => {
                if Some(path.len()) == binary_depth {
                    let payload = b64_bytes(&binary_data)?;
                    if let Some(last) = out.last_mut() {
                        last.certificate = BinaryData {
                            content_type: binary_content_type.clone(),
                            data: payload,
                        };
                    }
                    binary_depth = None;
                    binary_content_type.clear();
                    binary_data.clear();
                } else if Some(path.len()) == item_depth {
                    item_depth = None;
                }
                Ok(())
            }
        }
    })?;
    Ok(out)
}

fn parse_certificates_status(resp: &str) -> Result<Vec<CertificateStatus>, ClientError> {
    let mut out: Vec<CertificateStatus> = Vec::new();
    walk_local(resp, "GetCertificatesStatusResponse", |step| match step {
        Step::Start { path, .. } => {
            if tail_is(path, &["CertificateStatus"]) {
                out.push(CertificateStatus::default());
            }
            Ok(())
        }
        Step::Text { path, text } => {
            if let Some(last) = out.last_mut() {
                if tail_is(path, &["CertificateStatus", "CertificateID"]) {
                    last.certificate_id = text.to_string();
                } else if tail_is(path, &["CertificateStatus", "Status"]) {
                    last.status = xml_bool(text);
                }
            }
            Ok(())
        }
        Step::End { .. } => Ok(()),
    })?;
    Ok(out)
}

fn parse_certificate_information(
    resp: &str,
) -> Result<Option<CertificateInformation>, ClientError> {
    /// KeyUsage scratch: the value may ride the element itself (schema
    /// simpleContent) or a child `Value` element (Go's decode shape).
    #[derive(Default)]
    struct UsageScratch {
        critical: String,
        own_text: String,
        child_value: String,
    }

    let mut out: Option<CertificateInformation> = None;
    let mut key_usage: Option<UsageScratch> = None;
    let mut ext_key_usage: Option<UsageScratch> = None;
    let mut validity: Option<(String, String)> = None; // (from, until)

    walk_local(
        resp,
        "GetCertificateInformationResponse",
        |step| match step {
            Step::Start { path, attrs } => {
                if tail_is(path, &["CertificateInformation"]) {
                    out = Some(CertificateInformation::default());
                } else if tail_is(path, &["KeyUsage"]) {
                    key_usage = Some(UsageScratch {
                        critical: attr_get(attrs, "critical").unwrap_or("").to_string(),
                        own_text: String::new(),
                        child_value: String::new(),
                    });
                } else if tail_is(path, &["ExtendedKeyUsage"]) {
                    ext_key_usage = Some(UsageScratch {
                        critical: attr_get(attrs, "critical").unwrap_or("").to_string(),
                        own_text: String::new(),
                        child_value: String::new(),
                    });
                } else if tail_is(path, &["Validity"]) {
                    validity = Some((String::new(), String::new()));
                }
                Ok(())
            }
            Step::Text { path, text } => {
                if let Some(info) = out.as_mut() {
                    if tail_is(path, &["CertificateInformation", "CertificateID"]) {
                        info.certificate_id = text.to_string();
                    } else if tail_is(path, &["CertificateInformation", "IssuerDN"]) {
                        info.issuer_dn = text.to_string();
                    } else if tail_is(path, &["CertificateInformation", "SubjectDN"]) {
                        info.subject_dn = text.to_string();
                    } else if tail_is(path, &["CertificateInformation", "KeyLength"]) {
                        info.key_length = xml_int(text);
                    } else if tail_is(path, &["CertificateInformation", "Version"]) {
                        info.version = text.to_string();
                    } else if tail_is(path, &["CertificateInformation", "SerialNum"]) {
                        info.serial_num = text.to_string();
                    } else if tail_is(path, &["CertificateInformation", "SignatureAlgorithm"]) {
                        info.signature_algorithm = text.to_string();
                    }
                }
                if let Some(usage) = key_usage.as_mut() {
                    if tail_is(path, &["KeyUsage", "Value"]) {
                        usage.child_value = text.to_string();
                    } else if tail_is(path, &["KeyUsage", "Critical"]) {
                        usage.critical = text.to_string();
                    } else if tail_is(path, &["KeyUsage"]) {
                        usage.own_text.push_str(text);
                    }
                }
                if let Some(usage) = ext_key_usage.as_mut() {
                    if tail_is(path, &["ExtendedKeyUsage", "Value"]) {
                        usage.child_value = text.to_string();
                    } else if tail_is(path, &["ExtendedKeyUsage", "Critical"]) {
                        usage.critical = text.to_string();
                    } else if tail_is(path, &["ExtendedKeyUsage"]) {
                        usage.own_text.push_str(text);
                    }
                }
                if let Some((from, until)) = validity.as_mut() {
                    if tail_is(path, &["Validity", "From"]) {
                        *from = text.to_string();
                    } else if tail_is(path, &["Validity", "Until"]) {
                        *until = text.to_string();
                    }
                }
                Ok(())
            }
            Step::End { .. } => Ok(()),
        },
    )?;

    let finish_usage = |scratch: Option<UsageScratch>| -> Option<CertificateUsage> {
        scratch.map(|u| CertificateUsage {
            critical: xml_bool(&u.critical),
            value: if u.child_value.is_empty() {
                u.own_text
            } else {
                u.child_value
            },
        })
    };

    if let Some(info) = out.as_mut() {
        info.key_usage = finish_usage(key_usage.take());
        info.extended_key_usage = finish_usage(ext_key_usage.take());
        if let Some((from, until)) = validity.take() {
            info.validity = Some(DateTimeRange {
                from: parse_stamp(&from, "From")?,
                until: parse_stamp(&until, "Until")?,
            });
        }
    }
    Ok(out)
}

/// Parse an xs:dateTime that must be present (non-empty) — unparseable
/// text is a decode error, mirroring the Go time.Time decode.
fn parse_stamp(s: &str, field: &str) -> Result<Option<UtcStamp>, ClientError> {
    if s.trim().is_empty() {
        return Ok(None);
    }
    parse_xsd_datetime(s.trim())
        .map(|unix| Some(UtcStamp { unix }))
        .ok_or_else(|| ClientError::Parse(format!("bad Validity/{field} dateTime: {s}")))
}

fn parse_access_policy(resp: &str) -> Result<AccessPolicy, ClientError> {
    let mut out = AccessPolicy::default();
    let mut in_policy_file = false;
    let mut content_type = String::new();
    let mut data = String::new();
    walk_local(resp, "GetAccessPolicyResponse", |step| {
        match step {
            Step::Start { path, attrs } => {
                if tail_is(path, &["PolicyFile"]) {
                    in_policy_file = true;
                    content_type = attr_get(attrs, "ContentType").unwrap_or("").to_string();
                }
                Ok(())
            }
            Step::Text { path, text } => {
                if in_policy_file {
                    let leaf = path.last().map(String::as_str);
                    if leaf == Some("Data") {
                        data = text.to_string();
                    } else if leaf == Some("ContentType") {
                        content_type = text.to_string();
                    } else if tail_is(path, &["PolicyFile"]) && data.is_empty() {
                        // Simple-content form: the payload rides the
                        // PolicyFile element itself.
                        data = text.to_string();
                    }
                }
                Ok(())
            }
            Step::End { path } => {
                if tail_is(path, &["PolicyFile"]) {
                    if !data.is_empty() || !content_type.is_empty() {
                        out.policy_file = Some(BinaryData {
                            content_type: content_type.clone(),
                            data: b64_bytes(&data)?,
                        });
                    }
                    in_policy_file = false;
                    content_type.clear();
                    data.clear();
                }
                Ok(())
            }
        }
    })?;
    Ok(out)
}

fn parse_pkcs10_request(resp: &str) -> Result<Option<BinaryData>, ClientError> {
    let mut out: Option<BinaryData> = None;
    let mut in_request = false;
    let mut content_type = String::new();
    let mut data = String::new();
    walk_local(resp, "GetPkcs10RequestResponse", |step| match step {
        Step::Start { path, attrs } => {
            if tail_is(path, &["Pkcs10Request"]) {
                in_request = true;
                content_type = attr_get(attrs, "ContentType").unwrap_or("").to_string();
                out = Some(BinaryData::default());
            }
            Ok(())
        }
        Step::Text { path, text } => {
            if in_request {
                let leaf = path.last().map(String::as_str);
                if leaf == Some("Data") {
                    data = text.to_string();
                } else if leaf == Some("ContentType") {
                    content_type = text.to_string();
                }
            }
            Ok(())
        }
        Step::End { path } => {
            if tail_is(path, &["Pkcs10Request"]) {
                if let Some(slot) = out.as_mut() {
                    slot.content_type = content_type.clone();
                    slot.data = b64_bytes(&data)?;
                }
                in_request = false;
            }
            Ok(())
        }
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const USERS_RESP: &str = r#"<GetUsersResponse>
        <User><Username>admin</Username><UserLevel>Administrator</UserLevel></User>
        <User><Username>op</Username><UserLevel>Operator</UserLevel></User>
        </GetUsersResponse>"#;

    #[test]
    fn decodes_users() {
        let users = parse_users(USERS_RESP).unwrap();
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].username, "admin");
        assert_eq!(users[0].user_level, "Administrator");
        assert_eq!(users[1].user_level, "Operator");
        // Passwords never come back.
        assert_eq!(users[0].password, "");
    }

    #[test]
    fn decodes_remote_user() {
        let resp = r#"<GetRemoteUserResponse><RemoteUser><Username>remote</Username><Password>pw</Password><UseDerivedPassword>true</UseDerivedPassword></RemoteUser></GetRemoteUserResponse>"#;
        let user = parse_remote_user(resp).unwrap().unwrap();
        assert_eq!(user.username, "remote");
        assert!(user.use_derived_password);

        // No RemoteUser element -> None (the Go nil,nil path).
        assert!(parse_remote_user("<GetRemoteUserResponse/>")
            .unwrap()
            .is_none());
    }

    #[test]
    fn decodes_ip_address_filter_with_netmask() {
        let resp = r#"<GetIPAddressFilterResponse><IPAddressFilter><Type>Allow</Type><IPv4Address><Address>192.168.1.1</Address><PrefixLength>32</PrefixLength></IPv4Address><IPv6Address><Address>fe80::1</Address><PrefixLength>128</PrefixLength></IPv6Address></IPAddressFilter></GetIPAddressFilterResponse>"#;
        let filter = parse_ip_address_filter(resp).unwrap();
        assert_eq!(filter.kind, "Allow");
        assert_eq!(filter.ipv4_address.len(), 1);
        assert_eq!(filter.ipv4_address[0].address, "192.168.1.1");
        assert_eq!(filter.ipv4_address[0].prefix_length, 32);
        assert_eq!(filter.ipv4_address[0].netmask, "255.255.255.255");
        assert_eq!(filter.ipv6_address[0].address, "fe80::1");
        assert_eq!(filter.ipv6_address[0].prefix_length, 128);
    }

    #[test]
    fn decodes_password_policies() {
        let complexity = parse_password_complexity(
            r#"<GetPasswordComplexityConfigurationResponse><MinLen>12</MinLen><Uppercase>1</Uppercase><Number>2</Number><SpecialChars>1</SpecialChars><BlockUsernameOccurrence>true</BlockUsernameOccurrence></GetPasswordComplexityConfigurationResponse>"#,
        )
        .unwrap();
        assert_eq!(complexity.min_len, 12);
        assert_eq!(complexity.uppercase, 1);
        assert_eq!(complexity.number, 2);
        assert_eq!(complexity.special_chars, 1);
        assert!(complexity.block_username_occurrence);
        assert!(!complexity.policy_configuration_locked);

        // The history walk (same shape the SoapClient method drives).
        let mut out = PasswordHistoryConfiguration::default();
        walk_local(
            r#"<GetPasswordHistoryConfigurationResponse><Enabled>true</Enabled><Length>5</Length></GetPasswordHistoryConfigurationResponse>"#,
            "GetPasswordHistoryConfigurationResponse",
            |step| {
                if let Step::Text { path, text } = step {
                    if tail_is(path, &["Enabled"]) {
                        out.enabled = xml_bool(text);
                    } else if tail_is(path, &["Length"]) {
                        out.length = xml_int(text);
                    }
                }
                Ok(())
            },
        )
        .unwrap();
        assert!(out.enabled);
        assert_eq!(out.length, 5);
    }

    #[test]
    fn decodes_certificates() {
        // Real-device shape: ContentType as an ATTRIBUTE of the inner
        // tt:Certificate (the Go decode misses attributes — accepted here).
        let resp = r#"<GetCertificatesResponse><Certificate><CertificateID>cert-1</CertificateID><Certificate ContentType="application/pkix-cert"><Data>QUJD</Data></Certificate></Certificate></GetCertificatesResponse>"#;
        let certs = parse_certificates(resp).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].certificate_id, "cert-1");
        assert_eq!(certs[0].certificate.content_type, "application/pkix-cert");
        assert_eq!(certs[0].certificate.data, b"ABC");

        // Element-shaped ContentType (what the Go twin decodes).
        let resp = r#"<GetCertificatesResponse><Certificate><CertificateID>c2</CertificateID><Certificate><ContentType>application/pkcs10</ContentType><Data>REVG</Data></Certificate></Certificate></GetCertificatesResponse>"#;
        let certs = parse_certificates(resp).unwrap();
        assert_eq!(certs[0].certificate.content_type, "application/pkcs10");
        assert_eq!(certs[0].certificate.data, b"DEF");

        // Empty list.
        assert!(parse_certificates("<GetCertificatesResponse/>")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn decodes_certificate_status_and_pkcs10() {
        let statuses = parse_certificates_status(
            r#"<GetCertificatesStatusResponse><CertificateStatus><CertificateID>cert-1</CertificateID><Status>true</Status></CertificateStatus></GetCertificatesStatusResponse>"#,
        )
        .unwrap();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].certificate_id, "cert-1");
        assert!(statuses[0].status);

        // The Go fixture: ContentType as element, Data base64.
        let pkcs = parse_pkcs10_request(
            r#"<GetPkcs10RequestResponse><Pkcs10Request><ContentType>application/pkcs10</ContentType><Data>QUJD</Data></Pkcs10Request></GetPkcs10RequestResponse>"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(pkcs.content_type, "application/pkcs10");
        assert_eq!(pkcs.data, b"ABC");
    }

    #[test]
    fn decodes_certificate_information() {
        let resp = r#"<GetCertificateInformationResponse><CertificateInformation>
            <CertificateID>cert-1</CertificateID><IssuerDN>CN=ca</IssuerDN><SubjectDN>CN=cam</SubjectDN>
            <KeyUsage critical="true">digitalSignature</KeyUsage>
            <ExtendedKeyUsage><Critical>false</Critical><Value>serverAuth</Value></ExtendedKeyUsage>
            <KeyLength>2048</KeyLength><Version>3</Version><SerialNum>01</SerialNum>
            <SignatureAlgorithm>sha256WithRSAEncryption</SignatureAlgorithm>
            <Validity><From>2026-01-01T00:00:00Z</From><Until>2027-01-01T00:00:00Z</Until></Validity>
            </CertificateInformation></GetCertificateInformationResponse>"#;
        let info = parse_certificate_information(resp).unwrap().unwrap();
        assert_eq!(info.certificate_id, "cert-1");
        assert_eq!(info.issuer_dn, "CN=ca");
        assert_eq!(info.subject_dn, "CN=cam");
        // Attribute-critical + simpleContent value (schema shape).
        let usage = info.key_usage.as_ref().unwrap();
        assert!(usage.critical);
        assert_eq!(usage.value, "digitalSignature");
        assert_eq!(info.key_length, 2048);
        assert_eq!(info.signature_algorithm, "sha256WithRSAEncryption");
        let validity = info.validity.as_ref().unwrap();
        assert_eq!(
            validity.from.map(|t| t.to_rfc3339()).as_deref(),
            Some("2026-01-01T00:00:00Z")
        );
        assert_eq!(
            validity.until.map(|t| t.to_rfc3339()).as_deref(),
            Some("2027-01-01T00:00:00Z")
        );

        // Bad dateTime in a reported window is a decode error.
        let bad = resp.replace("2026-01-01T00:00:00Z", "not-a-time");
        assert!(parse_certificate_information(&bad).is_err());
    }

    #[test]
    fn decodes_access_policy() {
        // Element-shaped payload.
        let resp = r#"<GetAccessPolicyResponse><PolicyFile><ContentType>application/xeac+xml</ContentType><Data>UE9M</Data></PolicyFile></GetAccessPolicyResponse>"#;
        let policy = parse_access_policy(resp).unwrap();
        let file = policy.policy_file.unwrap();
        assert_eq!(file.content_type, "application/xeac+xml");
        assert_eq!(file.data, b"POL");

        // Empty policy (the Go round-trip fixture maps to a present but
        // content-less element; both decode without error).
        let empty = parse_access_policy(
            r#"<GetAccessPolicyResponse><AccessPolicy><DefaultAccessRules/></AccessPolicy></GetAccessPolicyResponse>"#,
        )
        .unwrap();
        assert!(empty.policy_file.is_none());
    }

    // -----------------------------------------------------------------
    // Request goldens
    // -----------------------------------------------------------------

    #[test]
    fn create_users_request_tt_children() {
        assert_eq!(
            build_create_users_request(&[User {
                username: "operator".into(),
                password: "s3cret".into(),
                user_level: "User".into(),
            }]),
            r#"<tds:CreateUsers xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema"><tds:User><tt:Username>operator</tt:Username><tt:Password>s3cret</tt:Password><tt:UserLevel>User</tt:UserLevel></tds:User></tds:CreateUsers>"#
        );
    }

    #[test]
    fn set_user_request_omits_empty_password() {
        assert_eq!(
            build_set_user_request(&User {
                username: "operator".into(),
                password: String::new(),
                user_level: "Administrator".into(),
            }),
            r#"<tds:SetUser xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema"><tds:User><tt:Username>operator</tt:Username><tt:UserLevel>Administrator</tt:UserLevel></tds:User></tds:SetUser>"#
        );
        let with_password = build_set_user_request(&User {
            username: "operator1".into(),
            password: "s3cret".into(),
            user_level: "Administrator".into(),
        });
        assert!(with_password.contains("<tt:Password>s3cret</tt:Password>"));
    }

    #[test]
    fn ip_filter_request_shared_shape() {
        let filter = IpAddressFilter {
            kind: "Allow".into(),
            ipv4_address: vec![PrefixedIpv4Address {
                address: "192.168.1.0".into(),
                prefix_length: 24,
                netmask: String::new(),
            }],
            ipv6_address: Vec::new(),
        };
        assert_eq!(
            build_ip_filter_request("SetIPAddressFilter", &filter),
            r#"<tds:SetIPAddressFilter xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:IPAddressFilter><tds:Type>Allow</tds:Type><tds:IPv4Address><tds:Address>192.168.1.0</tds:Address><tds:PrefixLength>24</tds:PrefixLength></tds:IPv4Address></tds:IPAddressFilter></tds:SetIPAddressFilter>"#
        );
        // The Add/Remove variants only swap the action element.
        let add = build_ip_filter_request("AddIPAddressFilter", &filter);
        assert!(add.starts_with("<tds:AddIPAddressFilter xmlns:tds="));
    }

    #[test]
    fn password_complexity_request_omitempty() {
        let cfg = PasswordComplexityConfiguration {
            min_len: 12,
            uppercase: 1,
            number: 2,
            special_chars: 1,
            block_username_occurrence: true,
            policy_configuration_locked: false,
        };
        assert_eq!(
            build_set_password_complexity_request(&cfg),
            r#"<tds:SetPasswordComplexityConfiguration xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:MinLen>12</tds:MinLen><tds:Uppercase>1</tds:Uppercase><tds:Number>2</tds:Number><tds:SpecialChars>1</tds:SpecialChars><tds:BlockUsernameOccurrence>true</tds:BlockUsernameOccurrence></tds:SetPasswordComplexityConfiguration>"#
        );
        // All-zero config emits an empty action element.
        assert_eq!(
            build_set_password_complexity_request(&PasswordComplexityConfiguration::default()),
            r#"<tds:SetPasswordComplexityConfiguration xmlns:tds="http://www.onvif.org/ver10/device/wsdl"></tds:SetPasswordComplexityConfiguration>"#
        );
    }

    #[test]
    fn load_certificates_request_shapes() {
        let cert = Certificate {
            certificate_id: "cert-1".into(),
            certificate: BinaryData {
                content_type: "application/pkix-cert".into(),
                data: b"ABC".to_vec(),
            },
        };
        assert_eq!(
            build_load_certificates_request(std::slice::from_ref(&cert)),
            r#"<tds:LoadCertificates xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema"><tds:Certificate><tt:CertificateID>cert-1</tt:CertificateID><tt:Certificate><tt:ContentType>application/pkix-cert</tt:ContentType><tt:Data>QUJD</tt:Data></tt:Certificate></tds:Certificate></tds:LoadCertificates>"#
        );
        // CA variant: unprefixed children, no omitempty (Go plain type).
        let empty_cert = Certificate {
            certificate_id: "cert-1".into(),
            certificate: BinaryData::default(),
        };
        assert_eq!(
            build_load_ca_certificates_request(&[empty_cert]),
            r#"<tds:LoadCACertificates xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:Certificate><CertificateID>cert-1</CertificateID><Certificate><ContentType></ContentType><Data></Data></Certificate></tds:Certificate></tds:LoadCACertificates>"#
        );
    }

    #[test]
    fn load_certificate_with_private_key_request() {
        let certs = vec![Certificate {
            certificate_id: "cert-1".into(),
            certificate: BinaryData::default(),
        }];
        let keys = vec![BinaryData {
            content_type: "application/pkcs8".into(),
            data: b"KEY".to_vec(),
        }];
        let ids = vec!["alias-1".to_string()];
        assert_eq!(
            build_load_certificate_with_private_key_request(&certs, &keys, &ids).unwrap(),
            r#"<tds:LoadCertificateWithPrivateKey xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema"><tds:CertificateWithPrivateKey><tt:CertificateID>alias-1</tt:CertificateID><tt:Certificate><tt:CertificateID>cert-1</tt:CertificateID><tt:Certificate><tt:Data></tt:Data></tt:Certificate></tt:Certificate><tt:PrivateKey><tt:ContentType>application/pkcs8</tt:ContentType><tt:Data>S0VZ</tt:Data></tt:PrivateKey></tds:CertificateWithPrivateKey></tds:LoadCertificateWithPrivateKey>"#
        );
        // Shorter key list omits the PrivateKey arm (Go's i < len check).
        let no_keys = build_load_certificate_with_private_key_request(&certs, &[], &ids).unwrap();
        assert!(!no_keys.contains("<tt:PrivateKey>"));
        // Shorter id list is rejected (Go would panic on the index).
        assert!(build_load_certificate_with_private_key_request(&certs, &keys, &[]).is_err());
    }

    #[test]
    fn access_policy_and_remote_user_requests() {
        let policy = AccessPolicy {
            policy_file: Some(BinaryData {
                content_type: "application/xeac+xml".into(),
                data: b"POL".to_vec(),
            }),
        };
        assert_eq!(
            build_set_access_policy_request(&policy),
            r#"<tds:SetAccessPolicy xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:PolicyFile><ContentType>application/xeac+xml</ContentType><Data>UE9M</Data></tds:PolicyFile></tds:SetAccessPolicy>"#
        );
        // None policy file omits the element entirely.
        assert_eq!(
            build_set_access_policy_request(&AccessPolicy::default()),
            r#"<tds:SetAccessPolicy xmlns:tds="http://www.onvif.org/ver10/device/wsdl"></tds:SetAccessPolicy>"#
        );

        assert_eq!(
            build_set_remote_user_request(Some(&RemoteUser {
                username: "u".into(),
                password: "p".into(),
                use_derived_password: true,
            })),
            r#"<tds:SetRemoteUser xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:RemoteUser><tds:Username>u</tds:Username><tds:Password>p</tds:Password><tds:UseDerivedPassword>true</tds:UseDerivedPassword></tds:RemoteUser></tds:SetRemoteUser>"#
        );
        assert_eq!(
            build_set_remote_user_request(None),
            r#"<tds:SetRemoteUser xmlns:tds="http://www.onvif.org/ver10/device/wsdl"></tds:SetRemoteUser>"#
        );
    }

    #[test]
    fn pkcs10_and_status_requests() {
        assert_eq!(
            build_get_pkcs10_request_request("cert-1", "CN=test", None),
            r#"<tds:GetPkcs10Request xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:CertificateID>cert-1</tds:CertificateID><tds:Subject>CN=test</tds:Subject></tds:GetPkcs10Request>"#
        );
        let with_attrs =
            build_get_pkcs10_request_request("cert-1", "CN=test", Some(&BinaryData::default()));
        assert!(with_attrs
            .contains("<tds:Attributes><ContentType></ContentType><Data></Data></tds:Attributes>"));

        assert_eq!(
            build_set_certificates_status_request(&[CertificateStatus {
                certificate_id: "cert-1".into(),
                status: true,
            }]),
            r#"<tds:SetCertificatesStatus xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:CertificateStatus><CertificateID>cert-1</CertificateID><Status>true</Status></tds:CertificateStatus></tds:SetCertificatesStatus>"#
        );
    }

    #[test]
    fn create_certificate_request_omits_empty_id() {
        assert_eq!(
            build_create_certificate_request("cert-1", "CN=test", "", ""),
            r#"<tds:CreateCertificate xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:CertificateID>cert-1</tds:CertificateID><tds:Subject>CN=test</tds:Subject><tds:ValidNotBefore></tds:ValidNotBefore><tds:ValidNotAfter></tds:ValidNotAfter></tds:CreateCertificate>"#
        );
        // Empty id drops the element (Go omitempty).
        assert_eq!(
            build_create_certificate_request("", "CN=test", "2026-01-01", "2027-01-01"),
            r#"<tds:CreateCertificate xmlns:tds="http://www.onvif.org/ver10/device/wsdl"><tds:Subject>CN=test</tds:Subject><tds:ValidNotBefore>2026-01-01</tds:ValidNotBefore><tds:ValidNotAfter>2027-01-01</tds:ValidNotAfter></tds:CreateCertificate>"#
        );
    }
}
