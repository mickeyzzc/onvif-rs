//! Analytics client family — the port of the onvif-go `analytics` package
//! (the ver20 tan service: the rule and analytics-module configuration
//! model behind Profile M). Requests ride the device endpoint, matching
//! the Go twin's `EndpointFor(ServiceAnalytics)` default.

use super::device::{collect_attrs, tail_is, walk_local, xml_bool, Step};
use super::media::parse_xml_tree;
use super::metadata::Frame as MetadataFrame;
use super::{ClientError, SoapClient};
use crate::events::SimpleItem;

/// tan (ver20 analytics service) and tt (ver10 schema) namespaces.
const TAN_NS: &str = "http://www.onvif.org/ver20/analytics/wsdl";
const TT_NS: &str = "http://www.onvif.org/ver10/schema";

/// The analytics service capability answer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AnalyticsCapabilities {
    pub rule_support: bool,
    pub analytics_module_support: bool,
}

/// One configurable parameter of a module/rule type.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ItemDescription {
    pub name: String,
    pub type_: String,
}

/// The description of one supported module or rule type (message
/// descriptions are not modeled — the Go twin's follow-up, mirrored).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigDescription {
    pub name: String,
    pub parameters: Vec<ItemDescription>,
}

/// The `GetSupported{Rules,AnalyticsModules}` answer: schema locations
/// plus one description per supported type.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Supported {
    pub content_schema_locations: Vec<String>,
    pub descriptions: Vec<ConfigDescription>,
}

/// One tt:Config — an analytics module or rule instance: a name, its type
/// QName, and the parameter values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnalyticsConfig {
    pub name: String,
    pub type_: String,
    pub parameters: Vec<SimpleItem>,
}

/// One tan:MetadataInfo answer: the sample frame describing the metadata
/// coordinate system.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MetadataInfo {
    pub sample_frame: Option<MetadataFrame>,
}

/// One tan:ConfigOptions entry of GetRuleOptions — the vendor parameter
/// tree is preserved verbatim in `inner_xml` for callers that need the
/// typed ranges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleOptions {
    pub rule_type: String,
    pub name: String,
    pub type_: String,
    pub inner_xml: String,
}

/// One tan:ConfigOptions entry of GetAnalyticsModuleOptions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleOptions {
    pub analytics_module: String,
    pub name: String,
    pub type_: String,
    pub inner_xml: String,
}

// ---------------------------------------------------------------------------
// Request builders (Go marshals empty elements in open/close form; attrs in
// struct field order)
// ---------------------------------------------------------------------------

fn esc_attr(s: &str) -> String {
    super::device::esc(s)
}

fn tan_root(action: &str, inner: &str) -> String {
    if inner.is_empty() {
        return format!("<tan:{action} xmlns:tan=\"{TAN_NS}\"></tan:{action}>");
    }
    format!("<tan:{action} xmlns:tan=\"{TAN_NS}\">{inner}</tan:{action}>")
}

fn tan_root_tt(action: &str, inner: &str) -> String {
    format!("<tan:{action} xmlns:tan=\"{TAN_NS}\" xmlns:tt=\"{TT_NS}\">{inner}</tan:{action}>")
}

fn token_xml(configuration_token: &str) -> String {
    format!(
        "<tan:ConfigurationToken>{}</tan:ConfigurationToken>",
        esc_attr(configuration_token)
    )
}

fn config_entry_xml(tag: &str, c: &AnalyticsConfig) -> String {
    let mut items = String::new();
    for item in &c.parameters {
        items.push_str(&format!(
            "<tt:SimpleItem Name=\"{}\" Value=\"{}\"></tt:SimpleItem>",
            esc_attr(&item.name),
            esc_attr(&item.value)
        ));
    }
    format!(
        "<tan:{tag} Name=\"{}\" Type=\"{}\"><tt:Parameters>{items}</tt:Parameters></tan:{tag}>",
        esc_attr(&c.name),
        esc_attr(&c.type_)
    )
}

pub(crate) fn build_get_service_capabilities() -> String {
    tan_root("GetServiceCapabilities", "")
}

pub(crate) fn build_get_supported(action: &str, configuration_token: &str) -> String {
    tan_root(action, &token_xml(configuration_token))
}

pub(crate) fn build_get_instances(action: &str, configuration_token: &str) -> String {
    tan_root(action, &token_xml(configuration_token))
}

pub(crate) fn build_write_configs(
    action: &str,
    entry_tag: &str,
    configuration_token: &str,
    configs: &[AnalyticsConfig],
) -> String {
    let mut inner = token_xml(configuration_token);
    for c in configs {
        inner.push_str(&config_entry_xml(entry_tag, c));
    }
    tan_root_tt(action, &inner)
}

pub(crate) fn build_delete_configs(
    action: &str,
    name_tag: &str,
    configuration_token: &str,
    names: &[&str],
) -> String {
    let mut inner = token_xml(configuration_token);
    for n in names {
        inner.push_str(&format!("<tan:{name_tag}>{}</tan:{name_tag}>", esc_attr(n)));
    }
    tan_root(action, &inner)
}

pub(crate) fn build_get_supported_metadata(module_type: &str) -> String {
    let inner = if module_type.is_empty() {
        String::new()
    } else {
        format!("<tan:Type>{}</tan:Type>", esc_attr(module_type))
    };
    tan_root("GetSupportedMetadata", &inner)
}

pub(crate) fn build_get_options(
    action: &str,
    type_tag: &str,
    type_filter: &str,
    configuration_token: &str,
) -> String {
    let mut inner = String::new();
    if !type_filter.is_empty() {
        inner.push_str(&format!(
            "<tan:{type_tag}>{}</tan:{type_tag}>",
            esc_attr(type_filter)
        ));
    }
    inner.push_str(&token_xml(configuration_token));
    tan_root(action, &inner)
}

// ---------------------------------------------------------------------------
// Response decode
// ---------------------------------------------------------------------------

fn parse_capabilities(resp: &str) -> Result<AnalyticsCapabilities, ClientError> {
    let mut caps = AnalyticsCapabilities::default();
    walk_local(resp, "GetServiceCapabilitiesResponse", |step| {
        if let Step::Start { path, attrs } = step {
            if tail_is(path, &["GetServiceCapabilitiesResponse", "Capabilities"]) {
                caps.rule_support = attr_bool(attrs, "RuleSupport");
                caps.analytics_module_support = attr_bool(attrs, "AnalyticsModuleSupport");
            }
        }
        Ok(())
    })?;
    Ok(caps)
}

fn attr_bool(attrs: &[(String, String)], name: &str) -> bool {
    attrs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| xml_bool(v))
        .unwrap_or(false)
}

fn parse_supported(
    resp: &str,
    op: &str,
    container: &str,
    description: &str,
    location: &str,
) -> Result<Supported, ClientError> {
    let mut out = Supported::default();
    walk_local(resp, op, |step| match step {
        Step::Text { path, text } => {
            if tail_is(path, &[container, location]) {
                out.content_schema_locations.push(text.to_string());
            }
            Ok(())
        }
        Step::Start { path, attrs } => {
            if tail_is(path, &[container, description]) {
                out.descriptions.push(ConfigDescription {
                    name: attr_string(attrs, "Name"),
                    parameters: Vec::new(),
                });
            } else if tail_is(path, &[container, description, "Parameters", "Item"]) {
                if let Some(last) = out.descriptions.last_mut() {
                    last.parameters.push(ItemDescription {
                        name: attr_string(attrs, "Name"),
                        type_: attr_string(attrs, "Type"),
                    });
                }
            }
            Ok(())
        }
        Step::End { .. } => Ok(()),
    })?;
    Ok(out)
}

fn attr_string(attrs: &[(String, String)], name: &str) -> String {
    attrs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

fn parse_configs(
    resp: &str,
    op: &str,
    root_local: &str,
    entry: &str,
) -> Result<Vec<AnalyticsConfig>, ClientError> {
    let mut out: Vec<AnalyticsConfig> = Vec::new();
    walk_local(resp, op, |step| match step {
        Step::Start { path, attrs } => {
            if tail_is(path, &[root_local, entry]) {
                out.push(AnalyticsConfig {
                    name: attr_string(attrs, "Name"),
                    type_: attr_string(attrs, "Type"),
                    parameters: Vec::new(),
                });
            } else if tail_is(path, &[root_local, entry, "Parameters", "SimpleItem"]) {
                if let Some(last) = out.last_mut() {
                    last.parameters.push(SimpleItem {
                        name: attr_string(attrs, "Name"),
                        value: attr_string(attrs, "Value"),
                    });
                }
            }
            Ok(())
        }
        _ => Ok(()),
    })?;
    Ok(out)
}

fn parse_metadata_infos(resp: &str) -> Result<Vec<MetadataInfo>, ClientError> {
    let root = parse_xml_tree(resp)?;
    let mut out = Vec::new();
    for module in root.find_all("AnalyticsModule") {
        out.push(MetadataInfo {
            sample_frame: module.find("SampleFrame").map(super::metadata::map_frame),
        });
    }
    Ok(out)
}

/// One `tan:ConfigOptions`-shaped entry with its verbatim inner XML.
type RawEntry = (Vec<(String, String)>, String);

/// Collect the `target_local` entries that sit directly under the
/// `response_local` element, each with its attributes and its raw inner
/// XML sliced from the source (byte-verbatim, the Go twin's `,innerxml`).
fn inner_xml_entries(
    resp: &str,
    op: &str,
    response_local: &str,
    target_local: &str,
) -> Result<Vec<RawEntry>, ClientError> {
    let mut reader = quick_xml::Reader::from_str(resp);
    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();
    let mut out: Vec<RawEntry> = Vec::new();

    // In-flight capture of one target element: open depth (incl. the
    // target itself), byte offset just past its start tag, attributes.
    struct Capture {
        depth: usize,
        span_start: usize,
        attrs: Vec<(String, String)>,
    }
    let mut cap: Option<Capture> = None;

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                let local = qname_local(e.name().as_ref());
                let pos = reader.buffer_position() as usize;
                if let Some(c) = cap.as_mut() {
                    c.depth += 1;
                } else if stack.last().map(String::as_str) == Some(response_local)
                    && local == target_local
                {
                    cap = Some(Capture {
                        depth: 1,
                        span_start: pos,
                        attrs: collect_attrs(&e),
                    });
                }
                stack.push(local);
            }
            Ok(XmlEvent::Empty(e)) => {
                let local = qname_local(e.name().as_ref());
                if cap.is_none()
                    && stack.last().map(String::as_str) == Some(response_local)
                    && local == target_local
                {
                    out.push((collect_attrs(&e), String::new()));
                }
                stack.push(local);
                stack.pop();
            }
            Ok(XmlEvent::End(e)) => {
                let end_len = 3 + e.name().as_ref().len(); // "</" + qname + ">"
                let pos = reader.buffer_position() as usize;
                if let Some(c) = cap.take() {
                    if c.depth == 1 {
                        let span_end = pos.saturating_sub(end_len);
                        let span = resp
                            .get(c.span_start..span_end)
                            .ok_or_else(|| {
                                ClientError::Parse(format!("parse {op}: inner-xml span"))
                            })?
                            .to_string();
                        out.push((c.attrs, span));
                    } else {
                        cap = Some(Capture {
                            depth: c.depth - 1,
                            ..c
                        });
                    }
                }
                stack.pop();
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(ClientError::Parse(format!("parse {op}: {e}"))),
        }
        buf.clear();
    }
    Ok(out)
}

fn qname_local(raw: &[u8]) -> String {
    let full = String::from_utf8_lossy(raw).to_string();
    match full.rsplit_once(':') {
        Some((_, local)) => local.to_string(),
        None => full,
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

impl SoapClient {
    /// The analytics service capabilities.
    pub async fn analytics_get_service_capabilities(
        &self,
    ) -> Result<AnalyticsCapabilities, ClientError> {
        let resp = self.device_call(&build_get_service_capabilities()).await?;
        parse_capabilities(&resp)
    }

    /// The module types a VideoAnalyticsConfiguration accepts, with their
    /// parameters.
    pub async fn analytics_get_supported_analytics_modules(
        &self,
        configuration_token: &str,
    ) -> Result<Supported, ClientError> {
        let resp = self
            .device_call(&build_get_supported(
                "GetSupportedAnalyticsModules",
                configuration_token,
            ))
            .await?;
        parse_supported(
            &resp,
            "GetSupportedAnalyticsModulesResponse",
            "SupportedAnalyticsModules",
            "AnalyticsModuleDescription",
            "AnalyticsModuleContentSchemaLocation",
        )
    }

    /// The rule types a VideoAnalyticsConfiguration accepts.
    pub async fn analytics_get_supported_rules(
        &self,
        configuration_token: &str,
    ) -> Result<Supported, ClientError> {
        let resp = self
            .device_call(&build_get_supported(
                "GetSupportedRules",
                configuration_token,
            ))
            .await?;
        parse_supported(
            &resp,
            "GetSupportedRulesResponse",
            "SupportedRules",
            "RuleDescription",
            "RuleContentSchemaLocation",
        )
    }

    /// The analytics module instances of a configuration.
    pub async fn analytics_get_analytics_modules(
        &self,
        configuration_token: &str,
    ) -> Result<Vec<AnalyticsConfig>, ClientError> {
        let resp = self
            .device_call(&build_get_instances(
                "GetAnalyticsModules",
                configuration_token,
            ))
            .await?;
        parse_configs(
            &resp,
            "GetAnalyticsModulesResponse",
            "GetAnalyticsModulesResponse",
            "AnalyticsModule",
        )
    }

    /// The rule instances of a configuration.
    pub async fn analytics_get_rules(
        &self,
        configuration_token: &str,
    ) -> Result<Vec<AnalyticsConfig>, ClientError> {
        let resp = self
            .device_call(&build_get_instances("GetRules", configuration_token))
            .await?;
        parse_configs(&resp, "GetRulesResponse", "GetRulesResponse", "Rule")
    }

    /// Add analytics module instances to a configuration.
    pub async fn analytics_create_analytics_modules(
        &self,
        configuration_token: &str,
        modules: &[AnalyticsConfig],
    ) -> Result<(), ClientError> {
        self.device_call(&build_write_configs(
            "CreateAnalyticsModules",
            "AnalyticsModule",
            configuration_token,
            modules,
        ))
        .await?;
        Ok(())
    }

    /// Update analytics module instances of a configuration.
    pub async fn analytics_modify_analytics_modules(
        &self,
        configuration_token: &str,
        modules: &[AnalyticsConfig],
    ) -> Result<(), ClientError> {
        self.device_call(&build_write_configs(
            "ModifyAnalyticsModules",
            "AnalyticsModule",
            configuration_token,
            modules,
        ))
        .await?;
        Ok(())
    }

    /// Remove analytics modules by name.
    pub async fn analytics_delete_analytics_modules(
        &self,
        configuration_token: &str,
        names: &[&str],
    ) -> Result<(), ClientError> {
        self.device_call(&build_delete_configs(
            "DeleteAnalyticsModules",
            "AnalyticsModuleName",
            configuration_token,
            names,
        ))
        .await?;
        Ok(())
    }

    /// Add rules to a VideoAnalyticsConfiguration (e.g. Hikvision / Axis
    /// MotionDetector / FieldDetector provisioning).
    pub async fn analytics_create_rules(
        &self,
        configuration_token: &str,
        rules: &[AnalyticsConfig],
    ) -> Result<(), ClientError> {
        self.device_call(&build_write_configs(
            "CreateRules",
            "Rule",
            configuration_token,
            rules,
        ))
        .await?;
        Ok(())
    }

    /// Update existing rules of a VideoAnalyticsConfiguration.
    pub async fn analytics_modify_rules(
        &self,
        configuration_token: &str,
        rules: &[AnalyticsConfig],
    ) -> Result<(), ClientError> {
        self.device_call(&build_write_configs(
            "ModifyRules",
            "Rule",
            configuration_token,
            rules,
        ))
        .await?;
        Ok(())
    }

    /// Remove named rules from a VideoAnalyticsConfiguration.
    pub async fn analytics_delete_rules(
        &self,
        configuration_token: &str,
        rule_names: &[&str],
    ) -> Result<(), ClientError> {
        self.device_call(&build_delete_configs(
            "DeleteRules",
            "RuleName",
            configuration_token,
            rule_names,
        ))
        .await?;
        Ok(())
    }

    /// The metadata descriptions (sample frames) of the analytics modules;
    /// an empty `module_type` asks for all types.
    pub async fn analytics_get_supported_metadata(
        &self,
        module_type: &str,
    ) -> Result<Vec<MetadataInfo>, ClientError> {
        let resp = self
            .device_call(&build_get_supported_metadata(module_type))
            .await?;
        parse_metadata_infos(&resp)
    }

    /// The configurable parameter ranges for a rule type (empty `rule_type`
    /// = all types; each entry then carries its `rule_type`).
    pub async fn analytics_get_rule_options(
        &self,
        rule_type: &str,
        configuration_token: &str,
    ) -> Result<Vec<RuleOptions>, ClientError> {
        let resp = self
            .device_call(&build_get_options(
                "GetRuleOptions",
                "RuleType",
                rule_type,
                configuration_token,
            ))
            .await?;
        let entries = inner_xml_entries(
            &resp,
            "GetRuleOptionsResponse",
            "GetRuleOptionsResponse",
            "RuleOptions",
        )?;
        Ok(entries
            .into_iter()
            .map(|(attrs, inner)| RuleOptions {
                rule_type: attr_string(&attrs, "RuleType"),
                name: attr_string(&attrs, "Name"),
                type_: attr_string(&attrs, "Type"),
                inner_xml: inner,
            })
            .collect())
    }

    /// The configurable parameter ranges for an analytics module type
    /// (empty `module_type` = all types).
    pub async fn analytics_get_analytics_module_options(
        &self,
        module_type: &str,
        configuration_token: &str,
    ) -> Result<Vec<ModuleOptions>, ClientError> {
        let resp = self
            .device_call(&build_get_options(
                "GetAnalyticsModuleOptions",
                "Type",
                module_type,
                configuration_token,
            ))
            .await?;
        let entries = inner_xml_entries(
            &resp,
            "GetAnalyticsModuleOptionsResponse",
            "GetAnalyticsModuleOptionsResponse",
            "Options",
        )?;
        Ok(entries
            .into_iter()
            .map(|(attrs, inner)| ModuleOptions {
                analytics_module: attr_string(&attrs, "AnalyticsModule"),
                name: attr_string(&attrs, "Name"),
                type_: attr_string(&attrs, "Type"),
                inner_xml: inner,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_goldens() {
        assert_eq!(
            build_get_service_capabilities(),
            "<tan:GetServiceCapabilities xmlns:tan=\"http://www.onvif.org/ver20/analytics/wsdl\"></tan:GetServiceCapabilities>"
        );

        assert_eq!(
            build_get_supported("GetSupportedRules", "video_analytics_1"),
            "<tan:GetSupportedRules xmlns:tan=\"http://www.onvif.org/ver20/analytics/wsdl\"><tan:ConfigurationToken>video_analytics_1</tan:ConfigurationToken></tan:GetSupportedRules>"
        );

        let module = AnalyticsConfig {
            name: "Detector1".to_string(),
            type_: "tt:MyDetector".to_string(),
            parameters: vec![SimpleItem {
                name: "Sensitivity".to_string(),
                value: "0.5".to_string(),
            }],
        };
        assert_eq!(
            build_write_configs(
                "CreateAnalyticsModules",
                "AnalyticsModule",
                "video_analytics_1",
                &[module]
            ),
            "<tan:CreateAnalyticsModules xmlns:tan=\"http://www.onvif.org/ver20/analytics/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\">\
             <tan:ConfigurationToken>video_analytics_1</tan:ConfigurationToken>\
             <tan:AnalyticsModule Name=\"Detector1\" Type=\"tt:MyDetector\"><tt:Parameters><tt:SimpleItem Name=\"Sensitivity\" Value=\"0.5\"></tt:SimpleItem></tt:Parameters></tan:AnalyticsModule>\
             </tan:CreateAnalyticsModules>"
        );

        assert_eq!(
            build_delete_configs("DeleteRules", "RuleName", "vac-1", &["rule-1", "rule-2"]),
            "<tan:DeleteRules xmlns:tan=\"http://www.onvif.org/ver20/analytics/wsdl\">\
             <tan:ConfigurationToken>vac-1</tan:ConfigurationToken>\
             <tan:RuleName>rule-1</tan:RuleName><tan:RuleName>rule-2</tan:RuleName></tan:DeleteRules>"
        );

        assert_eq!(
            build_get_supported_metadata("tt:MyDetector"),
            "<tan:GetSupportedMetadata xmlns:tan=\"http://www.onvif.org/ver20/analytics/wsdl\"><tan:Type>tt:MyDetector</tan:Type></tan:GetSupportedMetadata>"
        );
        // Empty module type omits the Type element (Go omitempty).
        assert!(
            !build_get_supported_metadata("").contains("tan:Type"),
            "empty module type must omit the Type element"
        );

        assert_eq!(
            build_get_options("GetRuleOptions", "RuleType", "tt:LineDetector", "vac-1"),
            "<tan:GetRuleOptions xmlns:tan=\"http://www.onvif.org/ver20/analytics/wsdl\">\
             <tan:RuleType>tt:LineDetector</tan:RuleType><tan:ConfigurationToken>vac-1</tan:ConfigurationToken></tan:GetRuleOptions>"
        );
    }

    #[test]
    fn decodes_capabilities() {
        let caps = parse_capabilities(
            r#"<GetServiceCapabilitiesResponse><Capabilities RuleSupport="true" AnalyticsModuleSupport="true"/></GetServiceCapabilitiesResponse>"#,
        )
        .unwrap();
        assert!(caps.rule_support && caps.analytics_module_support);

        let off = parse_capabilities(
            r#"<GetServiceCapabilitiesResponse><Capabilities RuleSupport="false"/></GetServiceCapabilitiesResponse>"#,
        )
        .unwrap();
        assert!(!off.rule_support && !off.analytics_module_support);
    }

    #[test]
    fn decodes_supported_modules_and_rules() {
        let supported = parse_supported(
            r#"<GetSupportedAnalyticsModulesResponse><SupportedAnalyticsModules>
                <AnalyticsModuleContentSchemaLocation>http://example/schema.xsd</AnalyticsModuleContentSchemaLocation>
                <AnalyticsModuleDescription Name="tt:MyDetector">
                    <Parameters>
                        <Item Name="Sensitivity" Type="xs:float"/>
                        <Item Name="Zone" Type="tt:Polygon"/>
                    </Parameters>
                </AnalyticsModuleDescription>
                </SupportedAnalyticsModules></GetSupportedAnalyticsModulesResponse>"#,
            "GetSupportedAnalyticsModulesResponse",
            "SupportedAnalyticsModules",
            "AnalyticsModuleDescription",
            "AnalyticsModuleContentSchemaLocation",
        )
        .unwrap();
        assert_eq!(
            supported.content_schema_locations,
            ["http://example/schema.xsd"]
        );
        assert_eq!(supported.descriptions.len(), 1);
        assert_eq!(supported.descriptions[0].name, "tt:MyDetector");
        assert_eq!(supported.descriptions[0].parameters.len(), 2);
        assert_eq!(supported.descriptions[0].parameters[1].name, "Zone");

        let rules = parse_supported(
            r#"<GetSupportedRulesResponse><SupportedRules>
                <RuleDescription Name="tt:LineDetector"><Parameters><Item Name="Direction" Type="xs:string"/></Parameters></RuleDescription>
                </SupportedRules></GetSupportedRulesResponse>"#,
            "GetSupportedRulesResponse",
            "SupportedRules",
            "RuleDescription",
            "RuleContentSchemaLocation",
        )
        .unwrap();
        assert_eq!(rules.descriptions[0].name, "tt:LineDetector");
        assert_eq!(rules.descriptions[0].parameters[0].type_, "xs:string");
    }

    #[test]
    fn decodes_module_and_rule_instances() {
        let modules = parse_configs(
            r#"<GetAnalyticsModulesResponse>
                <AnalyticsModule Name="Detector1" Type="tt:MyDetector">
                    <Parameters><SimpleItem Name="Sensitivity" Value="0.5"/><SimpleItem Name="Zone" Value="1"/></Parameters>
                </AnalyticsModule>
                </GetAnalyticsModulesResponse>"#,
            "GetAnalyticsModulesResponse",
            "GetAnalyticsModulesResponse",
            "AnalyticsModule",
        )
        .unwrap();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].name, "Detector1");
        assert_eq!(modules[0].parameters.len(), 2);
        assert_eq!(modules[0].parameters[0].value, "0.5");

        let rules = parse_configs(
            r#"<GetRulesResponse><Rule Name="Line1" Type="tt:LineDetector"><Parameters><SimpleItem Name="Direction" Value="Both"/></Parameters></Rule></GetRulesResponse>"#,
            "GetRulesResponse",
            "GetRulesResponse",
            "Rule",
        )
        .unwrap();
        assert_eq!(rules[0].name, "Line1");
        assert_eq!(rules[0].parameters[0].name, "Direction");
    }

    #[test]
    fn decodes_metadata_sample_frames() {
        let infos = parse_metadata_infos(
            r#"<GetSupportedMetadataResponse>
                <AnalyticsModule><SampleFrame UtcTime="2026-09-19T12:00:00Z"/></AnalyticsModule>
                </GetSupportedMetadataResponse>"#,
        )
        .unwrap();
        assert_eq!(infos.len(), 1);
        let frame = infos[0].sample_frame.as_ref().expect("sample frame");
        assert!(frame.utc_time.is_some());

        let bare = parse_metadata_infos(
            r#"<GetSupportedMetadataResponse><AnalyticsModule></AnalyticsModule></GetSupportedMetadataResponse>"#,
        )
        .unwrap();
        assert!(bare[0].sample_frame.is_none());
    }

    #[test]
    fn decodes_rule_options_with_verbatim_inner_xml() {
        let entries = inner_xml_entries(
            r#"<GetRuleOptionsResponse>
                <RuleOptions RuleType="tt:LineDetector" Name="Sensitivity" Type="tt:FloatItem">
                    <tt:FloatItem><Min>0</Min><Max>1</Max></tt:FloatItem>
                </RuleOptions>
                <RuleOptions RuleType="tt:LineDetector" Name="Mode" Type="tt:StringItem"/>
                </GetRuleOptionsResponse>"#,
            "GetRuleOptionsResponse",
            "GetRuleOptionsResponse",
            "RuleOptions",
        )
        .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0]
                .0
                .iter()
                .find(|(k, _)| k == "RuleType")
                .unwrap()
                .1,
            "tt:LineDetector"
        );
        // Byte-verbatim like the Go twin's `,innerxml` — surrounding
        // whitespace from the source rides along.
        assert_eq!(
            entries[0].1,
            "\n                    <tt:FloatItem><Min>0</Min><Max>1</Max></tt:FloatItem>\n                "
        );
        // Self-closing entries carry empty inner XML.
        assert_eq!(entries[1].1, "");
    }

    #[test]
    fn decodes_module_options() {
        let entries = inner_xml_entries(
            r#"<GetAnalyticsModuleOptionsResponse>
                <Options AnalyticsModule="tt:MyDetector" Name="Sensitivity" Type="tt:FloatItem">
                    <tt:FloatItem Minimum="0" Maximum="1"/>
                </Options>
                </GetAnalyticsModuleOptionsResponse>"#,
            "GetAnalyticsModuleOptionsResponse",
            "GetAnalyticsModuleOptionsResponse",
            "Options",
        )
        .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0]
                .0
                .iter()
                .find(|(k, _)| k == "AnalyticsModule")
                .unwrap()
                .1,
            "tt:MyDetector"
        );
        assert!(entries[0].1.contains("Maximum=\"1\""));
    }

    #[test]
    fn inner_xml_handles_nested_same_name_targets() {
        let entries = inner_xml_entries(
            r#"<GetRuleOptionsResponse><RuleOptions Name="a"><RuleOptions Name="inner"/></RuleOptions></GetRuleOptionsResponse>"#,
            "GetRuleOptionsResponse",
            "GetRuleOptionsResponse",
            "RuleOptions",
        )
        .unwrap();
        // Only direct children of the response root are entries; the
        // nested same-name element rides inside the outer's inner XML.
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, "<RuleOptions Name=\"inner\"/>");
    }
}
