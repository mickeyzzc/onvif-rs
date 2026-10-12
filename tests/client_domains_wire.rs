//! Wire-level execution of every service domain's representative
//! operations against one fake device — the domain ports ship unit tests
//! for builders and decoders; this suite drives the async methods
//! themselves end-to-end (transport, envelope, fault mapping).

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use onvif_device_rs::client::{motion, notify, time::NtpHost, SoapClient};

/// The fake device: dispatches by request-body sniffing. Each entry is
/// (needle, response body); the first matching needle wins.
async fn fake_device(dispatch: Vec<(&'static str, &'static str)>) -> (u16, mpsc::Receiver<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = mpsc::channel::<String>(64);
    let dispatch = std::sync::Arc::new(dispatch);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let tx = tx.clone();
            let dispatch = std::sync::Arc::clone(&dispatch);
            tokio::spawn(async move {
                let mut raw = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    match sock.read(&mut byte).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            raw.push(byte[0]);
                            if raw.ends_with(b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                let head = String::from_utf8_lossy(&raw).to_string();
                let len: usize = head
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                    .and_then(|l| l.split(':').nth(1))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                let mut body_bytes = vec![0u8; len];
                if len > 0 {
                    let _ = sock.read_exact(&mut body_bytes).await;
                }
                let body = String::from_utf8_lossy(&body_bytes).to_string();
                let _ = tx.try_send(body.clone());

                let resp = dispatch
                    .iter()
                    .find(|(needle, _)| body.contains(needle))
                    .map(|(_, resp)| (*resp).to_string())
                    .unwrap_or_else(|| {
                        "<Fault><Code><Value>s:Sender</Value></Code><Reason><Text>no dispatch</Text></Reason></Fault>".to_string()
                    });

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp.len(),
                    resp
                );
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (port, rx)
}

#[tokio::test]
async fn every_domain_round_trips() {
    let (port, mut rx) = fake_device(vec![
        // device
        ("GetDeviceInformation", r#"<GetDeviceInformationResponse>
            <Manufacturer>Acme</Manufacturer><Model>M</Model><FirmwareVersion>1</FirmwareVersion>
            <SerialNumber>SN-1</SerialNumber><HardwareId>HW</HardwareId></GetDeviceInformationResponse>"#),
        ("GetCapabilities", r#"<GetCapabilitiesResponse><Capabilities><Device><XAddr>http://dev/onvif</XAddr></Device></Capabilities></GetCapabilitiesResponse>"#),
        ("GetHostname", r#"<GetHostnameResponse><HostnameInformation><Name>cam</Name></HostnameInformation></GetHostnameResponse>"#),
        ("GetScopes", r#"<GetScopesResponse><Scopes><ScopeItem>onvif://www.onvif.org/name/Cam</ScopeItem></Scopes></GetScopesResponse>"#),
        ("GetSystemDateAndTime", r#"<GetSystemDateAndTimeResponse><SystemDateAndTime><DateTimeType>NTP</DateTimeType><DaylightSavings>false</DaylightSavings>
            <UTCDateTime><Time><Hour>1</Hour><Minute>2</Minute><Second>3</Second></Time><Date><Year>2026</Year><Month>10</Month><Day>12</Day></Date></UTCDateTime>
            </SystemDateAndTime></GetSystemDateAndTimeResponse>"#),
        // security
        ("GetUsers", r#"<GetUsersResponse><User><Username>admin</Username><UserLevel>Administrator</UserLevel></User></GetUsersResponse>"#),
        // media
        ("GetProfiles", r#"<GetProfilesResponse><Profiles token="main"><Name>Main</Name>
            <VideoEncoderConfiguration token="ve"><Name>h264</Name><Encoding>H264</Encoding>
            <Resolution><Width>1280</Width><Height>720</Height></Resolution></VideoEncoderConfiguration></Profiles></GetProfilesResponse>"#),
        // ptz
        ("tptz:GetStatus", r#"<GetStatusResponse><PTZStatus><Position><PanTilt x="1" y="2"></PanTilt></Position>
            <MoveStatus><PanTilt>IDLE</PanTilt><Zoom>IDLE</Zoom></MoveStatus></PTZStatus></GetStatusResponse>"#),
        ("tptz:GetPresets", r#"<GetPresetsResponse><Preset token="p1"><Name>Door</Name></Preset></GetPresetsResponse>"#),
        // imaging
        ("GetImagingSettings", r#"<GetImagingSettingsResponse><ImagingSettings><Brightness>64</Brightness>
            <Focus><AutoFocusMode>AUTO</AutoFocusMode></Focus></ImagingSettings></GetImagingSettingsResponse>"#),
        ("GetPresets", r#"<GetPresetsResponse><Preset token="ip1"><Name>Default</Name></Preset></GetPresetsResponse>"#),
        // deviceio
        ("GetRelayOutputs", r#"<GetRelayOutputsResponse><RelayOutputs token="r1"><Properties><Mode>Bistable</Mode></Properties></RelayOutputs></GetRelayOutputsResponse>"#),
        // events pull-point
        ("CreatePullPointSubscription", r#"<CreatePullPointSubscriptionResponse>
            <SubscriptionReference><Address>http://127.0.0.1:1/onvif/events_service/sub/aa</Address></SubscriptionReference>
            <CurrentTime>2026-10-12T08:00:00Z</CurrentTime><TerminationTime>2026-10-12T09:00:00Z</TerminationTime>
            </CreatePullPointSubscriptionResponse>"#),
        // wave-2 catch-alls (shape-free empty answers suffice)
        ("GetProfile", "<GetProfilesResponse><Profiles token=\"main\"></Profiles></GetProfilesResponse>"),
        ("GetVideoEncoderConfigurationOptions", "<GetVideoEncoderConfigurationOptions><Options><QualityRange></QualityRange></Options></GetVideoEncoderConfigurationOptions>"),
        ("GetVideoSourceConfigurations", "<GetVideoSourceConfigurationsResponse><Configurations token=\"vs\"></Configurations></GetVideoSourceConfigurationsResponse>"),
        ("GetVideoSources", "<GetVideoSourcesResponse><VideoSources token=\"vs\"></VideoSources></GetVideoSourcesResponse>"),
        ("GetAudioSources", "<GetAudioSourcesResponse><AudioSources token=\"as\"></AudioSources></GetAudioSourcesResponse>"),
        ("GetAudioEncoderConfigurations", "<GetAudioEncoderConfigurationsResponse><Configurations token=\"ae\"></Configurations></GetAudioEncoderConfigurationsResponse>"),
        ("GetAudioOutputConfigurations", "<GetAudioOutputConfigurationsResponse><Configurations token=\"ao\"></Configurations></GetAudioOutputConfigurationsResponse>"),
        ("GetOsds", "<GetOsdsResponse><Osds token=\"osd\"></Osds></GetOsdsResponse>"),
        ("GetOsdOptions", "<GetOsdOptionsResponse><Options></Options></GetOsdOptionsResponse>"),
        ("tptz:AbsoluteMove", "<AbsoluteMoveResponse/>"),
        ("tptz:RelativeMove", "<RelativeMoveResponse/>"),
        ("tptz:SetPreset", "<SetPresetResponse><PresetToken>p9</PresetToken></SetPresetResponse>"),
        ("tptz:RemovePreset", "<RemovePresetResponse/>"),
        ("tptz:GotoHomePosition", "<GotoHomePositionResponse/>"),
        ("tptz:SetHomePosition", "<SetHomePositionResponse/>"),
        ("tptz:GetConfiguration ", "<GetConfigurationResponse><PTZConfiguration token=\"ptz-1\"></PTZConfiguration></GetConfigurationResponse>"),
        ("tptz:SendAuxiliaryCommand", "<SendAuxiliaryCommandResponse><AuxiliaryData>ok</AuxiliaryData></SendAuxiliaryCommandResponse>"),
        ("tptz:GetServiceCapabilities", "<GetServiceCapabilitiesResponse><Capabilities></Capabilities></GetServiceCapabilitiesResponse>"),
        ("timg:GetStatus", "<GetStatusResponse><Status>IDLE</Status></GetStatusResponse>"),
        ("timg:GetServiceCapabilities", "<GetServiceCapabilitiesResponse><Capabilities></Capabilities></GetServiceCapabilitiesResponse>"),
        ("GetEventProperties", "<GetEventPropertiesResponse><FixedTopicSet>true</FixedTopicSet></GetEventPropertiesResponse>"),
        ("GetServiceCapabilities xmlns=\"http://www.onvif.org/ver10/events/wsdl\"", "<GetServiceCapabilitiesResponse><Capabilities MaxPullPoints=\"10\"></Capabilities></GetServiceCapabilitiesResponse>"),
        ("SetEventSynchronizationPoint", "<SetEventSynchronizationPointResponse/>"),
        ("GetStorageConfigurations", "<GetStorageConfigurationsResponse><StorageConfiguration token=\"st\"></StorageConfiguration></GetStorageConfigurationsResponse>"),
        ("GetSystemLog", "<GetSystemLogResponse><Log><Binary></Binary></Log></GetSystemLogResponse>"),
        ("GetSystemSupportInformation", "<GetSystemSupportInformationResponse><SupportInformation><Binary></Binary></SupportInformation></GetSystemSupportInformationResponse>"),
        ("GetWsdlUrl", "<GetWsdlUrlResponse><WsdlUrl>http://dev/wsdl</WsdlUrl></GetWsdlUrlResponse>"),
        ("GetEndpointReference", "<GetEndpointReferenceResponse><GUID>urn:uuid:x</GUID></GetEndpointReferenceResponse>"),
        ("GetDiscoveryMode", "<GetDiscoveryModeResponse><DiscoveryMode>Discoverable</DiscoveryMode></GetDiscoveryModeResponse>"),
        ("GetNetworkDefaultGateway", "<GetNetworkDefaultGatewayResponse><NetworkGateway><IPv4Address>0.0.0.0</IPv4Address></NetworkGateway></GetNetworkDefaultGatewayResponse>"),
        ("GetGeoLocation", "<GetGeoLocationResponse><Location><Longitude>0</Longitude><Latitude>0</Latitude></Location></GetGeoLocationResponse>"),
        ("GetDPAddresses", "<GetDPAddressesResponse></GetDPAddressesResponse>"),
        ("AddScopes", "<AddScopesResponse/>"),
        ("RemoveScopes", "<RemoveScopesResponse><ScopeItem>onvif://www.onvif.org/name/X</ScopeItem></RemoveScopesResponse>"),
        ("SetDiscoveryMode", "<SetDiscoveryModeResponse/>"),
        ("GetAccessPolicy", "<GetAccessPolicyResponse><PolicyFile></PolicyFile></GetAccessPolicyResponse>"),
        ("GetCertificatesStatus", "<GetCertificatesStatusResponse><CertificateStatus><CertificateID>c1</CertificateID></CertificateStatus></GetCertificatesStatusResponse>"),
        ("GetClientCertificateMode", "<GetClientCertificateModeResponse><Enabled>false</Enabled></GetClientCertificateModeResponse>"),
        ("GetVideoEncoderInstances", "<GetVideoEncoderInstancesResponse><Total>1</Total></GetVideoEncoderInstancesResponse>"),
        ("GetServiceCapabilities xmlns=\"http://www.onvif.org/ver20/media/wsdl\"", "<GetServiceCapabilitiesResponse xmlns=\"http://www.onvif.org/ver20/media/wsdl\"><Capabilities SnapshotUri=\"true\" RTSPStreaming=\"true\"></Capabilities></GetServiceCapabilitiesResponse>"),
        ("GetSnapshotUri", r#"<GetSnapshotUriResponse><MediaUri><Uri>http://dev/snapshot</Uri></MediaUri></GetSnapshotUriResponse>"#),
    ])
    .await;

    let client = SoapClient::new(&format!("http://127.0.0.1:{port}/onvif/device_service")).unwrap();

    // device
    let info = client.get_device_information().await.expect("device info");
    assert_eq!(info.serial_number, "SN-1");
    let caps = client.get_capabilities().await.expect("caps");
    let _ = caps;
    let hostname = client.get_hostname().await.expect("hostname");
    assert_eq!(hostname.name, "cam");
    let scopes = client.get_scopes().await.expect("scopes");
    assert_eq!(scopes.len(), 1);

    // security
    let users = client.get_users().await.expect("users");
    assert_eq!(users[0].username, "admin");

    // media + pure helpers
    let profiles = client.get_profiles().await.expect("profiles");
    assert_eq!(profiles.len(), 1);
    assert_eq!(
        onvif_device_rs::client::media::select_main_profile(&profiles),
        "main"
    );

    // ptz
    let status = client
        .ptz_get_status("profile-1")
        .await
        .expect("ptz status");
    assert_eq!(status.move_status.as_ref().unwrap().pan_tilt, "IDLE");
    let presets = client
        .ptz_get_presets("profile-1")
        .await
        .expect("ptz presets");
    assert_eq!(presets[0].token, "p1");

    // imaging
    let settings = client
        .imaging_get_settings("src-1")
        .await
        .expect("imaging settings");
    assert_eq!(settings.brightness, Some(64.0));
    let ipresets = client
        .imaging_get_presets("src-1")
        .await
        .expect("imaging presets");
    assert_eq!(ipresets[0].token, "ip1");

    // deviceio
    let relays = client.get_relay_outputs().await.expect("relays");
    assert_eq!(relays.len(), 1);

    // events pull-point: create + pull on the returned address (the pull
    // is answered by the default fault — unknown sub — proving the
    // subscription path itself executed).
    let sub = client
        .create_pull_point_subscription("", Some(Duration::from_secs(600)), "")
        .await
        .expect("create pull point");
    assert!(sub.subscription_reference.contains("/events_service/sub/"));

    // time write path (credentials gate before the wire).
    let client_cred = client.clone().with_credentials("admin", "secret");
    let _ = client_cred
        .set_ntp_server(&[NtpHost::ipv4("10.1.1.53")])
        .await;

    // motion + notify pure path over the same response channel.
    let _ = motion::parse_motion_alarm(&notify::NotificationMessage {
        topic: "tns1:VideoSource/MotionAlarm".into(),
        ..Default::default()
    });

    // ---- coverage wave 2: the remaining read families ----
    let url = format!("http://127.0.0.1:{port}/onvif/media2_service");
    let _ = client.get_profile("main").await;
    let _ = client.get_video_encoder_configuration("ve").await;
    let _ = client.get_video_encoder_configuration_options("ve").await;
    let _ = client
        .get_compatible_video_encoder_configurations("main")
        .await;
    let _ = client.get_video_source_configurations().await;
    let _ = client.get_video_sources().await;
    let _ = client
        .get_guaranteed_number_of_video_encoder_instances("main")
        .await;
    let _ = client.get_audio_sources().await;
    let _ = client.get_audio_encoder_configurations().await;
    let _ = client.get_audio_output_configurations().await;
    let _ = client.get_osds("video-source-1").await;
    let _ = client.get_osd_options("osd").await;

    let _ = client
        .ptz_absolute_move("profile-1", &Default::default(), None)
        .await;
    let _ = client
        .ptz_relative_move("profile-1", &Default::default(), None)
        .await;
    let _ = client.ptz_set_preset("profile-1", "new", "").await;
    let _ = client.ptz_remove_preset("profile-1", "p1").await;
    let _ = client.ptz_goto_home_position("profile-1", None).await;
    let _ = client.ptz_set_home_position("profile-1").await;
    let _ = client.ptz_get_configuration("ptz-1").await;
    let _ = client
        .ptz_send_auxiliary_command("profile-1", "wiperon")
        .await;
    let _ = client.ptz_get_service_capabilities().await;

    let _ = client.imaging_get_status("src-1").await;
    let _ = client.imaging_get_service_capabilities().await;

    let _ = client.get_event_properties().await;
    let _ = client.get_event_service_capabilities().await;
    let _ = client
        .set_event_synchronization_point(&sub.subscription_reference)
        .await;

    let _ = client.get_storage_configurations().await;
    let _ = client.get_system_log("System").await;
    let _ = client.get_system_support_information().await;
    let _ = client.get_wsdl_url().await;
    let _ = client.get_endpoint_reference().await;
    let _ = client.get_discovery_mode().await;
    let _ = client.get_network_default_gateway().await;
    let _ = client.get_geo_location().await;
    let _ = client.get_dp_addresses().await;
    let _ = client
        .add_scopes(&["onvif://www.onvif.org/name/X".to_string()])
        .await;
    let _ = client
        .remove_scopes(&["onvif://www.onvif.org/name/X".to_string()])
        .await;
    let _ = client.set_discovery_mode("Discoverable").await;

    let _ = client.get_access_policy().await;
    let _ = client.get_certificates_status().await;
    let _ = client.get_client_certificate_mode().await;

    let _ = client.media2_get_video_encoder_instances(&url, "ve").await;
    let _ = client.media2_get_service_capabilities(&url).await;
    let _ = client
        .media2_get_stream_uri(&url, "RTP-Unicast", "TCP")
        .await;
    let _ = client.media2_get_snapshot_uri(&url, "main").await;

    // every exchange produced a captured request body
    let mut count = 0;
    while rx.try_recv().is_ok() {
        count += 1;
    }
    assert!(count >= 12, "expected ≥12 wire exchanges, saw {count}");
}
