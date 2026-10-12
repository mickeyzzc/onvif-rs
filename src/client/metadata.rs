//! ONVIF metadata stream parsing (tt:MetadataStream, metadatastream.xsd,
//! target namespace ver10/schema) — the twin of the Go `metadata`
//! package: the Profile M analytics output channel delivered inside the
//! media stream. Pure decoding, no SOAP.
//!
//! Decoding is lenient by design (local-name matching, prefix dialects
//! tolerated), so both default-xmlns and prefixed documents from real
//! devices parse. The root element must be `MetadataStream`. VideoAnalytics
//! frames are modeled; PTZ, Event and SensorData stream members are not
//! (yet) — the same scope as the Go twin.
//!
//! One honest resolution difference: instants decode to
//! [`UtcStamp`](super::UtcStamp) (second resolution), so the sub-second
//! fraction of `UtcTime` attributes is truncated.

use super::media::{parse_xml_tree, XmlElem};
use super::{parse_xsd_datetime, ClientError, UtcStamp};

/// Decode one tt:MetadataStream document (the Go `metadata.Parse`).
pub fn parse(data: &str) -> Result<Stream, ClientError> {
    let inner = |doc: &str| -> Result<Stream, ClientError> {
        let root = parse_xml_tree(doc)?;
        if root.name != "MetadataStream" {
            return Err(ClientError::Parse(format!(
                "parse metadata stream: expected MetadataStream root, got <{}>",
                root.name
            )));
        }

        // Frames live under VideoAnalytics blocks (possibly several).
        let mut frames = Vec::new();
        for block in root.find_all("VideoAnalytics") {
            for frame in block.find_all("Frame") {
                frames.push(map_frame(frame));
            }
        }
        Ok(Stream { frames })
    };
    inner(data).map_err(|e| ClientError::Parse(e.to_string()))
}

/// The decoded MetadataStream: the analytics frames it carried.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Stream {
    pub frames: Vec<Frame>,
}

/// One tt:Frame: a timestamped scene description.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Frame {
    /// The frame timestamp (second resolution — the fraction of the wire
    /// attribute is truncated).
    pub utc_time: Option<UtcStamp>,
    pub transformation: Option<Transformation>,
    pub objects: Vec<Object>,
}

/// One tracked object (tt:Object extends tt:ObjectId).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Object {
    pub object_id: i64,
    pub uuid: String,
    pub parent: Option<i64>,
    pub appearance: Option<Appearance>,
    pub behaviour: Option<Behaviour>,
}

/// The tt:Appearance descriptor set.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Appearance {
    pub transformation: Option<Transformation>,
    pub shape: Option<Shape>,
    pub class: Option<Class>,
    pub geo_location: Option<GeoLocation>,
}

/// tt:ShapeDescriptor: the object's geometric representation.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Shape {
    pub bounding_box: Option<Rectangle>,
    pub polygon: Vec<Point>,
    pub center_of_gravity: Option<Point>,
}

/// tt:Rectangle (axis-aligned; pixel or normalized units per the frame's
/// transformation).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Rectangle {
    pub bottom: f64,
    pub top: f64,
    pub right: f64,
    pub left: f64,
}

/// tt:Vector.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Point {
    pub x: f32,
    pub y: f32,
}

/// tt:Transformation (translate + scale).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Transformation {
    pub translate: Option<Point>,
    pub scale: Option<Point>,
}

/// tt:ClassDescriptor: the recognized object types with likelihoods.
/// `types` is the current form; `candidates` the deprecated one.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Class {
    pub types: Vec<ClassType>,
    pub candidates: Vec<ClassCandidate>,
}

/// One tt:StringLikelihood entry (Go field `Type` renamed `kind`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClassType {
    pub kind: String,
    pub likelihood: Option<f32>,
}

/// The deprecated tt:ClassCandidate form (Go field `Type` renamed
/// `kind`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClassCandidate {
    pub kind: String,
    pub likelihood: Option<f32>,
}

/// tt:GeoLocation (angles in degrees).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct GeoLocation {
    pub lon: Option<f64>,
    pub lat: Option<f64>,
}

/// tt:Behaviour: the object's lifecycle state. Removed/Idle are marker
/// elements (empty by schema), so presence is the signal — `false` means
/// absent (the Go twin models them as nil-able pointers).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Behaviour {
    pub removed: bool,
    pub idle: bool,
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

fn attr_f64(el: &XmlElem, name: &str) -> Option<f64> {
    el.attr(name).and_then(|v| v.parse().ok())
}

fn attr_f32(el: &XmlElem, name: &str) -> Option<f32> {
    el.attr(name).and_then(|v| v.parse().ok())
}

fn map_point(el: &XmlElem) -> Point {
    Point {
        x: attr_f32(el, "x").unwrap_or(0.0),
        y: attr_f32(el, "y").unwrap_or(0.0),
    }
}

fn map_transformation(el: &XmlElem) -> Transformation {
    Transformation {
        translate: el.find("Translate").map(map_point),
        scale: el.find("Scale").map(map_point),
    }
}

fn map_frame(el: &XmlElem) -> Frame {
    Frame {
        utc_time: el
            .attr("UtcTime")
            .and_then(parse_xsd_datetime)
            .map(|unix| UtcStamp { unix }),
        transformation: el.find("Transformation").map(map_transformation),
        objects: el
            .find_all("Object")
            .iter()
            .map(|o| map_object(o))
            .collect(),
    }
}

fn map_object(el: &XmlElem) -> Object {
    Object {
        object_id: el
            .attr("ObjectId")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        uuid: el.attr("UUID").unwrap_or_default().to_string(),
        parent: el.attr("Parent").and_then(|v| v.parse().ok()),
        appearance: el.find("Appearance").map(map_appearance),
        behaviour: el.find("Behaviour").map(|b| Behaviour {
            removed: b.find("Removed").is_some(),
            idle: b.find("Idle").is_some(),
        }),
    }
}

fn map_appearance(el: &XmlElem) -> Appearance {
    Appearance {
        transformation: el.find("Transformation").map(map_transformation),
        shape: el.find("Shape").map(|s| Shape {
            bounding_box: s.find("BoundingBox").map(|b| Rectangle {
                bottom: attr_f64(b, "bottom").unwrap_or(0.0),
                top: attr_f64(b, "top").unwrap_or(0.0),
                right: attr_f64(b, "right").unwrap_or(0.0),
                left: attr_f64(b, "left").unwrap_or(0.0),
            }),
            polygon: s
                .find("Polygon")
                .map(|p| p.find_all("Point").iter().map(|pt| map_point(pt)).collect())
                .unwrap_or_default(),
            center_of_gravity: s.find("CenterOfGravity").map(map_point),
        }),
        class: el.find("Class").map(|c| Class {
            types: c
                .find_all("Type")
                .iter()
                .map(|t| ClassType {
                    kind: t.text.clone(),
                    likelihood: attr_f32(t, "Likelihood"),
                })
                .collect(),
            candidates: c
                .find_all("ClassCandidate")
                .iter()
                .map(|cand| ClassCandidate {
                    kind: cand.child_text("Type").unwrap_or_default(),
                    likelihood: cand.child_text("Likelihood").and_then(|t| t.parse().ok()),
                })
                .collect(),
        }),
        geo_location: el.find("GeoLocation").map(|g| GeoLocation {
            lon: attr_f64(g, "lon"),
            lat: attr_f64(g, "lat"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Go golden: a frame with a tracked vehicle (bounding box,
    /// polygon, class likelihoods, geo location) and a second frame whose
    /// object is being removed.
    const GOLDEN: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<tt:MetadataStream xmlns:tt="http://www.onvif.org/ver10/schema">
  <tt:VideoAnalytics>
    <tt:Frame UtcTime="2026-09-19T12:00:00.123Z">
      <tt:Transformation>
        <tt:Translate x="0" y="0"/>
        <tt:Scale x="0.5" y="0.5"/>
      </tt:Transformation>
      <tt:Object ObjectId="7" Parent="3">
        <tt:Appearance>
          <tt:Shape>
            <tt:BoundingBox bottom="0.8" top="0.4" right="0.6" left="0.2"/>
            <tt:Polygon>
              <tt:Point x="0.2" y="0.4"/>
              <tt:Point x="0.6" y="0.4"/>
              <tt:Point x="0.6" y="0.8"/>
              <tt:Point x="0.2" y="0.8"/>
            </tt:Polygon>
            <tt:CenterOfGravity x="0.4" y="0.6"/>
          </tt:Shape>
          <tt:Class>
            <tt:Type Likelihood="0.87">Vehicle</tt:Type>
            <tt:ClassCandidate>
              <tt:Type>Human</tt:Type>
              <tt:Likelihood>0.05</tt:Likelihood>
            </tt:ClassCandidate>
          </tt:Class>
          <tt:GeoLocation lon="116.397" lat="39.908"/>
        </tt:Appearance>
      </tt:Object>
    </tt:Frame>
    <tt:Frame UtcTime="2026-09-19T12:00:00.500Z">
      <tt:Object ObjectId="7">
        <tt:Behaviour>
          <tt:Removed/>
        </tt:Behaviour>
      </tt:Object>
    </tt:Frame>
  </tt:VideoAnalytics>
</tt:MetadataStream>"#;

    #[test]
    fn parse_golden() {
        let stream = parse(GOLDEN).unwrap();
        assert_eq!(stream.frames.len(), 2);

        let first = &stream.frames[0];
        // Second resolution: the .123 fraction truncates.
        assert_eq!(
            first.utc_time.map(|t| t.to_rfc3339()).as_deref(),
            Some("2026-09-19T12:00:00Z")
        );

        let tr = first.transformation.as_ref().unwrap();
        assert_eq!(tr.scale.unwrap().x, 0.5);

        assert_eq!(first.objects.len(), 1);
        let obj = &first.objects[0];
        assert_eq!((obj.object_id, obj.parent), (7, Some(3)));
        assert_eq!(obj.uuid, "");

        let appearance = obj.appearance.as_ref().unwrap();
        let shape = appearance.shape.as_ref().unwrap();
        let box_ = shape.bounding_box.as_ref().unwrap();
        assert_eq!(
            (box_.left, box_.right, box_.top, box_.bottom),
            (0.2, 0.6, 0.4, 0.8)
        );
        assert_eq!(shape.polygon.len(), 4);
        assert_eq!(shape.center_of_gravity.unwrap().x, 0.4);

        let class = appearance.class.as_ref().unwrap();
        assert_eq!(class.types.len(), 1);
        assert_eq!(class.types[0].kind, "Vehicle");
        assert_eq!(class.types[0].likelihood, Some(0.87));
        assert_eq!(class.candidates.len(), 1);
        assert_eq!(class.candidates[0].kind, "Human");
        assert_eq!(class.candidates[0].likelihood, Some(0.05));

        let geo = appearance.geo_location.as_ref().unwrap();
        assert_eq!(geo.lon, Some(116.397));
        assert_eq!(geo.lat, Some(39.908));

        let second = &stream.frames[1];
        assert_eq!(second.objects.len(), 1);
        let behaviour = second.objects[0].behaviour.as_ref().unwrap();
        assert!(behaviour.removed);
        assert!(!behaviour.idle);
    }

    /// Prefix independence: the same document with default xmlns
    /// declarations must decode identically (the Go
    /// TestParseDefaultNamespaceForm fixture).
    #[test]
    fn parse_default_namespace_form() {
        let doc = r#"<MetadataStream xmlns="http://www.onvif.org/ver10/schema">
<VideoAnalytics><Frame UtcTime="2026-09-19T12:00:00Z">
<Object ObjectId="1"><Appearance><Shape><BoundingBox bottom="1" top="0" right="1" left="0"/></Shape></Appearance></Object>
</Frame></VideoAnalytics></MetadataStream>"#;

        let stream = parse(doc).unwrap();
        assert_eq!(stream.frames.len(), 1);
        let box_ = stream.frames[0].objects[0]
            .appearance
            .as_ref()
            .unwrap()
            .shape
            .as_ref()
            .unwrap()
            .bounding_box
            .as_ref()
            .unwrap();
        assert_eq!((box_.left, box_.bottom), (0.0, 1.0));
    }

    /// Garbage and non-MetadataStream roots are rejected (the Go
    /// TestParseGarbage fixture).
    #[test]
    fn parse_garbage() {
        assert!(parse("not xml at all").is_err());
        assert!(parse("<Frame UtcTime=\"2026-09-19T12:00:00Z\"/>").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn parse_empty_stream_is_valid() {
        let stream =
            parse(r#"<tt:MetadataStream xmlns:tt="http://www.onvif.org/ver10/schema"/>"#).unwrap();
        assert_eq!(stream.frames.len(), 0);
    }

    /// Frames from SEVERAL VideoAnalytics blocks accumulate, and UUID /
    /// Idle marker decode.
    #[test]
    fn frames_accumulate_across_blocks() {
        let doc = r#"<MetadataStream xmlns="http://www.onvif.org/ver10/schema">
<VideoAnalytics><Frame UtcTime="2026-09-19T12:00:00Z"><Object ObjectId="1"/></Frame></VideoAnalytics>
<VideoAnalytics><Frame UtcTime="2026-09-19T12:00:01Z">
<Object ObjectId="2" UUID="urn:uuid:abc"><Behaviour><Idle/></Behaviour></Object></Frame></VideoAnalytics>
</MetadataStream>"#;
        let stream = parse(doc).unwrap();
        assert_eq!(stream.frames.len(), 2);
        assert_eq!(stream.frames[1].objects[0].uuid, "urn:uuid:abc");
        let behaviour = stream.frames[1].objects[0].behaviour.as_ref().unwrap();
        assert!(behaviour.idle);
        assert!(!behaviour.removed);
    }
}
