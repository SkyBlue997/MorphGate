//! Compiles `proto/morphgate/v1/*.proto` with the pure-Rust `protox` compiler
//! and generates prost types into `OUT_DIR`. No system `protoc` is needed.
//!
//! Also writes `OUT_DIR/proto_fields.rs`: every message's field names and
//! message-typed fields, used by the contract test that keeps `mg-core`'s JSON
//! field names identical to the protobuf field names.

use std::fmt::Write as _;
use std::path::PathBuf;

const FILES: &[&str] = &[
    "morphgate/v1/common.proto",
    "morphgate/v1/decision.proto",
    "morphgate/v1/config.proto",
    "morphgate/v1/challenge.proto",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // proto/rust -> proto (the include root that makes `morphgate/v1/...` imports resolve)
    let include = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?)
        .parent()
        .ok_or("mg-proto must live in proto/rust")?
        .to_path_buf();
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);

    for file in FILES {
        println!("cargo:rerun-if-changed={}", include.join(file).display());
    }

    let descriptors = protox::compile(FILES, [&include])?;

    // (message, field, message type of the field or "") for every field.
    let mut rows = Vec::new();
    for file in &descriptors.file {
        let package = file.package();
        let mut stack: Vec<_> = file
            .message_type
            .iter()
            .map(|m| (format!("{package}.{}", m.name()), m))
            .collect();
        while let Some((name, msg)) = stack.pop() {
            for field in &msg.field {
                const TYPE_MESSAGE: i32 = 11; // google.protobuf.FieldDescriptorProto.Type
                let ty = if field.r#type == Some(TYPE_MESSAGE) {
                    field.type_name().trim_start_matches('.').to_string()
                } else {
                    String::new()
                };
                rows.push((name.clone(), field.name().to_string(), ty));
            }
            for nested in &msg.nested_type {
                stack.push((format!("{name}.{}", nested.name()), nested));
            }
        }
    }
    rows.sort();
    let mut table = String::from(
        "/// `(message, field, message type or \"\")` for every field, sorted.\n\
         pub const PROTO_FIELDS: &[(&str, &str, &str)] = &[\n",
    );
    for (msg, field, ty) in &rows {
        writeln!(table, "    ({msg:?}, {field:?}, {ty:?}),")?;
    }
    table.push_str("];\n");
    std::fs::write(out_dir.join("proto_fields.rs"), table)?;

    prost_build::Config::new().compile_fds(descriptors)?;
    Ok(())
}
