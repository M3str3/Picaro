//! Windows application manifest (`RT_MANIFEST`) builder.
//!
//! Emits the small `asm.v1`/`asm.v3` document that carries the requested UAC
//! execution level and (optionally) DPI awareness. Embedding one turns a
//! "ran from a temp folder" binary into something that behaves like a normal
//! installed application for the shell and the compatibility engine.

use crate::plan::schema::ManifestPlan;

/// Builds the manifest XML for `plan`, as UTF-8 bytes.
pub fn build(plan: &ManifestPlan) -> Vec<u8> {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n");
    xml.push_str(
        "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\r\n",
    );
    xml.push_str("  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">\r\n");
    xml.push_str("    <security>\r\n");
    xml.push_str("      <requestedPrivileges>\r\n");
    xml.push_str(&format!(
        "        <requestedExecutionLevel level=\"{}\" uiAccess=\"{}\"/>\r\n",
        plan.level.xml_value(),
        plan.ui_access
    ));
    xml.push_str("      </requestedPrivileges>\r\n");
    xml.push_str("    </security>\r\n");
    xml.push_str("  </trustInfo>\r\n");

    if plan.dpi_aware {
        xml.push_str("  <application xmlns=\"urn:schemas-microsoft-com:asm.v3\">\r\n");
        xml.push_str("    <windowsSettings>\r\n");
        xml.push_str(
            "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>\r\n",
        );
        xml.push_str("    </windowsSettings>\r\n");
        xml.push_str("  </application>\r\n");
    }

    xml.push_str("</assembly>\r\n");
    xml.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::schema::ExecutionLevel;

    #[test]
    fn emits_the_requested_execution_level_and_ui_access() {
        let plan = ManifestPlan {
            level: ExecutionLevel::RequireAdministrator,
            ui_access: true,
            dpi_aware: true,
        };
        let xml = String::from_utf8(build(&plan)).expect("utf-8");
        assert!(xml.contains("level=\"requireAdministrator\""));
        assert!(xml.contains("uiAccess=\"true\""));
        assert!(xml.contains("<dpiAware"));
        assert!(xml.starts_with("<?xml"));
    }

    #[test]
    fn omits_dpi_awareness_when_disabled() {
        let plan = ManifestPlan {
            level: ExecutionLevel::AsInvoker,
            ui_access: false,
            dpi_aware: false,
        };
        let xml = String::from_utf8(build(&plan)).expect("utf-8");
        assert!(xml.contains("level=\"asInvoker\""));
        assert!(!xml.contains("dpiAware"));
    }
}
