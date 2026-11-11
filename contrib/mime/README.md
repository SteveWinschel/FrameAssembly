# Freedesktop `shared-mime-info` Package & Upstream Merge Guide for FrameAssembly (`.fasm`)

This directory contains the Freedesktop.org `shared-mime-info` XML database definition and upstream contribution assets for **FrameAssembly** (`.fasm`, media type `text/vnd.frameassembly`).

The definition provides desktop-wide MIME classification, content-sniffing magic rules, file-manager icons, and default editor associations across Linux, BSD, and Unix desktop environments (GNOME, KDE Plasma, XFCE, Sway, and Wayland/X11 compositors).

For the normative language specification, see [`docs/fasm-specification.md`](../../docs/fasm-specification.md). For the IANA registration application, see [`contrib/iana/text-vnd.frameassembly.md`](../iana/text-vnd.frameassembly.md). For GitHub Linguist integration, see [`contrib/linguist/README.md`](../linguist/README.md).

---

## 1. Package Definition Overview (`text-vnd.frameassembly.xml`)

The XML definition file [`text-vnd.frameassembly.xml`](text-vnd.frameassembly.xml) conforms to the [Freedesktop Shared MIME Info Specification](https://specifications.freedesktop.org/shared-mime-info-spec/shared-mime-info-spec-latest.html):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="text/vnd.frameassembly">
    <comment>FrameAssembly network packet specification</comment>
    <acronym>FASM</acronym>
    <expanded-acronym>FrameAssembly</expanded-acronym>
    <sub-class-of type="text/plain"/>
    <generic-icon name="text-x-script"/>
    <glob pattern="*.fasm" weight="60"/>
    <magic priority="60">
      ...
    </magic>
  </mime-type>
</mime-info>
```

### Key Elements & Technical Rationale

- **`type="text/vnd.frameassembly"`**: Formal media type aligned with RFC 6838 Vendor Tree registration (`contrib/iana/text-vnd.frameassembly.md`).
- **`<sub-class-of type="text/plain"/>`**: Ensures that every text editor, pager (`less`, `bat`), and previewer can inspect `.fasm` files out of the box even without dedicated syntax plugins.
- **`<generic-icon name="text-x-script"/>`**: Assigns standard script/source iconography in desktop file managers (GNOME Files/Nautilus, KDE Dolphin, Thunar).
- **`<glob pattern="*.fasm" weight="60"/>`**: Standard default glob weight is 50. Assigning `weight="60"` guarantees that FrameAssembly packet specifications are preferred over fallback generic plain-text associations.
- **`<magic priority="60">`**: Content-sniffing rules that accurately classify `.fasm` files by inspecting raw file contents even when filenames lack extensions or when conflicting file types share the `.fasm` extension.

---

## 2. Magic Content-Sniffing Rules Documentation

Because the `.fasm` extension is shared informally by Flat Assembler (x86 assembly) and FPGA FASM (SymbiFlow / F4PGA bitstream configurations), content sniffing is essential for deterministic disambiguation.

[`text-vnd.frameassembly.xml`](text-vnd.frameassembly.xml) implements two multi-level, nested conjunction (`AND`) magic rules:

### Conjunction Rule 1: `host ... ip|mac ... compile`

```xml
<match type="string" value="host " offset="0:1024">
  <match type="string" value="ip " offset="0:1536">
    <match type="string" value="compile" offset="0:8192"/>
  </match>
</match>
<match type="string" value="host " offset="0:1024">
  <match type="string" value="mac " offset="0:1536">
    <match type="string" value="compile" offset="0:8192"/>
  </match>
</match>
```

- **Offset `0:1024` for `host `**: Scans the first 1,024 bytes for the top-level strict-lowercase keyword `host` followed by a space or horizontal tab (`host&#x09;`). This offset window accommodates leading license banners and file comments.
- **Nested Offset `0:1536` for `ip ` or `mac `**: Requires either the `ip` or MAC-only `mac` endpoint configuration keyword within 1,536 bytes of file start, confirming that the block is a Layer 2 or Layer 3 network host declaration.
- **Nested Offset `0:8192` for `compile`**: Requires the compilation target block within the initial 8,192 bytes, ensuring the file is an end-to-end FrameAssembly specification rather than an arbitrary text document mentioning hosts.

### Conjunction Rule 2: `flow ... compile`

```xml
<match type="string" value="flow " offset="0:2048">
  <match type="string" value="compile" offset="0:8192"/>
</match>
```

- **Offset `0:2048` for `flow `**: Scans the first 2,048 bytes for the parameterized flow declaration keyword `flow` followed by a space or horizontal tab (`flow&#x09;`).
- **Nested Offset `0:8192` for `compile`**: Confirms that the flow is scheduled inside a `compile { ... }` block.
- **Priority `60`**: Overrides generic text and flat assembly heuristics (which look for `;` or `format PE`), ensuring zero false positives.

Neither Flat Assembler (which contains `format PE`, `section`, `use32`, and x86 mnemonics) nor FPGA FASM (which contains `#` and dot-separated hardware tile paths) contains `host`, `flow`, and `compile` blocks.

---

## 3. Local System Installation Guide

### Option A: User-Level (Rootless) Installation

Install the MIME package definition into the user's local XDG data directory:

```bash
# 1. Create the local MIME packages directory
mkdir -p ~/.local/share/mime/packages

# 2. Copy the XML definition
cp contrib/mime/text-vnd.frameassembly.xml ~/.local/share/mime/packages/

# 3. Update the local MIME database cache
update-mime-database ~/.local/share/mime
```

### Option B: System-Wide (Administrator) Installation

Install for all users on the system (standard path for package managers like APT, Pacman, RPM):

```bash
# 1. Copy the definition to the system packages directory
sudo cp contrib/mime/text-vnd.frameassembly.xml /usr/share/mime/packages/

# 2. Update the system MIME database
sudo update-mime-database /usr/share/mime
```

### Verifying MIME Installation

Verify that the local MIME database classifies `.fasm` files as `text/vnd.frameassembly`:

```bash
# Query via xdg-mime (standard freedesktop utility)
xdg-mime query filetype demo.fasm
# Output: text/vnd.frameassembly

# Query via GLib / GIO
gio info -a standard::content-type demo.fasm
# Output: standard::content-type: text/vnd.frameassembly

# Query via file utility (magic sniffing)
mimetype demo.fasm
# Output: demo.fasm: text/vnd.frameassembly
```

### Linux Distribution Packaging Integration

When creating Linux packages (`.deb`, `.rpm`), include `text-vnd.frameassembly.xml` under `/usr/share/mime/packages/` and invoke `update-mime-database` in post-install and post-remove hooks:

- **Debian (`debian/postinst` / `debian/postrm`)**:
  ```bash
  if [ -x /usr/bin/update-mime-database ]; then
      update-mime-database /usr/share/mime
  fi
  ```

---

## 4. Upstream GitLab Merge Request Guide (`shared-mime-info`)

To contribute `text/vnd.frameassembly` directly to the upstream Freedesktop.org repository so it ships by default in all future Linux distributions:

- **Upstream Repository**: [`https://gitlab.freedesktop.org/xdg/shared-mime-info`](https://gitlab.freedesktop.org/xdg/shared-mime-info)
- **Target File**: `data/freedesktop.org.xml.in` (master branch)
- **Key Requirement**: Upstream uses `data/freedesktop.org.xml.in` where translatable comment strings use `<_comment>` instead of `<comment>`.

### Git Patch Template for `data/freedesktop.org.xml.in`

```diff
diff --git a/data/freedesktop.org.xml.in b/data/freedesktop.org.xml.in
index a1b2c3d..e4f5a6b 100644
--- a/data/freedesktop.org.xml.in
+++ b/data/freedesktop.org.xml.in
@@ -5120,6 +5120,43 @@
     <glob pattern="*.pas"/>
   </mime-type>
 
+  <mime-type type="text/vnd.frameassembly">
+    <_comment>FrameAssembly network packet specification</_comment>
+    <acronym>FASM</acronym>
+    <expanded-acronym>FrameAssembly</expanded-acronym>
+    <sub-class-of type="text/plain"/>
+    <generic-icon name="text-x-script"/>
+    <glob pattern="*.fasm" weight="60"/>
+    <magic priority="60">
+      <match type="string" value="host " offset="0:1024">
+        <match type="string" value="ip " offset="0:1536">
+          <match type="string" value="compile" offset="0:8192"/>
+        </match>
+      </match>
+      <match type="string" value="host&#x09;" offset="0:1024">
+        <match type="string" value="ip " offset="0:1536">
+          <match type="string" value="compile" offset="0:8192"/>
+        </match>
+      </match>
+      <match type="string" value="host " offset="0:1024">
+        <match type="string" value="mac " offset="0:1536">
+          <match type="string" value="compile" offset="0:8192"/>
+        </match>
+      </match>
+      <match type="string" value="host&#x09;" offset="0:1024">
+        <match type="string" value="mac " offset="0:1536">
+          <match type="string" value="compile" offset="0:8192"/>
+        </match>
+      </match>
+      <match type="string" value="flow " offset="0:2048">
+        <match type="string" value="compile" offset="0:8192"/>
+      </match>
+      <match type="string" value="flow&#x09;" offset="0:2048">
+        <match type="string" value="compile" offset="0:8192"/>
+      </match>
+    </magic>
+  </mime-type>
+
   <mime-type type="text/x-patch">
     <_comment>differences between files</_comment>
     <sub-class-of type="text/plain"/>
```

### Upstream Testing Workflow (Meson & Ninja)

```bash
# 1. Clone the shared-mime-info repository
git clone https://gitlab.freedesktop.org/xdg/shared-mime-info.git
cd shared-mime-info

# 2. Setup build directory
meson setup build

# 3. Apply the patch above to data/freedesktop.org.xml.in
# Add a test file to tests/ (e.g. tests/sample.fasm)

# 4. Build and run tests
ninja -C build test
```

### Upstream GitLab Merge Request Description Template

```text
Title: Add text/vnd.frameassembly MIME type for FrameAssembly packet specifications

### Summary
Adds the `text/vnd.frameassembly` MIME type for FrameAssembly (`.fasm`) network packet specifications.

FrameAssembly is a declarative domain-specific language for synthesizing deterministic `.pcap` / `.pcapng` packet capture fixtures across 81 Layer 2–7 protocols.

### Specifications & Registrations
- Published Specification: https://github.com/SteveWinschel/FrameAssembly/blob/main/docs/fasm-specification.md
- IANA Vendor Tree Application: https://github.com/SteveWinschel/FrameAssembly/blob/main/contrib/iana/text-vnd.frameassembly.md
- Reference Compiler: https://github.com/SteveWinschel/FrameAssembly

### Disambiguation
The `.fasm` extension is shared with x86 Flat Assembler and FPGA FASM. This entry defines `weight="60"` and `<magic priority="60">` rules matching top-level `host ... ip|mac ... compile` and `flow ... compile` blocks, preventing false positive collisions.

### Verification
- Tested with `ninja -C build test`.
- Validated with `update-mime-database` and `xdg-mime`.
```

---

## 5. Desktop Application File Associations

To associate `.fasm` files with preferred code editors or the `frameassembly` terminal ladder previewer, configure XDG MIME applications:

```ini
# Add to ~/.config/mimeapps.list under [Default Applications]
[Default Applications]
text/vnd.frameassembly=code.desktop;org.gnome.TextEditor.desktop;
```

---

## 6. Verifying MIME Compilation with the Compiler

```frameassembly
host edge_router { ip 192.168.1.1 mac 00:11:22:33:44:01 }
host core_switch { ip 192.168.1.2 mac 00:11:22:33:44:02 }

flow lldp_discovery(src, dst) {
    src -> dst lldp chassisid "router-01" portid "eth0" ttl 120 wait 5ms
}

compile {
    lldp_discovery(edge_router, core_switch)
}
```
