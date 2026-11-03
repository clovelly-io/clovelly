//! Predicts RTMR1 and RTMR2 for a cell image offline, from its UKI and disk.
//!
//! What GCE's TDVF and systemd-stub extend, in order (checked against the CCEL of a
//! booted cell; RTMR0 is firmware state and RTMR3 stays zero, both recorded instead):
//!
//! RTMR1 (PCR 2-6):
//! 1. `EV_EFI_ACTION` "Calling EFI Application from Boot Option"
//! 2. `EV_SEPARATOR` (four zero bytes)
//! 3. `EV_EFI_GPT_EVENT`: the disk's GPT ([`gpt::gpt_event_data`])
//! 4. `EV_EFI_BOOT_SERVICES_APPLICATION`: the UKI's Authenticode digest. A Secure Boot
//!    signature does not change it.
//! 5. `EV_EFI_ACTION` "Exit Boot Services Invocation"
//! 6. `EV_EFI_ACTION` "Exit Boot Services Returned with Success"
//!
//! RTMR2 (PCR 8-15):
//! 1. systemd-stub's PCR 11 measurements of the UKI's sections, in its fixed order, each
//!    as the section name with its NUL and then the contents. The kernel command line is
//!    the `.cmdline` section; nothing is measured into PCR 12 unless the stub took load
//!    options, which Secure Boot forbids.
//! 2. The Linux EFI stub's PCR 9 `EV_EVENT_TAG` events: the load options systemd-stub
//!    passes (the command line, UTF-16 with its NUL) and the initrd it hands over (the
//!    `.initrd` section and a generated cpio with `.extra/os-release`, each padded to
//!    four bytes). The kernel logs these through the CC measurement protocol only when
//!    the firmware offers no TCG2 protocol, so this holds for cells without a vTPM,
//!    which is how cells are created; with a vTPM they go to the TPM instead.

pub mod gpt;
pub mod pe;

use common::tdx::Measurement;

/// The sections systemd-stub (v260) measures into PCR 11, in measurement order.
/// `.pcrsig` is never measured.
const STUB_SECTIONS: [&str; 10] = [
    ".linux", ".osrel", ".cmdline", ".initrd", ".ucode", ".splash", ".dtb", ".uname",
    ".sbat", ".pcrpkey",
];
/// Sections this predictor does not model: later stubs measure the first four, and
/// the others change the initrd systemd-stub builds.
const UNMODELLED: [&str; 7] = [".profile", ".dtbauto", ".hwids", ".efifw", ".ucode", ".pcrsig", ".pcrpkey"];

#[derive(Debug, thiserror::Error)]
pub enum PredictError {
    #[error(transparent)]
    Pe(#[from] pe::PeError),
    #[error(transparent)]
    Gpt(#[from] gpt::GptError),
    #[error("the UKI has section {0}, which this predictor does not model")]
    Unmodelled(String),
}

/// One extension of a predicted register, for reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    pub what: String,
    pub digest: Measurement,
}

/// Predicted RTMR1 and RTMR2, with the extensions that produce them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prediction {
    pub rtmr1: Measurement,
    pub rtmr2: Measurement,
    pub rtmr1_events: Vec<Extension>,
    pub rtmr2_events: Vec<Extension>,
}

fn action(text: &str) -> Extension {
    Extension {
        what: format!("EV_EFI_ACTION {text:?}"),
        digest: Measurement::sha384(text.as_bytes()),
    }
}

fn fold(events: &[Extension]) -> Measurement {
    events
        .iter()
        .fold(Measurement::ZERO, |r, e| r.extend(&e.digest))
}

/// Predicts the registers for `uki` (the EFI binary on the ESP) booted from `disk`.
pub fn predict(
    uki: &[u8],
    disk: &mut (impl std::io::Read + std::io::Seek),
) -> Result<Prediction, PredictError> {
    let image = pe::Pe::parse(uki)?;
    if let Some(s) = image
        .sections
        .iter()
        .find(|s| UNMODELLED.contains(&s.name.as_str()))
    {
        return Err(PredictError::Unmodelled(s.name.clone()));
    }
    let rtmr1_events = vec![
        action("Calling EFI Application from Boot Option"),
        Extension {
            what: "EV_SEPARATOR".into(),
            digest: Measurement::sha384(&[0; 4]),
        },
        Extension {
            what: "EV_EFI_GPT_EVENT".into(),
            digest: Measurement::sha384(&gpt::gpt_event_data(disk)?),
        },
        Extension {
            what: "EV_EFI_BOOT_SERVICES_APPLICATION (UKI Authenticode)".into(),
            digest: image.authenticode_sha384()?,
        },
        action("Exit Boot Services Invocation"),
        action("Exit Boot Services Returned with Success"),
    ];
    let mut rtmr2_events: Vec<Extension> = STUB_SECTIONS
        .iter()
        .filter_map(|&name| Some((name, image.section(name)?)))
        .flat_map(|(name, contents)| {
            let tagged: Vec<u8> = name.bytes().chain([0]).collect();
            [
                Extension {
                    what: format!("EV_IPL {name} name"),
                    digest: Measurement::sha384(&tagged),
                },
                Extension {
                    what: format!("EV_IPL {name} contents"),
                    digest: Measurement::sha384(contents),
                },
            ]
        })
        .collect();
    rtmr2_events.push(Extension {
        what: "EV_EVENT_TAG Linux LOADED_IMAGE::LoadOptions".into(),
        digest: Measurement::sha384(&load_options(image.section(".cmdline").unwrap_or_default())),
    });
    rtmr2_events.push(Extension {
        what: "EV_EVENT_TAG Linux initrd".into(),
        digest: Measurement::sha384(&stub_initrd(
            image.section(".initrd").unwrap_or_default(),
            image.section(".osrel").unwrap_or_default(),
        )),
    });
    Ok(Prediction {
        rtmr1: fold(&rtmr1_events),
        rtmr2: fold(&rtmr2_events),
        rtmr1_events,
        rtmr2_events,
    })
}

/// The load options systemd-stub (v260) gives the kernel: the `.cmdline` section up to
/// its first NUL with leading whitespace skipped, inner whitespace and control
/// characters turned into spaces and trailing whitespace chopped (`mangle_stub_cmdline`),
/// as UTF-16LE with a terminating NUL.
fn load_options(cmdline: &[u8]) -> Vec<u8> {
    let end = cmdline.iter().position(|&b| b == 0).unwrap_or(cmdline.len());
    let text = String::from_utf8_lossy(&cmdline[..end]);
    let space = |c: char| c <= ' ' || c == '\u{7f}';
    let mangled: String = text
        .trim_matches(space)
        .chars()
        .map(|c| if space(c) { ' ' } else { c })
        .collect();
    mangled
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn pad4(mut b: Vec<u8>) -> Vec<u8> {
    b.resize(b.len().next_multiple_of(4), 0);
    b
}

/// One newc cpio header and name, padded, as systemd-stub's `pack_cpio_*` write them:
/// no mtime, uid or gid, inode numbers from 1.
fn cpio_entry(inode: u32, mode: u32, size: usize, name: &str) -> Vec<u8> {
    let mut h = b"070701".to_vec();
    for v in [inode, mode, 0, 0, 1, 0, size as u32, 0, 0, 0, 0, name.len() as u32 + 1, 0] {
        h.extend_from_slice(format!("{v:08x}").as_bytes());
    }
    h.extend_from_slice(name.as_bytes());
    h.push(0);
    pad4(h)
}

/// The initrd systemd-stub (v260) builds for a UKI without credentials, extensions or
/// microcode: the `.initrd` section, then a cpio holding `.extra/os-release` (the
/// `.osrel` section), each padded to four bytes (`combine_initrds`).
fn stub_initrd(initrd: &[u8], osrel: &[u8]) -> Vec<u8> {
    let mut cpio = cpio_entry(1, 0o040_555, 0, ".extra");
    cpio.extend(cpio_entry(2, 0o100_444, osrel.len(), ".extra/os-release"));
    cpio.extend(pad4(osrel.to_vec()));
    // The trailer record: inode 0, nlink 1, name "TRAILER!!!" (11 bytes with its NUL),
    // padded to four bytes.
    let mut trailer = b"070701".to_vec();
    for v in [0u32, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0] {
        trailer.extend_from_slice(format!("{v:08x}").as_bytes());
    }
    trailer.extend_from_slice(b"0000000B00000000TRAILER!!!\0\0\0\0");
    cpio.extend(trailer);
    let mut out = pad4(initrd.to_vec());
    out.extend(pad4(cpio));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtmr2_measures_present_sections_in_stub_order() {
        let uki = pe::tests::image(
            &[(".cmdline", b"clovelly.roothash=00\n"), (".linux", b"bzImage")],
            b"",
        );
        let head = include_bytes!("../tests/data/gpt-head.bin");
        let p = predict(&uki, &mut std::io::Cursor::new(&head[..])).unwrap();
        let order: Vec<&str> = p.rtmr2_events.iter().map(|e| e.what.as_str()).collect();
        assert_eq!(
            order,
            [
                "EV_IPL .linux name",
                "EV_IPL .linux contents",
                "EV_IPL .cmdline name",
                "EV_IPL .cmdline contents",
                "EV_EVENT_TAG Linux LOADED_IMAGE::LoadOptions",
                "EV_EVENT_TAG Linux initrd",
            ]
        );
        assert_eq!(
            p.rtmr2_events[3].digest,
            Measurement::sha384(b"clovelly.roothash=00\n")
        );
        assert_eq!(p.rtmr2, fold(&p.rtmr2_events));
        assert_eq!(p.rtmr1_events.len(), 6);
    }

    /// The constant firmware events digest as a booted TD logged them.
    #[test]
    fn firmware_actions_match_a_booted_log() {
        assert!(
            action("Calling EFI Application from Boot Option")
                .digest
                .to_string()
                .starts_with("77a0dab2312b4e1e")
        );
        assert!(
            action("Exit Boot Services Returned with Success")
                .digest
                .to_string()
                .starts_with("0a2e01c85deae718")
        );
    }

    #[test]
    fn load_options_are_the_mangled_command_line_in_utf16() {
        let expected: Vec<u8> = "a b c\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(load_options(b" a\nb\tc \n\0junk"), expected);
    }

    /// The cpio framing systemd-stub writes, checked against its source: the trailer
    /// is 124 bytes and every entry is a multiple of four.
    #[test]
    fn stub_initrd_layout() {
        let out = stub_initrd(b"12345", b"ID=clovelly\n");
        assert_eq!(&out[..8], b"12345\0\0\0");
        let cpio = &out[8..];
        assert!(cpio.starts_with(b"070701000000010000416d"));
        assert!(cpio.ends_with(b"TRAILER!!!\0\0\0\0"));
        assert_eq!(cpio.len() % 4, 0);
    }

    #[test]
    fn refuses_sections_it_does_not_model() {
        let uki = pe::tests::image(&[(".profile", b"x")], b"");
        let head = include_bytes!("../tests/data/gpt-head.bin");
        assert!(matches!(
            predict(&uki, &mut std::io::Cursor::new(&head[..])),
            Err(PredictError::Unmodelled(_))
        ));
    }
}
