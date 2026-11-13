//! USB devices attached to the host, from the kernel messages that syslog files and `dmesg`
//! output keep (`var/log/syslog`, `messages`, `kern.log`, `dmesg`). Not the journal: the
//! `journald` artifact owns that. One record per attach, with what the USB core logs about
//! the device (drivers/usb/core/hub.c and usb.c): the vendor and product ids, the descriptor
//! strings (`Product:`, `Manufacturer:`, `SerialNumber:`), the speed and host controller, and
//! the time it was disconnected. A device that the mass-storage driver claimed (`usb-storage`)
//! is marked, because a USB disk is a way to carry data out. A keyboard that appears in the
//! middle of a session is how keystroke-injection devices show up.
//!
//! Format: the lines the kernel prints, `usb 1-1: New USB device found, idVendor=0627,
//! idProduct=0001, bcdDevice= 0.00`, with a syslog header or a `dmesg` uptime stamp
//! (`[  12.345678]`). A record made from a `dmesg` line carries the uptime and no time of day:
//! the boot time is not in the text. Root hubs (`usb usb1`) are devices too and are kept, so the
//! count of records is the count of `New USB device found` lines.

use crate::common::syslog::{parse_header, timeline_message};
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, UNIX};
use nixcavate_core::{Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "usb-devices",
    "USB devices attached, from kernel messages in syslog and dmesg files",
    Category::Security,
    UNIX,
    &[
        "var/log/syslog*",
        "var/log/messages*",
        "var/log/kern.log*",
        "var/log/kernel.log*",
        "var/log/dmesg*",
        "var/log/debug*",
    ],
    parse,
);

/// Open records held at once; a log of thousands of re-plugs stays bounded.
const MAX_DEVICES: usize = 20_000;

#[derive(Serialize)]
struct Usb {
    /// When the device was attached (the `New USB device found` line).
    time: Option<Timestamp>,
    /// Seconds since boot, from a `dmesg` stamp.
    uptime_secs: Option<f64>,
    /// The bus and port path: `usb1` for a root hub, `1-1` or `3-2.4` for a device.
    device: String,
    device_number: Option<u32>,
    /// `low-speed`, `full-speed`, `high-speed`, `super-speed`...
    speed: Option<String>,
    /// The host controller driver: `xhci_hcd`, `uhci_hcd`, `ehci-pci`.
    controller: Option<String>,
    vendor_id: String,
    product_id: String,
    bcd_device: Option<String>,
    manufacturer: Option<String>,
    product: Option<String>,
    serial_number: Option<String>,
    /// The mass-storage driver claimed the device.
    mass_storage: bool,
    /// The `USB disconnect` line for this device number, when the log has it.
    disconnected: Option<Timestamp>,
    #[serde(skip)]
    offset: u64,
}

impl Record for Usb {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let name = format!(
            "{} {:?} {:?} ({}:{}){}",
            self.device,
            self.manufacturer.as_deref().unwrap_or(""),
            self.product.as_deref().unwrap_or(""),
            self.vendor_id,
            self.product_id,
            if self.mass_storage { " mass storage" } else { "" }
        );
        let mut events = Vec::new();
        if let Some(t) = self.time {
            events.push(Event::new(t, "usb_attached", timeline_message("usb", &name)));
        }
        if let Some(t) = self.disconnected {
            events.push(Event::new(t, "usb_detached", timeline_message("usb", &name)));
        }
        events.into_iter()
    }
}

/// `[  12.345678] message` into the uptime and the message.
fn dmesg_stamp(message: &str) -> Option<(f64, &str)> {
    let rest = message.strip_prefix('[')?;
    let (stamp, rest) = rest.split_once(']')?;
    Some((stamp.trim().parse().ok()?, rest.trim_start()))
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut devices: Vec<Usb> = Vec::new();
    let mut full_warned = false;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let header = parse_header(input, text.trim_end().as_bytes());
        // `kernel:` is the program of a syslog line; a bare dmesg line has none.
        if !matches!(header.program.as_ref(), "kernel" | "") {
            return Ok(());
        }
        let message: &str = &header.message;
        let (uptime, message) = match dmesg_stamp(message) {
            Some((up, rest)) => (Some(up), rest),
            None => (None, message),
        };
        let Some(rest) = message.strip_prefix("usb ").or_else(|| message.strip_prefix("usb-storage ")) else {
            return Ok(());
        };
        let storage = message.starts_with("usb-storage ");
        let Some((device, what)) = rest.split_once(": ") else { return Ok(()) };
        // `usb-storage 1-1:1.0` names an interface: the device is before the colon.
        let device = if storage { device.split(':').next().unwrap_or(device) } else { device };
        let open = |devices: &mut Vec<Usb>| devices.iter().rposition(|d| d.device == device);
        if storage {
            if what.starts_with("USB Mass Storage device detected") {
                if let Some(at) = open(&mut devices) {
                    devices[at].mass_storage = true;
                }
            }
            return Ok(());
        }
        if let Some(found) = what.strip_prefix("New USB device found, ") {
            let (mut vendor, mut product, mut bcd) = ("", "", None);
            for part in found.split(", ") {
                match part.split_once('=') {
                    Some(("idVendor", v)) => vendor = v,
                    Some(("idProduct", v)) => product = v,
                    Some(("bcdDevice", v)) => bcd = Some(v.trim().to_string()),
                    _ => {}
                }
            }
            if devices.len() >= MAX_DEVICES {
                if !std::mem::replace(&mut full_warned, true) {
                    sink.warn(format!(
                        "more than {MAX_DEVICES} USB devices at once; the oldest are written out unfinished"
                    ));
                }
                let oldest = devices.remove(0);
                sink.emit(Loc::Offset(oldest.offset), &oldest)?;
            }
            // The speed and controller come from the `new ... USB device number` line just before.
            let announced = devices.iter().rposition(|d| d.device == device && d.vendor_id.is_empty());
            let mut usb = match announced {
                Some(at) => devices.remove(at),
                None => Usb {
                    time: header.time,
                    uptime_secs: uptime,
                    device: device.to_string(),
                    device_number: None,
                    speed: None,
                    controller: None,
                    vendor_id: String::new(),
                    product_id: String::new(),
                    bcd_device: None,
                    manufacturer: None,
                    product: None,
                    serial_number: None,
                    mass_storage: false,
                    disconnected: None,
                    offset: line.offset,
                },
            };
            usb.vendor_id = vendor.to_string();
            usb.product_id = product.to_string();
            usb.bcd_device = bcd;
            devices.push(usb);
        } else if let Some(new) = what.strip_prefix("new ") {
            // `new full-speed USB device number 2 using uhci_hcd` (or `... address 2` before 2.6.32).
            if let Some((speed, tail)) = new.split_once(" USB device") {
                let number = tail
                    .split_whitespace()
                    .skip_while(|w| *w != "number" && *w != "address")
                    .nth(1)
                    .and_then(|n| n.parse().ok());
                let controller =
                    tail.split(" using ").nth(1).map(|c| c.split_whitespace().next().unwrap_or_default().to_string());
                if devices.len() < MAX_DEVICES {
                    devices.push(Usb {
                        time: header.time,
                        uptime_secs: uptime,
                        device: device.to_string(),
                        device_number: number,
                        speed: Some(speed.to_string()),
                        controller,
                        vendor_id: String::new(),
                        product_id: String::new(),
                        bcd_device: None,
                        manufacturer: None,
                        product: None,
                        serial_number: None,
                        mass_storage: false,
                        disconnected: None,
                        offset: line.offset,
                    });
                }
            }
        } else if let Some(value) = what.strip_prefix("Product: ") {
            if let Some(at) = open(&mut devices) {
                devices[at].product = Some(value.to_string());
            }
        } else if let Some(value) = what.strip_prefix("Manufacturer: ") {
            if let Some(at) = open(&mut devices) {
                devices[at].manufacturer = Some(value.to_string());
            }
        } else if let Some(value) = what.strip_prefix("SerialNumber: ") {
            if let Some(at) = open(&mut devices) {
                devices[at].serial_number = Some(value.to_string());
            }
        } else if let Some(number) = what.strip_prefix("USB disconnect, device number ") {
            let number: Option<u32> = number.trim().parse().ok();
            if let Some(at) = devices.iter().rposition(|d| {
                d.device == device && (number.is_none() || d.device_number == number || d.device_number.is_none())
            }) {
                devices[at].disconnected = header.time;
                // Done: no more descriptor lines belong to this device.
                let finished = devices.remove(at);
                sink.emit(Loc::Offset(finished.offset), &finished)?;
            }
        }
        Ok(())
    })?;
    for usb in devices {
        // A `new ... USB device` line that never got its descriptor is not an attach record.
        if !usb.vendor_id.is_empty() {
            sink.emit(Loc::Offset(usb.offset), &usb)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::run;

    fn records(out: &str) -> Vec<&str> {
        out.lines().take_while(|l| !l.starts_with("---")).collect()
    }

    /// Synthetic only: the line layouts come from the kernel sources (drivers/usb/core/hub.c, usb.c,
    /// storage/usb.c) and from real kernel logs of qemu guests (root hubs, a tablet); the keyboard and
    /// the disk are made up. The real-log check is in the validation notes, not a fixture.
    const KERN: &str = "\
Nov 11 21:48:11 host kernel: usb usb1: New USB device found, idVendor=1d6b, idProduct=0002, bcdDevice= 3.10
Nov 11 21:48:11 host kernel: usb usb1: New USB device strings: Mfr=3, Product=2, SerialNumber=1
Nov 11 21:48:11 host kernel: usb usb1: Manufacturer: Linux 3.10.0 ehci_hcd
Nov 11 21:48:11 host kernel: usb usb1: SerialNumber: 0000:00:04.7
Nov 11 21:49:02 host kernel: usb 1-1: new full-speed USB device number 2 using uhci_hcd
Nov 11 21:49:02 host kernel: usb 1-1: New USB device found, idVendor=0627, idProduct=0001, bcdDevice= 0.00
Nov 11 21:49:02 host kernel: usb 1-1: New USB device strings: Mfr=1, Product=3, SerialNumber=10
Nov 11 21:49:02 host kernel: usb 1-1: Product: QEMU USB Tablet
Nov 11 21:49:02 host kernel: usb 1-1: Manufacturer: QEMU
Nov 11 21:49:02 host kernel: usb 1-1: SerialNumber: 42
Nov 11 22:10:00 host kernel: usb 2-3: new high-speed USB device number 7 using xhci_hcd
Nov 11 22:10:00 host kernel: usb 2-3: New USB device found, idVendor=0781, idProduct=5567, bcdDevice= 1.00
Nov 11 22:10:00 host kernel: usb 2-3: Product: Cruzer Blade
Nov 11 22:10:00 host kernel: usb 2-3: Manufacturer: SanDisk
Nov 11 22:10:00 host kernel: usb 2-3: SerialNumber: 4C530001234567890123
Nov 11 22:10:01 host kernel: usb-storage 2-3:1.0: USB Mass Storage device detected
Nov 11 22:20:30 host kernel: usb 2-3: USB disconnect, device number 7
Nov 11 22:30:00 host kernel: usb 1-1: USB disconnect, device number 2
";

    #[test]
    fn attach_records_carry_descriptor_strings_storage_and_disconnect_time() {
        let out = run(&ARTIFACT, "var/log/kern.log", KERN.as_bytes(), 1_794_600_000);
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{out}");
        assert_eq!(records(&out).len(), KERN.matches("New USB device found").count());
        let disk = records(&out).into_iter().find(|l| l.contains("SanDisk")).unwrap_or_default();
        assert!(
            disk.contains("\"device\":\"2-3\"")
                && disk.contains("\"speed\":\"high-speed\"")
                && disk.contains("\"controller\":\"xhci_hcd\""),
            "{disk}"
        );
        assert!(
            disk.contains("\"mass_storage\":true") && disk.contains("\"serial_number\":\"4C530001234567890123\""),
            "{disk}"
        );
        assert!(
            disk.contains("-11-11T22:10:00Z") && disk.contains("\"disconnected\":\"") && disk.contains("T22:20:30Z"),
            "{disk}"
        );
        let tablet = records(&out).into_iter().find(|l| l.contains("QEMU USB Tablet")).unwrap_or_default();
        assert!(
            tablet.contains("\"vendor_id\":\"0627\",\"product_id\":\"0001\"")
                && tablet.contains("\"mass_storage\":false"),
            "{tablet}"
        );
        assert!(out.contains("usb_attached") && out.contains("usb_detached"));
        insta::assert_snapshot!(out);
    }

    #[test]
    fn dmesg_lines_carry_uptime_not_a_time_of_day() {
        let dmesg = "[    1.234567] usb 3-2: new low-speed USB device number 4 using xhci_hcd\n[    1.345678] usb 3-2: New USB device found, idVendor=046d, idProduct=c077, bcdDevice=72.00\n[    1.345700] usb 3-2: Product: USB Optical Mouse\n";
        let out = run(&ARTIFACT, "var/log/dmesg", dmesg.as_bytes(), 0);
        assert!(out.contains("\"time\":null") || out.contains("\"time\":\""), "{out}");
        assert!(out.contains("\"uptime_secs\":1.234567") && out.contains("USB Optical Mouse"), "{out}");
    }

    #[test]
    fn unrelated_and_hostile_lines_are_ignored() {
        let cases: [&[u8]; 6] = [
            b"Nov 11 22:10:00 host kernel: usb 2-3: New USB device found, idVendor=",
            b"Nov 11 22:10:00 host kernel: usb : ",
            b"Nov 11 22:10:00 host kernel: usb 2-3: USB disconnect, device number zzz",
            b"Nov 11 22:10:00 host sshd[1]: usb 2-3: New USB device found, idVendor=0781, idProduct=5567",
            b"[ abc] usb 1-1: Product: x",
            b"\xff\xfe usb 1-1: Product: \xff",
        ];
        for data in cases {
            run(&ARTIFACT, "var/log/kern.log", data, 1_794_600_000);
        }
        assert_eq!(records(&run(&ARTIFACT, "var/log/syslog", b"Nov 11 22:10:00 host sshd[1]: usb 2-3: New USB device found, idVendor=0781, idProduct=5567, bcdDevice= 1.00\n", 1_794_600_000)).len(), 0);
        for cut in 0..KERN.len() {
            run(&ARTIFACT, "var/log/kern.log", &KERN.as_bytes()[..cut], 1_794_600_000);
        }
    }
}
