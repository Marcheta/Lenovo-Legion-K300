// Lenovo Legion K300 RGB keyboard — SignalRGB plugin
// Reverse-engineered via static analysis (Ghidra/ldm_k300.dll) + live USB capture
// (USBPcap/Wireshark) of Lenovo "Legion Accessory Central" traffic.
//
// Protocol summary (capture and Lenovo application analysis):
//   1) USB SET_REPORT Feature control transfer, wValue=0x0300 (ReportId 0,
//      Type Feature), wIndex=3 (targets the vendor HID interface, MI_03),
//      wLength=8. Payload: [cmd0, cmd1, 0x5A, 0,0,0,0,0].
//   2) USB Interrupt OUT, endpoint 0x04, 64-byte payload:
//        bytes 0-3   : header  01 0C 02 03  (0C = five-zone static effect)
//        bytes 4-15  : reserved / always 0x00
//        bytes 16-18 : Zone 1 RGB
//        bytes 20-22 : Zone 2 RGB
//        bytes 24-26 : Zone 3 RGB
//        bytes 28-30 : Zone 4 RGB
//        bytes 32-34 : Zone 5 RGB
//        bytes 35-63 : reserved / always 0x00
//      (stride is 4 bytes per zone: R, G, B, 0x00 padding)
//
// UNVERIFIED / TODO before relying on this in production:
//   - The feature-report "cmd0 cmd1" bytes: live capture showed 0x88,0x01
//     once (possibly a one-time "enter custom mode" command) and 0x14,0x00
//     repeated for every zone-color push. This plugin assumes that split;
//     test and adjust if colors don't apply correctly.
//   - No clean "restore hardware control" command was captured, so
//     Shutdown() just pushes a black frame instead of guessing a
//     /k300/restore_factory-style command.
//
// Buffer/padding convention — CONFIRMED BY LIVE CAPTURE (k300_capture4.pcapng)
// of SignalRGB's own traffic: both device.send_report() and device.write()
// treat packet[0] as an implicit Report ID placeholder byte and STRIP it
// before transmission, because this device's HID descriptor declares
// unnumbered reports (Report ID 0). An earlier assumption (based on the
// bundled Lenovo_Legion_5_Pro_Keyboard.js example, whose device uses a real
// nonzero Report ID 0xCC baked into its descriptor, so nothing gets
// stripped for it) was WRONG for this device and caused cmd0/cmd1 to be
// silently dropped from every feature report. Both sendFeatureCommand() and
// sendColors() now prepend an explicit 0x00 pad byte so the real payload
// survives the strip.

export function Name() { return "Lenovo Legion K300"; }
export function VendorId() { return 0x17EF; }
export function ProductId() { return 0x60F0; }
export function Publisher() { return "Community (reverse-engineered)"; }
export function Documentation() { return "troubleshooting/lenovo"; }
export function Type() { return "hid"; }
export function DeviceType() { return "keyboard"; }

export function Size() { return [5, 1]; }
export function DefaultPosition() { return [240, 120]; }
export function DefaultScale() { return 8.0; }

let vLedNames = ["Zone 1", "Zone 2", "Zone 3", "Zone 4", "Zone 5"];
let vLedPositions = [[0, 0], [1, 0], [2, 0], [3, 0], [4, 0]];

export function LedNames() { return vLedNames; }
export function LedPositions() { return vLedPositions; }

/* global
shutdownColor:readonly
lightingMode:readonly
*/
export function ControllableParameters() {
  return [
    { "property": "lightingMode", "label": "Lighting Mode", "type": "combobox", "values": ["Canvas", "Zone Test"], "default": "Canvas" },
    { "property": "shutdownColor", "label": "Shutdown Color", "min": "0", "max": "360", "type": "color", "default": "000000" },
  ];
}

// Byte offset (within the 64-byte data payload) of each zone's RGB triplet.
const ZONE_OFFSETS = [16, 20, 24, 28, 32];
const TEST_COLORS = [[255, 0, 0], [0, 255, 0], [0, 0, 255], [255, 255, 0], [255, 0, 255]];
let lastRenderColors = null;
let lastRenderTime = 0;

export function Initialize() {
  lastRenderColors = null;
  lastRenderTime = 0;
  // One-time "enter custom/software lighting mode" command, inferred from
  // the first feature report seen in the capture (0x88, 0x01). Verify this
  // is actually required; some devices work fine without an explicit
  // "enter software mode" handshake.
  sendFeatureCommand(0x88, 0x01);
  device.pause(100);
  device.send_report([0x00, 0x19, 0x00, 0x5A, 0x0C, 0x00, 0x00, 0x00, 0x00], 9);
  device.pause(100);
}

export function Render() {
  sendColors(undefined, true);
  device.pause(50);
}

export function Shutdown(SystemSuspending) {
  sendFeatureCommand(0x14, 0x00);
  sendColors(shutdownColor || "#000000");
}

function sendFeatureCommand(cmd0, cmd1) {
  // 8-byte Feature report: [cmd0, cmd1, 0x5A, 0, 0, 0, 0, 0]
  // Matches the captured wLength=8 data stage exactly. This device's HID
  // descriptor declares unnumbered reports (Report ID 0), and SignalRGB's
  // device.send_report()/device.write() both treat packet[0] as that
  // placeholder Report ID byte and strip it before transmission — so a
  // leading 0x00 pad byte must be prepended here too (confirmed by capture:
  // omitting it caused cmd0 to be silently dropped on the wire).
  let packet = [0x00, cmd0, cmd1, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00];
  device.send_report(packet, packet.length);
}

function sendColors(overrideColor, skipUnchanged) {
  // Build the 64-byte lighting payload, then prepend the 0x00 report-id pad
  // byte for device.write() (matches SignalRGB's documented convention for
  // devices with no numbered reports on the write endpoint).
  let data = new Array(64).fill(0x00);
  data[0] = 0x01;
  data[1] = 0x0C;
  data[2] = 0x02;
  data[3] = 0x03;

  for (let i = 0; i < vLedPositions.length; i++) {
    let color;
    if (overrideColor) {
      color = hexToRgb(overrideColor);
    } else if (typeof lightingMode !== "undefined" && lightingMode === "Zone Test") {
      color = TEST_COLORS[i];
    } else {
      let [x, y] = vLedPositions[i];
      color = device.color(x, y);
    }
    let off = ZONE_OFFSETS[i];
    data[off] = color[0];
    data[off + 1] = color[1];
    data[off + 2] = color[2];
  }

  if (skipUnchanged) {
    let colors = ZONE_OFFSETS.map(off => data.slice(off, off + 3).join(",")).join(",");
    let now = Date.now();
    if (colors === lastRenderColors && now - lastRenderTime < 2000) return;
    sendFeatureCommand(0x14, 0x00);
    lastRenderColors = colors;
    lastRenderTime = now;
  }

  let packet = [0x00].concat(data); // leading report-id pad byte
  device.write(packet, packet.length);
}

function hexToRgb(hex) {
  let result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  if (!result) return [0, 0, 0];
  return [parseInt(result[1], 16), parseInt(result[2], 16), parseInt(result[3], 16)];
}

export function Validate(endpoint) {
  // MI_03 is the vendor-defined lighting interface (confirmed via
  // wIndex=3 in every captured SET_REPORT Feature transfer).
  return endpoint.interface === 3;
}

export function ImageUrl() { return ""; }
