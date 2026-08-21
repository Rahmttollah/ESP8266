/*
  CurrentWatch ESP8266 -> Render API heartbeat client
  FORENSIC DEBUG VERSION
  - Heartbeat schedule: 500ms
  const char* WIFI_SSID = "দীয়া বাবু";
const char* WIFI_PASSWORD = "OOOOOOOO";
  - WiFi modem sleep: disabled for lower latency/jitter
  - Auto reconnect: enabled
*/

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClientSecure.h>

const char* WIFI_SSID = "দীয়া বাবু";
const char* WIFI_PASSWORD = "OOOOOOOO";

const char* CURRENTWATCH_API =
    "https://currentwatch-api.onrender.com/api/heartbeat";

const char* DEVICE_API_KEY = "Rifat6677";
const char* DEVICE_ID = "currentwatch-01";

const unsigned long HEARTBEAT_INTERVAL_MS = 10;

// Safety limit for a single HTTPS request.
// This prevents one request from blocking the ESP for 37+ seconds.
const unsigned long HTTP_TIMEOUT_MS = 12000;

unsigned long lastHeartbeatMs = 0;
bool apiReady = false;

// ------------------------------------------------------------
// FORENSIC SERIAL LOGGING
// ------------------------------------------------------------

void printTimestamp() {
  Serial.print("[");
  Serial.print(millis());
  Serial.print(" ms | uptime ");
  Serial.print(millis() / 1000UL);
  Serial.print("s] ");
}

void logLine(const String& text) {
  printTimestamp();
  Serial.println(text);
}

void printWiFiState(const char* prefix) {
  printTimestamp();
  Serial.print(prefix);
  Serial.print(" WiFi=");

  wl_status_t status = WiFi.status();

  switch (status) {
    case WL_CONNECTED:
      Serial.print("CONNECTED");
      break;
    case WL_NO_SSID_AVAIL:
      Serial.print("NO_SSID");
      break;
    case WL_CONNECT_FAILED:
      Serial.print("CONNECT_FAILED");
      break;
    case WL_CONNECTION_LOST:
      Serial.print("CONNECTION_LOST");
      break;
    case WL_DISCONNECTED:
      Serial.print("DISCONNECTED");
      break;
    default:
      Serial.print("STATUS_");
      Serial.print((int)status);
      break;
  }

  if (status == WL_CONNECTED) {
    Serial.print(" RSSI=");
    Serial.print(WiFi.RSSI());
    Serial.print("dBm IP=");
    Serial.print(WiFi.localIP());
  }

  Serial.println();
}

// ------------------------------------------------------------
// WIFI EVENTS
// ------------------------------------------------------------

WiFiEventHandler wifiConnectHandler;
WiFiEventHandler wifiDisconnectHandler;

void onWiFiConnect(const WiFiEventStationModeConnected& event) {
  logLine("WIFI EVENT: CONNECTED TO AP");
}

void onWiFiDisconnect(const WiFiEventStationModeDisconnected& event) {
  printTimestamp();
  Serial.print("WIFI EVENT: DISCONNECTED | reason=");
  Serial.println((int)event.reason);
}

// ------------------------------------------------------------
// WIFI CONNECTION
// ------------------------------------------------------------

void connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) {
    return;
  }

  logLine("WIFI CONNECTION REQUIRED");
  Serial.print("Connecting WiFi");

  WiFi.mode(WIFI_STA);

  // Stability-oriented ESP8266 WiFi settings.
  // Disable modem sleep to reduce WiFi latency/jitter.
  WiFi.setSleepMode(WIFI_NONE_SLEEP);

  // Let the ESP automatically reconnect if the AP connection drops.
  WiFi.setAutoReconnect(true);

  // Avoid writing WiFi credentials/settings to flash repeatedly.
  WiFi.persistent(false);

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  unsigned long started = millis();

  while (WiFi.status() != WL_CONNECTED &&
         millis() - started < 15000UL) {
    delay(250);
    Serial.print(".");
  }

  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {
    printWiFiState("WIFI CONNECTED:");
  } else {
    logLine("WIFI CONNECTION FAILED AFTER 15 SECONDS");
    printWiFiState("WIFI STATE:");
  }
}

// ------------------------------------------------------------
// HEARTBEAT
// ------------------------------------------------------------

bool sendCurrentWatchHeartbeat() {
  unsigned long functionStart = millis();

  logLine("HEARTBEAT START");
  printWiFiState("BEFORE HTTP:");

  if (WiFi.status() != WL_CONNECTED) {
    apiReady = false;

    logLine("HEARTBEAT ABORTED: WIFI NOT CONNECTED");

    connectWiFi();

    if (WiFi.status() != WL_CONNECTED) {
      logLine("HEARTBEAT ABORTED: WIFI RECONNECT FAILED");
      return false;
    }
  }

  WiFiClientSecure client;
  client.setInsecure();

  HTTPClient http;

  // Prevent a stuck HTTPS request from blocking the ESP for tens of seconds.
  http.setTimeout(HTTP_TIMEOUT_MS);

  logLine("HTTP BEGIN START");

  unsigned long beginStart = millis();

  if (!http.begin(client, CURRENTWATCH_API)) {
    apiReady = false;

    printTimestamp();
    Serial.print("HTTP BEGIN FAILED | duration=");
    Serial.print(millis() - beginStart);
    Serial.println(" ms");

    return false;
  }

  printTimestamp();
  Serial.print("HTTP BEGIN OK | duration=");
  Serial.print(millis() - beginStart);
  Serial.println(" ms");

  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-Device-Key", DEVICE_API_KEY);

  String body = "{\"device_id\":\"";
  body += DEVICE_ID;
  body += "\"}";

  logLine("HTTP POST START");

  unsigned long postStart = millis();

  int httpCode = http.POST(body);

  unsigned long postDuration = millis() - postStart;
  unsigned long totalDuration = millis() - functionStart;

  if (httpCode >= 200 && httpCode < 300) {
    apiReady = true;

    printTimestamp();
    Serial.print("HEARTBEAT OK: ");
    Serial.print(httpCode);
    Serial.print(" | POST=");
    Serial.print(postDuration);
    Serial.print(" ms | TOTAL=");
    Serial.print(totalDuration);
    Serial.print(" ms | RSSI=");

    if (WiFi.status() == WL_CONNECTED) {
      Serial.print(WiFi.RSSI());
      Serial.print("dBm");
    } else {
      Serial.print("DISCONNECTED");
    }

    Serial.print(" | FREE_HEAP=");
    Serial.println(ESP.getFreeHeap());

    http.end();
    return true;
  }

  apiReady = false;

  printTimestamp();
  Serial.print("HEARTBEAT FAILED: HTTP=");
  Serial.print(httpCode);
  Serial.print(" | POST=");
  Serial.print(postDuration);
  Serial.print(" ms | TOTAL=");
  Serial.print(totalDuration);
  Serial.println(" ms");

  if (httpCode > 0) {
    Serial.print("Response: ");
    Serial.println(http.getString());
  } else {
    Serial.print("HTTP Error: ");
    Serial.println(http.errorToString(httpCode));
  }

  printWiFiState("AFTER HTTP:");

  http.end();
  return false;
}

// ------------------------------------------------------------
// HEARTBEAT SCHEDULER
// ------------------------------------------------------------

void currentWatchLoop() {
  unsigned long now = millis();

  if (now - lastHeartbeatMs < HEARTBEAT_INTERVAL_MS) {
    return;
  }

  lastHeartbeatMs = now;

  // Keep the existing electricity/current logic independent.
  sendCurrentWatchHeartbeat();
}

// ------------------------------------------------------------
// SETUP
// ------------------------------------------------------------

void setup() {
  Serial.begin(115200);
  delay(100);

  wifiConnectHandler =
      WiFi.onStationModeConnected(onWiFiConnect);

  wifiDisconnectHandler =
      WiFi.onStationModeDisconnected(onWiFiDisconnect);

  Serial.println();
  Serial.println("==============================================");
  Serial.println("CurrentWatch ESP8266 FORENSIC HEARTBEAT");
  Serial.println("==============================================");

  printTimestamp();
  Serial.print("RESET REASON: ");
  Serial.println(ESP.getResetReason());

  printTimestamp();
  Serial.print("FREE HEAP: ");
  Serial.println(ESP.getFreeHeap());

  printTimestamp();
  Serial.print("HEARTBEAT SCHEDULE: ");
  Serial.print(HEARTBEAT_INTERVAL_MS);
  Serial.println(" ms");

  printTimestamp();
  Serial.print("HTTP TIMEOUT: ");
  Serial.print(HTTP_TIMEOUT_MS);
  Serial.println(" ms");

  connectWiFi();

  if (WiFi.status() == WL_CONNECTED) {
    sendCurrentWatchHeartbeat();
    lastHeartbeatMs = millis();
  }
}

// ------------------------------------------------------------
// LOOP
// ------------------------------------------------------------

void loop() {
  currentWatchLoop();

  // KEEP YOUR EXISTING ELECTRICITY/CURRENT CODE HERE.
}
