/*
  CurrentWatch ESP8266 -> Render API heartbeat client
  RELIABLE + NON-BLOCKING WIFI RECONNECT VERSION

  Behavior:
  - No heartbeat retry-count limit.
  - HTTP attempts are short-fail and immediately retried.
  - On HTTP failure/timeout:
      -> close HTTP
      -> trigger WiFi reconnect
      -> do NOT block for 1+ seconds
      -> retry as soon as WiFi is connected
  - 5000 ms is ONLY the desired SUCCESS TARGET.
  - It is NOT a hard timeout.
  - Retries continue until a heartbeat succeeds.
  - WiFi reconnect is handled without a blocking reconnect loop.
  - Existing electricity/current code remains independent.
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

// ------------------------------------------------------------
// HEARTBEAT SETTINGS
// ------------------------------------------------------------

// Maximum time for ONE HTTP attempt.
const unsigned long HTTP_TIMEOUT_MS = 100UL;

// Desired time to successfully complete a heartbeat.
// NOT a hard stop.
const unsigned long HEARTBEAT_SUCCESS_TARGET_MS = 5000UL;

// Heartbeat schedule.
const unsigned long HEARTBEAT_INTERVAL_MS = 10UL;

// No retry delay.
const unsigned long RETRY_DELAY_MS = 0UL;

// WiFi reconnect trigger spacing.
// Prevents WiFi.begin() from being hammered continuously.
const unsigned long WIFI_RECONNECT_RETRY_MS = 1000UL;

// Initial WiFi connection is allowed more time.
const unsigned long INITIAL_WIFI_TIMEOUT_MS = 15000UL;

unsigned long lastHeartbeatMs = 0;
unsigned long lastWiFiReconnectTriggerMs = 0;

bool apiReady = false;
bool heartbeatRunning = false;
bool heartbeatWaitingForWiFi = false;

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
  Serial.print("WiFi=");

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

  heartbeatWaitingForWiFi = false;
}

void onWiFiDisconnect(const WiFiEventStationModeDisconnected& event) {
  printTimestamp();
  Serial.print("WIFI EVENT: DISCONNECTED | reason=");
  Serial.println((int)event.reason);

  apiReady = false;
}

// ------------------------------------------------------------
// WIFI CONFIGURATION
// ------------------------------------------------------------

void configureWiFi() {
  WiFi.mode(WIFI_STA);

  // Disable modem sleep for lower latency/jitter.
  WiFi.setSleepMode(WIFI_NONE_SLEEP);

  // Use the ESP8266's highest normal transmit-power setting.
  // This does not magically improve the router/ISP signal, but it gives
  // the ESP the strongest supported outgoing WiFi transmission.
  WiFi.setOutputPower(20.5f);

  // Let ESP8266 automatically recover from AP loss.
  WiFi.setAutoReconnect(true);

  // Do not repeatedly write credentials/settings to flash.
  WiFi.persistent(false);
}

// ------------------------------------------------------------
// NON-BLOCKING WIFI RECONNECT TRIGGER
// ------------------------------------------------------------

void requestWiFiReconnect() {
  unsigned long now = millis();

  if (WiFi.status() == WL_CONNECTED) {
    heartbeatWaitingForWiFi = false;
    return;
  }

  // Do not call WiFi.begin() repeatedly every few milliseconds.
  if (now - lastWiFiReconnectTriggerMs < WIFI_RECONNECT_RETRY_MS) {
    return;
  }

  lastWiFiReconnectTriggerMs = now;

  logLine("WIFI RECONNECT TRIGGER");

  configureWiFi();

  /*
    This starts/restarts the connection attempt but does NOT wait here.
    The loop remains free to run the electricity/current logic.
  */
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  heartbeatWaitingForWiFi = true;
}

// ------------------------------------------------------------
// INITIAL WIFI CONNECTION
// ------------------------------------------------------------

bool connectWiFiInitial() {
  configureWiFi();

  logLine("INITIAL WIFI CONNECTION START");

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  unsigned long started = millis();

  while (WiFi.status() != WL_CONNECTED &&
         millis() - started < INITIAL_WIFI_TIMEOUT_MS) {
    delay(100);
    yield();
  }

  if (WiFi.status() == WL_CONNECTED) {
    printWiFiState("WIFI CONNECTED: ");
    heartbeatWaitingForWiFi = false;
    return true;
  }

  logLine("INITIAL WIFI CONNECTION FAILED");
  printWiFiState("WIFI STATE: ");

  heartbeatWaitingForWiFi = true;
  return false;
}

// ------------------------------------------------------------
// ONE HTTP HEARTBEAT ATTEMPT
// ------------------------------------------------------------

bool sendHeartbeatAttempt() {
  unsigned long attemptStart = millis();

  printTimestamp();
  Serial.println("HEARTBEAT HTTP ATTEMPT START");

  if (WiFi.status() != WL_CONNECTED) {
    logLine("HTTP ATTEMPT SKIPPED: WIFI NOT CONNECTED");
    return false;
  }

  WiFiClientSecure client;

  // Same behavior as the original code.
  client.setInsecure();

  // Underlying secure client timeout.
  client.setTimeout(HTTP_TIMEOUT_MS);

  HTTPClient http;

  // Maximum wait for this HTTP attempt.
  http.setTimeout(HTTP_TIMEOUT_MS);

  if (!http.begin(client, CURRENTWATCH_API)) {
    apiReady = false;

    logLine("HTTP BEGIN FAILED");

    http.end();
    return false;
  }

  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-Device-Key", DEVICE_API_KEY);

  String body = "{\"device_id\":\"";
  body += DEVICE_ID;
  body += "\"}";

  logLine("HTTP POST START");

  int httpCode = http.POST(body);

  unsigned long duration = millis() - attemptStart;

  if (httpCode >= 200 && httpCode < 300) {
    apiReady = true;

    printTimestamp();
    Serial.print("HEARTBEAT SUCCESS: HTTP=");
    Serial.print(httpCode);
    Serial.print(" | HTTP_ATTEMPT=");
    Serial.print(duration);
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
  Serial.print("HEARTBEAT HTTP FAILED: HTTP=");
  Serial.print(httpCode);
  Serial.print(" | HTTP_ATTEMPT=");
  Serial.print(duration);
  Serial.println(" ms");

  if (httpCode > 0) {
    String response = http.getString();

    Serial.print("Response: ");
    Serial.println(response);
  } else {
    Serial.print("HTTP Error: ");
    Serial.println(http.errorToString(httpCode));
  }

  http.end();

  printWiFiState("AFTER FAILED HTTP: ");

  return false;
}

// ------------------------------------------------------------
// RELIABLE HEARTBEAT
// ------------------------------------------------------------

bool sendReliableHeartbeat() {
  heartbeatWaitingForWiFi = false;

  unsigned long cycleStart = millis();
  unsigned long attemptNumber = 0;

  while (true) {
    unsigned long now = millis();

    if (WiFi.status() != WL_CONNECTED) {
      apiReady = false;
      heartbeatWaitingForWiFi = true;

      requestWiFiReconnect();

      // Keep the retry loop alive without a blocking reconnect wait.
      delay(1);
      yield();
      continue;
    }

    heartbeatWaitingForWiFi = false;
    attemptNumber++;

    printTimestamp();
    Serial.print("HEARTBEAT REQUEST #");
    Serial.print(attemptNumber);
    Serial.print(" | ELAPSED=");
    Serial.print(millis() - cycleStart);
    Serial.println(" ms");

    if (sendHeartbeatAttempt()) {
      unsigned long total = millis() - cycleStart;

      printTimestamp();
      Serial.print("HEARTBEAT SUCCESS | TOTAL=");
      Serial.print(total);
      Serial.println(" ms");

      // Immediately start the next heartbeat cycle.
      heartbeatRunning = false;
      heartbeatWaitingForWiFi = false;
      return true;
    }

    apiReady = false;

    // NEVER stop after 5 seconds.
    // NEVER stop after a fixed number of attempts.
    // Keep requesting continuously for as long as necessary.
    if (WiFi.status() != WL_CONNECTED) {
      heartbeatWaitingForWiFi = true;
      requestWiFiReconnect();
    }

    yield();
  }
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

  // No retry count and no "one request per heartbeat cycle" limit.
  // Each cycle keeps requesting until a server response succeeds.
  sendReliableHeartbeat();
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
  Serial.println("CurrentWatch ESP8266");
  Serial.println("CURRENTWATCH CONTINUOUS HEARTBEAT");
  Serial.println("==============================================");

  printTimestamp();
  Serial.print("RESET REASON: ");
  Serial.println(ESP.getResetReason());

  printTimestamp();
  Serial.print("FREE HEAP: ");
  Serial.println(ESP.getFreeHeap());

  printTimestamp();
  Serial.print("HTTP ATTEMPT TIMEOUT: ");
  Serial.print(HTTP_TIMEOUT_MS);
  Serial.println(" ms");

  printTimestamp();
  Serial.print("SUCCESS TARGET: ");
  Serial.print(HEARTBEAT_SUCCESS_TARGET_MS);
  Serial.println(" ms");

  printTimestamp();
  Serial.print("WIFI RECONNECT TRIGGER: ");
  Serial.print(WIFI_RECONNECT_RETRY_MS);
  Serial.println(" ms");

  printTimestamp();
  Serial.print("HEARTBEAT INTERVAL: ");
  Serial.print(HEARTBEAT_INTERVAL_MS);
  Serial.println(" ms");

  if (connectWiFiInitial()) {
    sendReliableHeartbeat();
    lastHeartbeatMs = millis();
  } else {
    /*
      We do not give up after initial WiFi failure.
      The normal loop will continue trying.
    */
    requestWiFiReconnect();
  }
}

// ------------------------------------------------------------
// LOOP
// ------------------------------------------------------------

void loop() {
  currentWatchLoop();

  // KEEP YOUR EXISTING ELECTRICITY/CURRENT CODE HERE.
}
