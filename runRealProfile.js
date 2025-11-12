import { exec, spawn } from "child_process";
import { promisify } from "util";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";
import http from "http";
import net from "net";

const execAsync = promisify(exec);
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Global proxy relay server instance
let proxyRelayServer = null;

/**
 * CONCURRENT MODE USAGE:
 *
 * To run multiple Chrome profiles simultaneously, you MUST:
 * 1. Set killExisting: false (otherwise it kills other instances)
 * 2. Use unique remoteDebuggingPort for each instance (e.g., 9222, 9223, 9224)
 * 3. Use unique localProxyPort for each instance (e.g., 8888, 8889, 8890)
 * 4. Use different profileName for each instance (e.g., 'Profile 1', 'Profile 2')
 *
 * Example:
 *   Terminal 1: node launch-profile-1.js  (port 9222, proxy 8888)
 *   Terminal 2: node launch-profile-2.js  (port 9223, proxy 8889)
 *
 * See CONCURRENT-PROFILES.md for detailed guide.
 */

// Platform-specific Chrome paths
const CHROME_PATHS = {
  darwin: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  win32: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  linux: "/usr/bin/google-chrome",
};

// Platform-specific User Data paths
const USER_DATA_PATHS = {
  darwin: `${process.env.HOME}/Library/Application Support/Google/Chrome`,
  win32: `${process.env.LOCALAPPDATA}\\Google\\Chrome\\User Data`,
  linux: `${process.env.HOME}/.config/google-chrome`,
};

/**
 * Parse proxy string in format: "socks5://host:port" or "host:port:username:password"
 * @param {string} proxyString - Proxy string to parse
 * @returns {Object} Parsed proxy configuration
 */
function parseProxyString(proxyString) {
  if (!proxyString) {
    return null;
  }

  // Check if it's a SOCKS5 URL
  if (proxyString.startsWith("socks5://")) {
    try {
      const url = new URL(proxyString);
      return {
        type: "socks5",
        host: url.hostname,
        port: url.port || "1080",
        server: `${url.hostname}:${url.port || "1080"}`,
        url: proxyString,
        hasAuth: !!(url.username && url.password),
        username: url.username || null,
        password: url.password || null,
      };
    } catch (error) {
      throw new Error(
        `Invalid SOCKS5 URL format: ${proxyString}. Expected: socks5://host:port`
      );
    }
  }

  // Legacy format: host:port:username:password
  const parts = proxyString.split(":");

  if (parts.length < 2) {
    throw new Error(
      "Invalid proxy format. Expected: socks5://host:port or host:port:username:password"
    );
  }

  return {
    type: "http",
    host: parts[0],
    port: parts[1],
    username: parts[2] || null,
    password: parts[3] || null,
    server: `${parts[0]}:${parts[1]}`,
    hasAuth: !!(parts[2] && parts[3]),
  };
}

/**
 * Mask password for logging
 * @param {string} password - Password to mask
 * @returns {string} Masked password
 */
function maskPassword(password) {
  if (!password || password.length === 0) return "";
  if (password.length <= 2) return "*".repeat(password.length);
  return (
    password[0] +
    "*".repeat(password.length - 2) +
    password[password.length - 1]
  );
}

/**
 * Check if Chrome is running
 * @returns {Promise<boolean>}
 */
async function isChromeRunning() {
  const platform = process.platform;

  try {
    if (platform === "darwin") {
      const { stdout } = await execAsync('pgrep -f "Google Chrome"');
      return stdout.trim().length > 0;
    } else if (platform === "win32") {
      const { stdout } = await execAsync("tasklist | findstr chrome.exe");
      return stdout.trim().length > 0;
    } else {
      const { stdout } = await execAsync("pgrep chrome");
      return stdout.trim().length > 0;
    }
  } catch (error) {
    // If pgrep/tasklist finds nothing, it exits with error code
    return false;
  }
}

/**
 * Kill all Chrome processes
 * @returns {Promise<void>}
 */
async function killChrome() {
  const platform = process.platform;

  try {
    if (platform === "darwin") {
      await execAsync('pkill -f "Google Chrome"');
    } else if (platform === "win32") {
      await execAsync("taskkill /F /IM chrome.exe /T");
    } else {
      await execAsync("pkill chrome");
    }

    // Active polling to verify Chrome processes are terminated
    console.log("[*] Waiting for Chrome processes to terminate...");
    let attempts = 0;
    const maxAttempts = 10; // Max 5 seconds (10 * 500ms)

    while (attempts < maxAttempts) {
      await new Promise((resolve) => setTimeout(resolve, 500));

      // Check if Chrome processes still exist
      try {
        let checkCmd;
        if (platform === "darwin") {
          checkCmd = 'pgrep -f "Google Chrome"';
        } else if (platform === "win32") {
          checkCmd = 'tasklist /FI "IMAGENAME eq chrome.exe" /NH';
        } else {
          checkCmd = "pgrep chrome";
        }

        await execAsync(checkCmd);

        // If we get here, processes still exist
        attempts++;
        if (attempts % 2 === 0) {
          console.log(`[*] Still waiting... (${attempts * 0.5}s)`);
        }
      } catch (error) {
        // pgrep/tasklist returns error if no processes found - means we're done!
        console.log(
          `[OK] Chrome processes terminated (${(attempts + 1) * 0.5}s)`
        );
        return;
      }
    }

    // If we reach here, Chrome may still be running but we've waited long enough
    console.log("[OK] Chrome shutdown timeout reached (5s)");
  } catch (error) {
    // May throw if no processes found, which is fine
    console.log("[INFO] No Chrome processes to kill");
  }
}

/**
 * List available Chrome profiles
 * @param {string} userDataDir - Path to Chrome User Data directory
 * @returns {Promise<string[]>}
 */
async function listProfiles(userDataDir) {
  try {
    const entries = await fs.promises.readdir(userDataDir, {
      withFileTypes: true,
    });
    const profiles = entries
      .filter((entry) => entry.isDirectory())
      .filter(
        (dir) => dir.name === "Default" || dir.name.startsWith("Profile ")
      )
      .map((dir) => dir.name);

    return profiles;
  } catch (error) {
    throw new Error(`Failed to read User Data directory: ${error.message}`);
  }
}

/**
 * Backup Preferences file
 * @param {string} prefsPath - Path to Preferences file
 * @returns {Promise<string>} Backup file path
 */
async function backupPreferences(prefsPath) {
  // Check if Preferences file exists first
  try {
    await fs.promises.access(prefsPath, fs.constants.F_OK);
  } catch (error) {
    // File doesn't exist - skip backup (this is a new profile)
    console.log("[INFO] No existing Preferences file to backup (new profile)");
    return null;
  }

  const timestamp = Date.now();
  const backupPath = `${prefsPath}.backup.${timestamp}`;

  try {
    await fs.promises.copyFile(prefsPath, backupPath);
    console.log(`[BACKUP] Created: ${path.basename(backupPath)}`);
    return backupPath;
  } catch (error) {
    throw new Error(`Failed to create backup: ${error.message}`);
  }
}

/**
 * Clean up old backups (keep only last 3)
 * @param {string} profileDir - Profile directory path
 */
async function cleanupOldBackups(profileDir) {
  try {
    const entries = await fs.promises.readdir(profileDir);
    const backups = entries
      .filter((name) => name.startsWith("Preferences.backup."))
      .sort()
      .reverse();

    // Keep only last 3 backups
    for (let i = 3; i < backups.length; i++) {
      const backupPath = path.join(profileDir, backups[i]);
      await fs.promises.unlink(backupPath);
      console.log(`[CLEANUP] Removed old backup: ${backups[i]}`);
    }
  } catch (error) {
    console.log("[WARN] Could not clean up old backups:", error.message);
  }
}

/**
 * Update Chrome Preferences file with proxy configuration
 * @param {string} prefsPath - Path to Preferences file
 * @param {Object} proxyConfig - Proxy configuration
 */
async function updatePreferences(prefsPath, proxyConfig) {
  try {
    let prefs = {};

    // Try to read existing preferences
    try {
      const prefsData = await fs.promises.readFile(prefsPath, "utf8");
      prefs = JSON.parse(prefsData);
    } catch (error) {
      // File doesn't exist - create new preferences object
      console.log("[INFO] Creating new Preferences file");
      prefs = {};
    }

    // Update proxy settings
    if (!prefs.proxy) {
      prefs.proxy = {};
    }

    prefs.proxy = {
      mode: "fixed_servers",
      server: `http://${proxyConfig.server}`,
    };

    // Ensure profile directory exists
    const profileDir = path.dirname(prefsPath);
    await fs.promises.mkdir(profileDir, { recursive: true });

    // Write preferences file
    await fs.promises.writeFile(prefsPath, JSON.stringify(prefs, null, 3));
    console.log(`[CONFIG] Proxy configured: ${proxyConfig.server}`);

    return true;
  } catch (error) {
    throw new Error(`Failed to update Preferences: ${error.message}`);
  }
}

/**
 * Validate configuration
 * @param {Object} config - Configuration object
 * @returns {Promise<Object>} Validation result
 */
async function validateConfig(config) {
  const result = {
    valid: true,
    errors: [],
    warnings: [],
    chromePath: config.chromePath,
    userDataDir: config.userDataDir,
    profileName: config.profileName,
  };

  // Check Chrome executable
  try {
    await fs.promises.access(
      result.chromePath,
      fs.constants.F_OK | fs.constants.X_OK
    );
    console.log("[OK] Chrome executable found");
  } catch (error) {
    result.valid = false;
    result.errors.push(`Chrome executable not found at: ${result.chromePath}`);
    return result;
  }

  // Check User Data directory (create if not exists)
  try {
    await fs.promises.access(result.userDataDir, fs.constants.F_OK);
    console.log("[OK] User Data directory found");
  } catch (error) {
    // Directory doesn't exist - create it
    try {
      console.log(
        `[INFO] User Data directory not found, creating: ${result.userDataDir}`
      );
      await fs.promises.mkdir(result.userDataDir, { recursive: true });
      console.log("[OK] User Data directory created");
    } catch (createError) {
      result.valid = false;
      result.errors.push(
        `Failed to create User Data directory at: ${result.userDataDir} - ${createError.message}`
      );
      return result;
    }
  }

  // Check profile (allow Chrome to create if not exists for new User Data directories)
  const profilePath = path.join(result.userDataDir, result.profileName);
  try {
    await fs.promises.access(profilePath, fs.constants.F_OK);
    console.log(`[OK] Profile "${result.profileName}" found`);
  } catch (error) {
    // Profile doesn't exist
    // For 'Default' profile in a new User Data directory, Chrome will create it automatically
    if (result.profileName === "Default") {
      console.log(
        `[INFO] Profile "Default" will be created automatically by Chrome`
      );
    } else {
      // For non-Default profiles, list available profiles
      try {
        const availableProfiles = await listProfiles(result.userDataDir);
        if (availableProfiles.length > 0) {
          result.valid = false;
          result.errors.push(`Profile "${result.profileName}" not found`);
          result.availableProfiles = availableProfiles;
          return result;
        } else {
          // No profiles exist yet - Chrome will create Default
          console.log(
            `[INFO] No profiles exist yet, Chrome will create "${result.profileName}"`
          );
        }
      } catch (listError) {
        // Can't list profiles (directory might be empty) - let Chrome create the profile
        console.log(
          `[INFO] Profile "${result.profileName}" will be created automatically by Chrome`
        );
      }
    }
  }

  return result;
}

/**
 * Test proxy connectivity
 * @param {Object} proxyConfig - Proxy configuration
 * @returns {Promise<boolean>}
 */
async function testProxyConnectivity(proxyConfig) {
  try {
    const { default: axios } = await import("axios");
    const proxyUrl = proxyConfig.hasAuth
      ? `http://${proxyConfig.username}:${proxyConfig.password}@${proxyConfig.server}`
      : `http://${proxyConfig.server}`;

    const response = await axios.get("https://api.ipify.org?format=json", {
      proxy: false,
      httpsAgent: proxyUrl,
      timeout: 5000,
    });

    console.log(`[OK] Proxy is reachable (IP: ${response.data.ip})`);
    return true;
  } catch (error) {
    console.log(`[WARN] Proxy health check failed: ${error.message}`);
    return false;
  }
}

/**
 * Create Basic Auth header for proxy
 * @param {string} username - Proxy username
 * @param {string} password - Proxy password
 * @returns {string} Basic auth header
 */
function createAuthHeader(username, password) {
  const credentials = `${username}:${password}`;
  const encoded = Buffer.from(credentials).toString("base64");
  return `Basic ${encoded}`;
}

/**
 * Connect to remote proxy with authentication
 * @param {string} host - Target host
 * @param {string} port - Target port
 * @param {Object} proxyConfig - Proxy configuration
 * @param {Function} callback - Callback function
 * @returns {net.Socket}
 */
function connectToRemoteProxy(host, port, proxyConfig, callback) {
  const authHeader = createAuthHeader(
    proxyConfig.username,
    proxyConfig.password
  );

  const socket = net.connect(proxyConfig.port, proxyConfig.host, () => {
    // Send CONNECT request with auth
    const connectRequest = [
      `CONNECT ${host}:${port} HTTP/1.1`,
      `Host: ${host}:${port}`,
      `Proxy-Authorization: ${authHeader}`,
      `Proxy-Connection: Keep-Alive`,
      "",
      "",
    ].join("\r\n");

    socket.write(connectRequest);
    callback(null, socket);
  });

  socket.on("error", (err) => {
    console.error(`[Relay] Remote proxy error:`, err.message);
    callback(err);
  });

  return socket;
}

/**
 * Start local proxy relay server
 * @param {number} localPort - Local port to listen on
 * @param {Object} remoteProxyConfig - Remote proxy configuration
 * @returns {Promise<http.Server>}
 */
async function startProxyRelayServer(localPort, remoteProxyConfig) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      // Handle HTTP requests
      const options = {
        host: remoteProxyConfig.host,
        port: remoteProxyConfig.port,
        path: req.url,
        method: req.method,
        headers: {
          ...req.headers,
          "Proxy-Authorization": createAuthHeader(
            remoteProxyConfig.username,
            remoteProxyConfig.password
          ),
        },
      };

      const proxyReq = http.request(options, (proxyRes) => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
      });

      proxyReq.on("error", (err) => {
        console.error(`[Relay] Proxy request error:`, err.message);
        res.writeHead(500);
        res.end("Proxy Error");
      });

      req.pipe(proxyReq);
    });

    // Handle CONNECT method (for HTTPS)
    server.on("connect", (req, clientSocket, head) => {
      const [host, port] = req.url.split(":");

      // Connect to remote proxy
      connectToRemoteProxy(
        host,
        port,
        remoteProxyConfig,
        (err, proxySocket) => {
          if (err) {
            clientSocket.write("HTTP/1.1 500 Connection Error\r\n\r\n");
            clientSocket.end();
            return;
          }

          // Wait for remote proxy response
          proxySocket.once("data", (data) => {
            const response = data.toString();

            if (response.includes("200")) {
              // Success! Tell client connection established
              clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");

              // Pipe data between client and proxy
              clientSocket.pipe(proxySocket);
              proxySocket.pipe(clientSocket);
            } else {
              console.error(`[Relay] Remote proxy rejected:`, response.trim());
              clientSocket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
              clientSocket.end();
            }
          });

          // Handle errors
          clientSocket.on("error", (err) => {
            proxySocket.end();
          });

          proxySocket.on("error", (err) => {
            clientSocket.end();
          });
        }
      );
    });

    // Start server
    server.listen(localPort, () => {
      console.log(
        `[RELAY] Proxy relay server started on localhost:${localPort}`
      );
      console.log(
        `[RELAY] Forwarding to ${remoteProxyConfig.host}:${remoteProxyConfig.port}`
      );
      resolve(server);
    });

    server.on("error", (err) => {
      if (err.code === "EADDRINUSE") {
        console.log(
          `[WARN] Port ${localPort} already in use, assuming relay is running`
        );
        resolve(null); // Return null to indicate we should use existing server
      } else {
        reject(err);
      }
    });
  });
}

/**
 * Stop proxy relay server
 * @param {http.Server} server - Server instance to stop
 */
function stopProxyRelayServer(server) {
  if (server) {
    return new Promise((resolve) => {
      server.close(() => {
        console.log("[RELAY] Proxy relay server stopped");
        resolve();
      });
    });
  }
  return Promise.resolve();
}

// REMOVED: createProxyAuthExtension() function
// Reason: Manifest V2 is deprecated, Chrome extension mode is unreliable
// Use Proxy Relay Mode instead (see startProxyRelayServer)

/**
 * Launch Chrome with profile and proxy
 * @param {Object} options - Launch options
 * @returns {Promise<ChildProcess>}
 */
async function launchChrome(options) {
  const {
    chromePath,
    userDataDir,
    profileName,
    proxyConfig,
    startUrl = "https://api.ipify.org",
    additionalArgs = [],
    localProxyPort = 8888, // Local proxy relay port
    remoteDebuggingPort = null, // Fixed remote debugging port
  } = options;

  // Build Chrome arguments
  const args = [
    `--user-data-dir=${userDataDir}`,
    `--profile-directory=${profileName}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--start-maximized",
    "--disable-popup-blocking",
    "--disable-notifications",
    "--disable-infobars",
  ];

  // Add remote debugging port if specified
  if (remoteDebuggingPort) {
    args.push(`--remote-debugging-port=${remoteDebuggingPort}`);
    console.log(
      `[DEBUG] Remote debugging enabled on port ${remoteDebuggingPort}`
    );
  }

  // Add proxy if configured
  if (proxyConfig) {
    if (proxyConfig.type === "socks5") {
      // ✅ SOCKS5 PROXY - Direct connection (no relay needed)
      console.log("\n[PROXY] Using SOCKS5 Proxy Mode");
      args.push(`--proxy-server=${proxyConfig.url}`);
      console.log(`   SOCKS5 Proxy: ${proxyConfig.url}`);
      if (proxyConfig.hasAuth) {
        console.log(`   Username: ${proxyConfig.username}`);
        console.log(`   Password: ${maskPassword(proxyConfig.password)}`);
      }
      console.log("   ✅ Direct SOCKS5 connection\n");
    } else if (proxyConfig.hasAuth) {
      // ✅ PROXY RELAY MODE - Transparent authentication
      console.log("\n[PROXY] Using Proxy Relay Mode");
      args.push(`--proxy-server=localhost:${localProxyPort}`);
      console.log(`   Local Proxy: localhost:${localProxyPort}`);
      console.log(`   Remote Proxy: ${proxyConfig.server}`);
      console.log(`   Username: ${proxyConfig.username}`);
      console.log(`   Password: ${maskPassword(proxyConfig.password)}`);
      console.log(
        `   ✅ Authentication handled automatically by relay server\n`
      );
    } else {
      // No auth proxy - direct connection
      console.log("\n[PROXY] Using direct proxy (no authentication)");
      args.push(`--proxy-server=${proxyConfig.server}`);
      console.log(`   Proxy: ${proxyConfig.server}\n`);
    }
  }

  // Add additional args
  args.push(...additionalArgs);

  // Add start URL
  args.push(startUrl);

  console.log("\n[LAUNCH] Starting Chrome...");
  console.log(`[USER DATA] ${userDataDir}`);
  console.log(`[PROFILE] ${profileName}`);
  console.log(
    `[CMD] "${chromePath}" --user-data-dir="${userDataDir}" --profile-directory="${profileName}" [${
      args.length - 2
    } args] ${startUrl}\n`
  );

  // Spawn Chrome process
  const chromeProcess = spawn(chromePath, args, {
    detached: true,
    stdio: "ignore",
  });

  chromeProcess.unref();

  return chromeProcess;
}

/**
 * Main function to run Chrome profile with proxy
 * @param {Object} config - Configuration
 */
export async function runRealProfile(config = {}) {
  const platform = process.platform;

  // Default configuration
  const defaultConfig = {
    chromePath: CHROME_PATHS[platform],
    userDataDir: USER_DATA_PATHS[platform],
    profileName: "Default",
    proxy: null, // Format: "host:port:username:password"
    startUrl: "https://api.ipify.org",
    killExisting: true,
    testProxy: false,
    additionalArgs: [],
    localProxyPort: 8888, // Local proxy relay port (for authenticated proxies)
    remoteDebuggingPort: null, // Fixed remote debugging port (e.g., 9222)
  };

  const finalConfig = { ...defaultConfig, ...config };

  console.log("\n========================================");
  console.log("Chrome Profile Launcher with Proxy");
  console.log("========================================\n");

  // Display input
  console.log("[CONFIG] Input Configuration:");
  console.log(`   Chrome Path: ${finalConfig.chromePath}`);
  console.log(`   User Data: ${finalConfig.userDataDir}`);
  console.log(`   Profile: ${finalConfig.profileName}`);
  if (finalConfig.proxy) {
    const proxyConfig = parseProxyString(finalConfig.proxy);
    console.log(
      `   Proxy: ${
        proxyConfig.type === "socks5" ? proxyConfig.url : proxyConfig.server
      }`
    );
    if (proxyConfig.type === "socks5") {
      console.log(`   Proxy Mode: SOCKS5`);
      if (proxyConfig.hasAuth) {
        console.log(`   Proxy User: ${proxyConfig.username}`);
        console.log(`   Proxy Pass: ${maskPassword(proxyConfig.password)}`);
      }
    } else if (proxyConfig.hasAuth) {
      console.log(`   Proxy User: ${proxyConfig.username}`);
      console.log(`   Proxy Pass: ${maskPassword(proxyConfig.password)}`);
      console.log(`   Proxy Mode: Relay`);
    }
  } else {
    console.log("   Proxy: None");
  }
  if (finalConfig.remoteDebuggingPort) {
    console.log(`   Debug Port: ${finalConfig.remoteDebuggingPort}`);
  }
  console.log(`   Start URL: ${finalConfig.startUrl}\n`);

  // Step 1: Validate configuration
  console.log("[STEP 1] Validating configuration...");
  const validation = await validateConfig(finalConfig);

  if (!validation.valid) {
    console.error("\n[ERROR] Configuration validation failed\n");
    validation.errors.forEach((err) => console.error(`   [X] ${err}`));

    if (validation.availableProfiles) {
      console.log("\n[INFO] Available profiles:");
      validation.availableProfiles.forEach((p) => console.log(`   - ${p}`));
      console.log(
        "\n[SOLUTION] Update profileName to one of the profiles above\n"
      );
    }

    return { success: false, errors: validation.errors };
  }

  // Step 2: Parse proxy configuration
  let proxyConfig = null;
  if (finalConfig.proxy) {
    try {
      proxyConfig = parseProxyString(finalConfig.proxy);
      console.log(`[OK] Proxy parsed: ${proxyConfig.server}`);

      // Optional: Test proxy connectivity
      if (finalConfig.testProxy) {
        await testProxyConnectivity(proxyConfig);
      }

      // Step 2.1: Start proxy relay server for authenticated HTTP proxy
      if (proxyConfig.type === "socks5") {
        console.log("\n[STEP 2.1] Using SOCKS5 proxy (no relay needed)");
        console.log(`[OK] SOCKS5 proxy configured: ${proxyConfig.url}`);
      } else if (proxyConfig.hasAuth) {
        console.log("\n[STEP 2.1] Starting Proxy Relay Server...");
        try {
          proxyRelayServer = await startProxyRelayServer(
            finalConfig.localProxyPort,
            proxyConfig
          );

          // Wait a bit for server to be ready
          await new Promise((resolve) => setTimeout(resolve, 1000));

          if (proxyRelayServer) {
            console.log("[OK] Proxy relay server is ready!");
          } else {
            console.log("[OK] Using existing proxy relay server");
          }
        } catch (error) {
          console.error(
            `\n[ERROR] Failed to start proxy relay: ${error.message}\n`
          );
          return { success: false, errors: [error.message] };
        }
      }
    } catch (error) {
      console.error(`\n[ERROR] ${error.message}\n`);
      return { success: false, errors: [error.message] };
    }
  }

  // Step 3: Check if Chrome is running
  console.log("\n[STEP 2] Checking Chrome processes...");
  const isRunning = await isChromeRunning();

  if (isRunning && finalConfig.killExisting) {
    console.log("[WARN] Chrome is running, terminating...");
    await killChrome();
    console.log("[OK] Chrome is not running");
  } else if (isRunning && !finalConfig.killExisting) {
    console.log("[WARN] Chrome is running. Proxy changes may not take effect.");
    console.log("[INFO] Consider setting killExisting: true");
  } else {
    console.log("[OK] Chrome is not running");
  }

  // Step 4: Update Preferences if HTTP proxy is configured (SOCKS5 uses Chrome args directly)
  if (proxyConfig && proxyConfig.type === "http") {
    const profilePath = path.join(
      finalConfig.userDataDir,
      finalConfig.profileName
    );
    const prefsPath = path.join(profilePath, "Preferences");

    try {
      // Backup current preferences
      console.log("\n[STEP 3] Managing Preferences file...");
      await backupPreferences(prefsPath);

      // Update preferences
      console.log("[CONFIG] Updating proxy in Preferences...");
      await updatePreferences(prefsPath, proxyConfig);

      // Cleanup old backups
      await cleanupOldBackups(profilePath);
    } catch (error) {
      console.error(`\n[ERROR] ${error.message}\n`);
      return { success: false, errors: [error.message] };
    }
  } else if (proxyConfig && proxyConfig.type === "socks5") {
    console.log(
      "\n[STEP 3] SOCKS5 proxy configured (no Preferences update needed)"
    );
    console.log(
      "[INFO] SOCKS5 proxy will be used via Chrome command-line argument"
    );
  }

  // Step 5: Launch Chrome
  try {
    const chromeProcess = await launchChrome({
      chromePath: finalConfig.chromePath,
      userDataDir: finalConfig.userDataDir,
      profileName: finalConfig.profileName,
      proxyConfig,
      startUrl: finalConfig.startUrl,
      additionalArgs: finalConfig.additionalArgs,
      localProxyPort: finalConfig.localProxyPort,
      remoteDebuggingPort: finalConfig.remoteDebuggingPort,
    });

    console.log("[SUCCESS] Chrome launched successfully!\n");

    // Success output
    console.log("========================================");
    console.log("Status: SUCCESS");
    console.log("========================================\n");
    console.log("[NEXT STEPS]");
    console.log("   1. Check if IP matches proxy server at the opened page");

    if (proxyConfig && proxyConfig.hasAuth && proxyConfig.type === "http") {
      console.log(
        "   2. ✅ NO AUTHENTICATION POPUP - Relay handles it automatically!"
      );
    } else if (proxyConfig && proxyConfig.type === "socks5") {
      console.log("   2. ✅ SOCKS5 proxy is configured and ready!");
    }

    console.log("   3. Verify websites load correctly\n");

    if (proxyConfig) {
      console.log("[NOTES]");
      console.log("   - Preferences backup saved in profile directory");

      if (proxyConfig.hasAuth && proxyConfig.type === "http") {
        console.log("   - Proxy relay server is running in background");
        console.log("   - Chrome connects to localhost without authentication");
        console.log("   - Relay server forwards requests to remote proxy");
      } else if (proxyConfig.type === "socks5") {
        console.log("   - SOCKS5 proxy configured directly");
        console.log(`   - Chrome connects to: ${proxyConfig.url}`);
      }

      if (finalConfig.remoteDebuggingPort) {
        console.log(
          `   - Remote debugging available at: http://localhost:${finalConfig.remoteDebuggingPort}`
        );
      }

      console.log("   - To stop Chrome:");
      console.log('     macOS/Linux: pkill -f "Google Chrome"');
      console.log("     Windows: taskkill /F /IM chrome.exe");

      if (proxyRelayServer) {
        console.log(
          "   - Proxy relay server will auto-stop when script exits\n"
        );
      }
    }

    return {
      success: true,
      process: chromeProcess,
      config: finalConfig,
      proxyConfig,
      relayServer: proxyRelayServer,
    };
  } catch (error) {
    console.error("\n[ERROR] Failed to launch Chrome\n");
    console.error(`   ${error.message}\n`);

    // Cleanup relay server if it was started
    if (proxyRelayServer) {
      await stopProxyRelayServer(proxyRelayServer);
    }

    return { success: false, errors: [error.message] };
  }
}

// Auto-run if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  // Example: Run with authenticated proxy using PROXY RELAY
  const config = {
    profileName: "Profile 1", // Change to your profile: Default, Profile 1, Profile 2, etc.
    proxy: "sunday.mikproxy.online:3131:9U1QUC:sday", // Change to your proxy or set to null
    startUrl: "https://api.ipify.org",
    killExisting: true,
    localProxyPort: 8888,
    remoteDebuggingPort: 9222, // Fixed port for browser automation
  };

  console.log("\n[INFO] Running with config:", {
    profileName: config.profileName,
    proxy: config.proxy
      ? config.proxy.split(":").slice(0, 2).join(":")
      : "None",
    startUrl: config.startUrl,
    proxyMode: "Relay (Automatic Auth)",
    debugPort: config.remoteDebuggingPort || "None",
  });

  // Handle cleanup on exit
  process.on("SIGINT", async () => {
    console.log("\n\n[CLEANUP] Ctrl+C detected - Shutting down...");

    // Kill Chrome immediately (force kill for fast exit)
    console.log("[CLEANUP] Killing Chrome processes...");
    const platform = process.platform;
    try {
      if (platform === "darwin") {
        // Use SIGKILL (-9) for immediate termination on macOS
        await execAsync('pkill -9 -f "Google Chrome"');
      } else if (platform === "win32") {
        // /F = force terminate on Windows
        await execAsync("taskkill /F /IM chrome.exe /T");
      } else {
        // Use SIGKILL (-9) for immediate termination on Linux
        await execAsync("pkill -9 chrome");
      }
      console.log("[CLEANUP] Chrome killed");
    } catch (error) {
      // No Chrome running - that's fine
    }

    // Stop proxy relay server
    if (proxyRelayServer) {
      console.log("[CLEANUP] Stopping proxy relay...");
      await stopProxyRelayServer(proxyRelayServer);
    }

    console.log("[CLEANUP] Done!\n");
    process.exit(0);
  });

  process.on("SIGTERM", async () => {
    console.log("\n\n[CLEANUP] SIGTERM detected - Shutting down...");

    // Kill Chrome immediately (force kill for fast exit)
    console.log("[CLEANUP] Killing Chrome processes...");
    const platform = process.platform;
    try {
      if (platform === "darwin") {
        await execAsync('pkill -9 -f "Google Chrome"');
      } else if (platform === "win32") {
        await execAsync("taskkill /F /IM chrome.exe /T");
      } else {
        await execAsync("pkill -9 chrome");
      }
      console.log("[CLEANUP] Chrome killed");
    } catch (error) {
      // No Chrome running - that's fine
    }

    // Stop proxy relay server
    if (proxyRelayServer) {
      console.log("[CLEANUP] Stopping proxy relay...");
      await stopProxyRelayServer(proxyRelayServer);
    }

    console.log("[CLEANUP] Done!\n");
    process.exit(0);
  });

  runRealProfile(config).catch(async (error) => {
    console.error(error);
    if (proxyRelayServer) {
      await stopProxyRelayServer(proxyRelayServer);
    }
    process.exit(1);
  });
}
