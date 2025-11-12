import { runRealProfile } from "./runRealProfile.js";

/**
 * Launch Chrome Profile 1 - Concurrent Mode
 *
 * This script is designed to run alongside other profile launchers
 * without conflicts. Each launcher uses unique ports.
 *
 * Usage:
 *   node launch-profile-1.js
 *
 * To run multiple profiles simultaneously:
 *   Terminal 1: node launch-profile-1.js
 *   Terminal 2: node launch-profile-2.js
 *   Terminal 3: node launch-profile-3.js (create as needed)
 */

console.log("\n=== Launching Chrome Profile 1 (Concurrent Mode) ===\n");

const config = {
  // Profile configuration
  profileName: "Default", // Use 'Default' profile within this user data dir

  // IMPORTANT: Use separate User Data Directory for concurrent mode
  // This prevents Chrome from locking the entire user data directory
  userDataDir:
    process.platform === "darwin"
      ? `${process.env.HOME}/Library/Application Support/Google/Chrome-Profile1`
      : process.platform === "win32"
      ? `${process.env.LOCALAPPDATA}\\Google\\Chrome-Profile1\\User Data`
      : `${process.env.HOME}/.config/google-chrome-profile1`,

  // Proxy configuration
  proxy: "socks5://127.0.0.1:50836", // SOCKS5 proxy URL (port 50836 maps to SOCKS5 port 1080 in container)

  // URL to open on startup
  startUrl: "https://api.ipify.org",

  // IMPORTANT: Set to false for concurrent mode
  killExisting: false, // ✅ Do NOT kill other Chrome instances

  // IMPORTANT: Unique ports for this profile
  localProxyPort: 8888, // Local proxy relay port (unique)
  remoteDebuggingPort: 9222, // Remote debugging port (unique)

  // Additional Chrome arguments (optional)
  additionalArgs: [
    // Add custom args here if needed
    // '--start-maximized',
    // '--disable-notifications',
  ],
};

console.log("[CONFIG] Profile 1 Configuration:");
console.log(`   Profile Name: ${config.profileName}`);
console.log(`   Proxy: ${config.proxy}`);
console.log(`   Local Proxy Port: ${config.localProxyPort}`);
console.log(`   Remote Debug Port: ${config.remoteDebuggingPort}`);
console.log(
  `   Kill Existing: ${config.killExisting} (MUST be false for concurrent mode)`
);
console.log("");

// Warnings
if (config.killExisting) {
  console.warn("⚠️  WARNING: killExisting is true!");
  console.warn("⚠️  This will kill other Chrome instances!");
  console.warn("⚠️  Set to false for concurrent mode\n");
}

// Launch
runRealProfile(config).catch((error) => {
  console.error("\n[ERROR] Failed to launch Profile 1:");
  console.error(error.message);
  process.exit(1);
});
