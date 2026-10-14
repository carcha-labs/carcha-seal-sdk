'use strict';
// The napi-rs target name for this machine (the platform package suffix), or null when
// no prebuilt module exists for it. Shared by index.js (loading) and scripts/build.js.
function isMusl() {
  // glibc reports its version in the process report; musl does not.
  const report = typeof process.report?.getReport === 'function' ? process.report.getReport() : null;
  return !report?.header?.glibcVersionRuntime;
}

function target(platform = process.platform, arch = process.arch, musl = platform === 'linux' && isMusl()) {
  if (platform === 'darwin' && (arch === 'arm64' || arch === 'x64')) return `darwin-${arch}`;
  if (platform === 'win32' && arch === 'x64') return 'win32-x64-msvc';
  if (platform === 'linux' && arch === 'x64' && !musl) return 'linux-x64-gnu';
  return null;
}

module.exports = { target, TARGETS: ['darwin-arm64', 'darwin-x64', 'win32-x64-msvc', 'linux-x64-gnu'] };
