#if NETFRAMEWORK
// .NET Framework does not pick native files from a package's runtimes/ folder: the CarchaLabs.Seal.NetFramework
// package's build targets copy seal_native.dll for each CPU to carcha-seal\{x86,x64,arm64}\ next to the app
// (Microsoft, "Native files in .NET packages"), and this loads the one that matches the process before the first
// call into it. Once loaded, DllImport("seal_native") binds to that module.
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace CarchaLabs.Seal
{
    internal static class NetFrameworkLoader
    {
        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibraryW(string path);

        /// <summary>
        /// The process's CPU: a 32-bit process is x86; a 64-bit one is ARM64 when the process itself runs as ARM64
        /// (PROCESSOR_ARCHITECTURE is set per process, so an x64 app emulated on ARM64 reads AMD64), otherwise x64.
        /// </summary>
        internal static string ProcessCpu()
        {
            if (IntPtr.Size == 4) return "x86";
            string arch = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE") ?? "";
            return string.Equals(arch, "ARM64", StringComparison.OrdinalIgnoreCase) ? "arm64" : "x64";
        }

        internal static void Load()
        {
            string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "carcha-seal", ProcessCpu(), Native.Library + ".dll");
            // Without the folder (the native file placed next to the app some other way), the normal DLL search applies.
            if (!File.Exists(path)) return;
            if (LoadLibraryW(path) == IntPtr.Zero)
                throw new DllNotFoundException("Carcha Seal: " + path + " could not be loaded (error " + Marshal.GetLastWin32Error() + ").");
        }
    }
}
#endif
