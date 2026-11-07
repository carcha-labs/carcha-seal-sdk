// An app that installs the packages: checks the native library it loaded and that the client runs.
// Usage: Consumer <native version> [<cpu folder the .NET Framework build must load from: x86, x64 or arm64>]
// C# 7.3, so the packages.config project (Legacy/) builds it with the compiler's default for .NET Framework.
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using CarchaLabs.Seal;

static class Program
{
    const string PublicKeys = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\n";

    static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.Error.WriteLine("usage: Consumer <native version> [x86|x64|arm64]");
            return 2;
        }
        int failures = 0;
        Action<bool, string> expect = (ok, what) =>
        {
            if (ok) return;
            failures++;
            Console.WriteLine("FAIL: " + what);
        };

        string version = SealClient.NativeVersion;
        string store = Path.Combine(Path.GetTempPath(), "carcha-seal-consumer-" + Guid.NewGuid().ToString("N"));
        LicenseStatus status;
        string userAgent;
        using (var seal = new SealClient(new SealOptions
        {
            Product = "studio",
            ServerUrl = "http://127.0.0.1:9",   // nothing answers: the check is offline, with no saved license
            PublicKeys = PublicKeys,
            StorageDirectory = store,
            Hardware = false,
            Timeout = TimeSpan.FromSeconds(2),
        }))
        {
            userAgent = seal.UserAgent;
            status = seal.CheckAsync().GetAwaiter().GetResult().Status;
        }
        string loaded = Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Select(m => m.FileName)
            .FirstOrDefault(f => f != null && Path.GetFileName(f).IndexOf("seal_native", StringComparison.OrdinalIgnoreCase) >= 0);

        Console.WriteLine("process: " + (IntPtr.Size * 8) + "-bit, PROCESSOR_ARCHITECTURE=" + Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE"));
        Console.WriteLine("native library: " + version + ", loaded from " + (loaded ?? "(not listed)"));
        Console.WriteLine("user agent: " + userAgent + ", status: " + status);

        expect(version == args[0], "native version " + version + ", want " + args[0]);
        expect(userAgent == "carcha-seal-native/" + args[0] + " (dotnet)", "user agent");
        expect(status == LicenseStatus.Unlicensed, "status " + status + ", want Unlicensed");
#if NETFRAMEWORK
        // The CarchaLabs.Seal.NetFramework build targets put a copy per CPU under carcha-seal\; the library must
        // have loaded one of them, the one for this process.
        string folder = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "carcha-seal");
        expect(loaded != null && loaded.StartsWith(folder, StringComparison.OrdinalIgnoreCase), "loaded from " + folder);
        if (args.Length > 1)
            expect(loaded != null && string.Equals(loaded, Path.Combine(folder, args[1], "seal_native.dll"), StringComparison.OrdinalIgnoreCase), "loaded the " + args[1] + " copy");
#endif
        try { Directory.Delete(store, true); } catch (IOException) { }
        Console.WriteLine(failures == 0 ? "OK" : failures + " failures");
        return failures == 0 ? 0 : 1;
    }
}
