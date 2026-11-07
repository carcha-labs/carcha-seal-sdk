// Every client scenario recorded from the Electron SDK (packages/client/tests/vectors.json) through the C# SDK:
// the requests it sends (path and JSON body) and what it returns or throws, step by step, with license.dat in a
// folder. Compiled twice: against the net10.0 build (LibraryImport) and the netstandard2.0 build (DllImport).
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using CarchaLabs.Seal;
using Xunit;

namespace CarchaLabs.Seal.Tests;

public class ScenarioTests
{
    private const string Server = "https://seal.example.com";

    private static JsonObject Vectors() => JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "vectors.json")))!.AsObject();

    private static string Iso(DateTimeOffset? d) => d!.Value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    /// <summary>The state as the recorded LicenseState JSON.</summary>
    private static JsonObject StateJson(LicenseState s)
    {
        var o = new JsonObject
        {
            ["status"] = s.Status switch
            {
                LicenseStatus.Valid => "valid",
                LicenseStatus.Grace => "grace",
                LicenseStatus.Invalid => "invalid",
                LicenseStatus.Unlicensed => "unlicensed",
                _ => "clock_suspect",
            },
            ["offline"] = s.Offline,
            ["storageProtected"] = s.StorageProtected,
            ["features"] = new JsonArray(s.Features.Select(f => (JsonNode)JsonValue.Create(f)!).ToArray()),
            ["expiresAt"] = s.ExpiresAt.HasValue ? Iso(s.ExpiresAt) : null,
        };
        void Put(string name, string? value)
        {
            if (value != null) o[name] = value;
        }
        Put("reason", s.Reason);
        Put("message", s.Message);
        Put("customer", s.Customer);
        Put("keyHint", s.KeyHint);
        if (s.RevalidateBy.HasValue) o["revalidateBy"] = Iso(s.RevalidateBy);
        if (s.MaintenanceUntil.HasValue) o["maintenanceUntil"] = Iso(s.MaintenanceUntil);
        if (s.NoticesJson != null) o["notices"] = JsonNode.Parse(s.NoticesJson);
        if (s.OfflineActivated) o["offlineActivated"] = true;
        Assert.Equal(s.Status == LicenseStatus.Valid || s.Status == LicenseStatus.Grace, s.IsUsable);
        foreach (var f in s.Features) Assert.Equal(s.IsUsable, s.HasFeature(f));
        return o;
    }

    /// <summary>
    /// The recorded result as the C# SDK can show it: a lease state's "maintenanceUntil": null (no maintenance date)
    /// and an absent one both read as MaintenanceUntil == null.
    /// </summary>
    private static JsonNode? Normalize(JsonNode? outcome)
    {
        var copy = outcome?.DeepClone();
        if (copy?["result"]?["value"] is JsonObject v && v.ContainsKey("maintenanceUntil") && v["maintenanceUntil"] is null) v.Remove("maintenanceUntil");
        return copy;
    }

    private static string Platform() =>
        OperatingSystem.IsWindows() ? "win32" : OperatingSystem.IsMacOS() ? "darwin" : "linux";

    /// <summary>As the recorder's placeholders(): the SDK version and platform this build sends.</summary>
    private static JsonNode? Placeholders(JsonNode? body)
    {
        if (body is not JsonObject o) return body;
        if (o.ContainsKey("sdkVersion"))
        {
            Assert.Equal(SealClient.NativeVersion, (string?)o["sdkVersion"]);
            o["sdkVersion"] = "<sdk-version>";
        }
        if (o.ContainsKey("platform"))
        {
            Assert.Equal(Platform(), (string?)o["platform"]);
            o["platform"] = "<platform>";
        }
        if (o["activation"] is JsonObject a) Placeholders(a);
        return o;
    }

    [Fact]
    public async Task Every_client_scenario_matches_the_electron_sdk()
    {
        var vectors = Vectors();
        string root = Path.Combine(Path.GetTempPath(), "seal-dotnet-" + Guid.NewGuid().ToString("N"));
        int steps = 0;
        var failures = new List<string>();
        try
        {
            int n = 0;
            foreach (var scenario in vectors["scenarios"]!.AsArray())
            {
                string name = (string)scenario!["name"]!;
                // The machine id cannot be made unreadable through the options; covered in packages/client.
                if (scenario["machineId"] is null) continue;
                var o = scenario["options"]!;
                var requests = new JsonArray();
                JsonNode? scripted = null;
                long nowMs = 0;
                var options = new SealOptions
                {
                    Product = (string)o["product"]!,
                    ServerUrl = Server,
                    PublicKeys = string.Concat(o["publicKey"]!.AsArray().Select(k => (string)k!)),
                    StorageDirectory = Path.Combine(root, (n++).ToString(CultureInfo.InvariantCulture)),
                    AppVersion = (string?)o["appVersion"],
                    GraceDays = (double?)o["graceDays"],
                    Hardware = false,
                    MachineId = (string)scenario["machineId"]!,
                    Clock = () => DateTimeOffset.FromUnixTimeMilliseconds(nowMs),
                    Transport = (request, _) =>
                    {
                        Assert.StartsWith(Server, request.Url);
                        Assert.StartsWith("carcha-seal-native/" + SealClient.NativeVersion + " (dotnet)", request.UserAgent);
                        requests.Add(new JsonObject { ["path"] = request.Url.Substring(Server.Length), ["body"] = Placeholders(JsonNode.Parse(request.Body)) });
                        if (scripted is null || scripted["network"] != null) return Task.FromResult(SealHttpResponse.NoAnswer);
                        string text = (string?)scripted["raw"] ?? (scripted["body"]?.ToJsonString() ?? "{}");
                        return Task.FromResult(new SealHttpResponse((int)scripted["status"]!, Encoding.UTF8.GetBytes(text)));
                    },
                };
                using var client = new SealClient(options);
                Assert.Equal("carcha-seal-native/" + SealClient.NativeVersion + " (dotnet)", client.UserAgent);

                var stepsArray = scenario["steps"]!.AsArray();
                var outcomes = scenario["outcomes"]!.AsArray();
                for (int i = 0; i < stepsArray.Count; i++)
                {
                    var step = stepsArray[i]!;
                    nowMs = (long)(double)step["nowMs"]!;
                    scripted = step["response"];
                    requests.Clear();
                    var args = step["args"]?.AsArray().Select(a => (string?)a).ToArray() ?? Array.Empty<string?>();
                    string? Arg(int k) => k < args.Length ? args[k] : null;
                    JsonNode result;
                    try
                    {
                        JsonNode? value = (string)step["call"]! switch
                        {
                            "activate" => StateJson(await client.ActivateAsync(Arg(0)!, Arg(1), TestContext.Current.CancellationToken)),
                            "check" => StateJson(await client.CheckAsync(TestContext.Current.CancellationToken)),
                            "deactivate" => await client.DeactivateAsync(TestContext.Current.CancellationToken).ContinueWith(t => { t.GetAwaiter().GetResult(); return (JsonNode?)null; }),
                            "offlineRequest" => Placeholders(JsonNode.Parse(client.OfflineRequest(Arg(0)!, Arg(1)))),
                            "activateOffline" => StateJson(client.ActivateOffline(Arg(0)!)),
                            "deactivateOffline" => JsonNode.Parse(client.DeactivateOffline()),
                            "decrypt" => Convert.ToBase64String(client.Decrypt(Arg(0)!, Convert.FromBase64String(Arg(1)!))),
                            var other => throw new InvalidOperationException("unknown call " + other),
                        };
                        result = new JsonObject { ["ok"] = true, ["value"] = value };
                    }
                    catch (LicenseException e)
                    {
                        result = new JsonObject { ["ok"] = false, ["error"] = new JsonObject { ["code"] = e.Code, ["message"] = e.Message } };
                    }
                    var got = new JsonObject { ["requests"] = requests.DeepClone(), ["result"] = result };
                    var want = Normalize(outcomes[i]);
                    if (!JsonNode.DeepEquals(got, want)) failures.Add($"{name}, step {i + 1} ({step["call"]}):\n  got:  {got.ToJsonString()}\n  want: {want?.ToJsonString()}");
                    steps++;
                }
            }
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
        Assert.True(failures.Count == 0, string.Join("\n", failures));
        Assert.True(steps >= 90, steps + " steps");
    }

    [Fact]
    public void Options_that_are_refused_name_the_problem()
    {
        var options = new SealOptions
        {
            Product = "studio",
            ServerUrl = "http://seal.example.com",
            PublicKeys = (string)Vectors()["publicKey"]!,
            StorageDirectory = Path.GetTempPath(),
        };
        var e = Assert.Throws<ArgumentException>(() => new SealClient(options));
        Assert.StartsWith("Carcha Seal: insecure_server_url", e.Message);
        options.ServerUrl = "https://seal.example.com";
        options.PublicKeys = "not a key";
        Assert.StartsWith("Carcha Seal: invalid_public_keys", Assert.Throws<ArgumentException>(() => new SealClient(options)).Message);
        options.PublicKeys = (string)Vectors()["publicKey"]!;
        options.Product = "nul\0inside";
        Assert.Throws<ArgumentException>(() => new SealClient(options));
    }
}
