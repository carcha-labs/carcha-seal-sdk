// The default HTTP path (the library's own HttpClient) against a local server: what it sends, refusals,
// redirects not followed, no connection.
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json.Nodes;
using CarchaLabs.Seal;
using Xunit;

namespace CarchaLabs.Seal.Tests;

public class HttpTests
{
    /// <summary>One request on a local port: returns the raw request received; writes <paramref name="answer"/> as is.</summary>
    private static (string Url, Task<string> Received) ServeOnce(Func<string, string> answer)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        string url = "http://127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port;
        var received = Task.Run(async () =>
        {
            using var socket = await listener.AcceptTcpClientAsync();
            listener.Stop();
            var stream = socket.GetStream();
            var reader = new StreamReader(stream, Encoding.ASCII);
            var head = new StringBuilder();
            int length = 0;
            string? line;
            while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync()))
            {
                head.Append(line).Append("\r\n");
                if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase)) length = int.Parse(line.Substring(15).Trim());
            }
            var body = new char[length];
            int read = 0;
            while (read < length) read += await reader.ReadAsync(body, read, length - read);
            var request = head + "\r\n" + new string(body);
            var bytes = Encoding.ASCII.GetBytes(answer(url));
            await stream.WriteAsync(bytes, 0, bytes.Length);
            return request;
        });
        return (url, received);
    }

    private static SealClient Client(string serverUrl) => new SealClient(new SealOptions
    {
        Product = "studio",
        ServerUrl = serverUrl,
        PublicKeys = (string)JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "vectors.json")))!["publicKey"]!,
        StorageDirectory = Path.Combine(Path.GetTempPath(), "seal-dotnet-http-" + Guid.NewGuid().ToString("N")),
        MachineId = "linux:0123456789abcdef0123456789abcdef",
        Hardware = false,
        Timeout = TimeSpan.FromSeconds(5),
    });

    [Fact]
    public async Task Posts_json_with_the_user_agent_and_reads_a_refusal()
    {
        const string refusal = "{\"error\":\"activation_limit\",\"message\":\"All seats are in use.\"}";
        var (url, received) = ServeOnce(_ => $"HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: {refusal.Length}\r\nConnection: close\r\n\r\n{refusal}");
        using var client = Client(url + "/acme");
        var e = await Assert.ThrowsAsync<LicenseException>(() => client.ActivateAsync("LK-AAAA-BBBB", cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(("activation_limit", "All seats are in use."), (e.Code, e.Message));
        string request = (await received).ToLowerInvariant();
        Assert.StartsWith("post /acme/v1/activate http/1.1\r\n", request);
        Assert.Contains("\r\ncontent-type: application/json; charset=utf-8\r\n", request);
        Assert.Contains("\r\nuser-agent: carcha-seal-native/" + SealClient.NativeVersion + " (dotnet)\r\n", request);
        Assert.Contains("\"licensekey\":\"lk-aaaa-bbbb\"", request);
    }

    [Theory]
    [InlineData("301 Moved Permanently")]
    [InlineData("302 Found")]
    [InlineData("303 See Other")]
    [InlineData("307 Temporary Redirect")]
    [InlineData("308 Permanent Redirect")]
    public async Task A_redirect_is_not_followed(string status)
    {
        var (target, reached) = ServeOnce(_ => "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
        var (url, _) = ServeOnce(_ => $"HTTP/1.1 {status}\r\nLocation: {target}/v1/activate\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        using var client = Client(url);
        var e = await Assert.ThrowsAsync<LicenseException>(() => client.ActivateAsync("LK-AAAA-BBBB", cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal("network", e.Code);
        Assert.NotSame(reached, await Task.WhenAny(reached, Task.Delay(300, TestContext.Current.CancellationToken)));
    }

    [Theory]
    [InlineData("307 Temporary Redirect")]
    [InlineData("308 Permanent Redirect")]
    public async Task The_answer_after_a_redirect_followed_by_the_apps_own_HttpClient_is_not_used(string status)
    {
        const string activated = "{\"token\":\"not-a-lease\"}";
        var (target, reached) = ServeOnce(_ => $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {activated.Length}\r\nConnection: close\r\n\r\n{activated}");
        var (url, _) = ServeOnce(_ => $"HTTP/1.1 {status}\r\nLocation: {target}/v1/activate\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        // HttpClient's default handler follows redirects (AllowAutoRedirect = true), against the README's advice.
        using var followsRedirects = new System.Net.Http.HttpClient();
        using var client = new SealClient(new SealOptions
        {
            Product = "studio",
            ServerUrl = url,
            PublicKeys = (string)JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "vectors.json")))!["publicKey"]!,
            StorageDirectory = Path.Combine(Path.GetTempPath(), "seal-dotnet-http-" + Guid.NewGuid().ToString("N")),
            MachineId = "linux:0123456789abcdef0123456789abcdef",
            Hardware = false,
            HttpClient = followsRedirects,
        });
        var e = await Assert.ThrowsAsync<LicenseException>(() => client.ActivateAsync("LK-AAAA-BBBB", cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal("network", e.Code);
        Assert.Contains("post /v1/activate", (await reached).ToLowerInvariant()); // the app's HttpClient did follow it
    }

    [Fact]
    public async Task No_connection_is_a_network_error_and_check_falls_back_to_nothing_saved()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        using var client = Client("http://127.0.0.1:" + port);
        Assert.Equal("network", (await Assert.ThrowsAsync<LicenseException>(() => client.ActivateAsync("LK-AAAA-BBBB", cancellationToken: TestContext.Current.CancellationToken))).Code);
        Assert.Equal(LicenseStatus.Unlicensed, (await client.CheckAsync(TestContext.Current.CancellationToken)).Status);
    }
}
