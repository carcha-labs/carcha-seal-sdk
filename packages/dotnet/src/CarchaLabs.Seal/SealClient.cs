using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CarchaLabs.Seal
{
    /// <summary>A request to the license server: POST <see cref="Body"/> (JSON) to <see cref="Url"/>.</summary>
    public sealed class SealHttpRequest
    {
        internal SealHttpRequest(string url, string userAgent, string body)
        {
            Url = url;
            UserAgent = userAgent;
            Body = body;
        }

        /// <summary>The whole address to POST to.</summary>
        public string Url { get; }
        /// <summary>The User-Agent header to send.</summary>
        public string UserAgent { get; }
        /// <summary>The JSON body, to send as is with Content-Type: application/json.</summary>
        public string Body { get; }
    }

    /// <summary>The server's answer. Status 0: no answer (no connection, timeout, TLS failure, a redirect).</summary>
    public sealed class SealHttpResponse
    {
        /// <summary>An answer.</summary>
        public SealHttpResponse(int status, byte[] body)
        {
            Status = status;
            Body = body ?? Array.Empty<byte>();
        }

        /// <summary>The HTTP status, or 0 for no answer.</summary>
        public int Status { get; }
        /// <summary>The raw body.</summary>
        public byte[] Body { get; }

        /// <summary>No answer.</summary>
        public static SealHttpResponse NoAnswer { get; } = new SealHttpResponse(0, Array.Empty<byte>());
    }

    /// <summary>Options for <see cref="SealClient"/>.</summary>
    public sealed class SealOptions
    {
        /// <summary>Your product code.</summary>
        public string Product { get; set; } = "";
        /// <summary>https://, or http:// on this computer only. A hosted vendor's is https://seal.carchalabs.com/&lt;slug&gt;.</summary>
        public string ServerUrl { get; set; } = "";
        /// <summary>The Ed25519 public keys you trust (PEM), in your app's code, not read from a file.</summary>
        public string PublicKeys { get; set; } = "";
        /// <summary>The folder that keeps license.dat.</summary>
        public string StorageDirectory { get; set; } = "";
        /// <summary>Sent so you can require a minimum app version.</summary>
        public string? AppVersion { get; set; }
        /// <summary>Offline grace when the lease has none (default: 7 days).</summary>
        public double? GraceDays { get; set; }
        /// <summary>Send hashed hardware components and this device's public key (default true).</summary>
        public bool Hardware { get; set; } = true;
        /// <summary>The HTTP client for requests; default: one of the library's own, with redirects refused.</summary>
        public HttpClient? HttpClient { get; set; }
        /// <summary>How long a request may take (default 8 seconds).</summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(8);
        /// <summary>Replaces the HTTP client entirely, e.g. for tests.</summary>
        public Func<SealHttpRequest, CancellationToken, Task<SealHttpResponse>>? Transport { get; set; }
        /// <summary>Tests only: a fixed raw machine id instead of this machine's.</summary>
        public string? MachineId { get; set; }
        /// <summary>Tests only: the clock (default: the system clock).</summary>
        public Func<DateTimeOffset>? Clock { get; set; }
    }

    /// <summary>
    /// Carcha Seal license client: the same behaviour as the Electron SDK, run by the native library. One operation
    /// runs at a time; concurrent calls wait for each other.
    /// </summary>
    public sealed class SealClient : IDisposable
    {
        private static readonly Lazy<HttpClient> DefaultHttp = new Lazy<HttpClient>(() =>
            new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = System.Threading.Timeout.InfiniteTimeSpan });

        private readonly ClientHandle _handle;
        private readonly SealOptions _options;
        private readonly SemaphoreSlim _gate = new SemaphoreSlim(1, 1);

        /// <summary>A client. Throws <see cref="ArgumentException"/> naming a bad option ("insecure_server_url", ...).</summary>
        public unsafe SealClient(SealOptions options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            byte[]? product = Utf8.Bytes(options.Product), server = Utf8.Bytes(options.ServerUrl), keys = Utf8.Bytes(options.PublicKeys),
                dir = Utf8.Bytes(options.StorageDirectory), app = Utf8.Bytes(options.AppVersion), sdk = Utf8.Bytes("dotnet"),
                machine = Utf8.Bytes(options.MachineId);
            fixed (byte* pProduct = product, pServer = server, pKeys = keys, pDir = dir, pApp = app, pSdk = sdk, pMachine = machine)
            {
                Native.ClientOptions o;
                Native.seal_client_options_init(&o);
                o.Product = pProduct;
                o.ServerUrl = pServer;
                o.PublicKeys = pKeys;
                o.StorageDir = pDir;
                o.AppVersion = pApp;
                if (options.GraceDays.HasValue) o.GraceDays = options.GraceDays.Value;
                o.SdkName = pSdk;
                o.MachineId = pMachine;
                o.Hardware = options.Hardware ? 1 : 0;
                string? problem = Utf8.Read(Native.seal_client_options_error(&o));
                if (problem != null) throw new ArgumentException("Carcha Seal: " + problem, nameof(options));
                _handle = Native.seal_client_new(&o);
            }
            if (_handle.IsInvalid) throw new InvalidOperationException("Carcha Seal: the client could not be created.");
        }

        /// <summary>The native library's version, which every request reports as sdkVersion.</summary>
        public static unsafe string NativeVersion => Utf8.Read(Native.seal_version()) ?? "";

        /// <summary>The User-Agent sent with every request.</summary>
        public unsafe string UserAgent => Utf8.Read(Native.seal_client_user_agent(_handle)) ?? "";

        private double NowMs()
        {
            DateTimeOffset now = _options.Clock?.Invoke() ?? DateTimeOffset.UtcNow;
            return now.ToUnixTimeMilliseconds();
        }

        /// <summary>
        /// Activates this device with a license key. machineName: what the vendor sees for this device; none is sent by
        /// default (a computer name often holds a person's name).
        /// </summary>
        public unsafe Task<LicenseState> ActivateAsync(string licenseKey, string? machineName = null, CancellationToken cancellationToken = default)
        {
            byte[] key = Utf8.Bytes(licenseKey ?? throw new ArgumentNullException(nameof(licenseKey)))!;
            byte[]? name = Utf8.Bytes(machineName);
            return Run(() =>
            {
                fixed (byte* pKey = key, pName = name) return Native.seal_client_activate_begin(_handle, pKey, pName);
            }, (status, body, now) =>
            {
                fixed (byte* pBody = body) return Native.seal_client_activate_finish(_handle, status, pBody, (nuint)body.Length, now);
            }, StateOf, cancellationToken);
        }

        /// <summary>Checks the license: online when the server answers, otherwise from the saved lease with its offline grace.</summary>
        public unsafe Task<LicenseState> CheckAsync(CancellationToken cancellationToken = default)
        {
            return Run(() => Native.seal_client_check_begin(_handle, NowMs()), (status, body, now) =>
            {
                fixed (byte* pBody = body) return Native.seal_client_check_finish(_handle, status, pBody, (nuint)body.Length, now);
            }, StateOf, cancellationToken);
        }

        /// <summary>Releases this device's seat on the server and removes the license here.</summary>
        public unsafe Task DeactivateAsync(CancellationToken cancellationToken = default)
        {
            return Run(() => Native.seal_client_deactivate_begin(_handle), (status, body, now) =>
            {
                fixed (byte* pBody = body) return Native.seal_client_deactivate_finish(_handle, status, pBody, (nuint)body.Length);
            }, r =>
            {
                ThrowIfError(r);
                return true;
            }, cancellationToken);
        }

        /// <summary>Offline activation, step 1: the request file (JSON text) for a machine that cannot reach the server.</summary>
        public unsafe string OfflineRequest(string licenseKey, string? machineName = null)
        {
            byte[] key = Utf8.Bytes(licenseKey ?? throw new ArgumentNullException(nameof(licenseKey)))!;
            byte[]? name = Utf8.Bytes(machineName);
            return Locked(() =>
            {
                fixed (byte* pKey = key, pName = name)
                using (var r = Checked(Native.seal_client_offline_request(_handle, pKey, pName)))
                    return TextOf(r);
            });
        }

        /// <summary>Offline activation, step 2: loads the license file the server issued for this machine's request.</summary>
        public unsafe LicenseState ActivateOffline(string licenseFile)
        {
            byte[] file = Utf8.Bytes(licenseFile ?? throw new ArgumentNullException(nameof(licenseFile)))!;
            return Locked(() =>
            {
                fixed (byte* pFile = file)
                using (var r = Checked(Native.seal_client_activate_offline(_handle, pFile, NowMs())))
                    return StateOf(r);
            });
        }

        /// <summary>Gives an offline machine's seat back: removes the license and returns the deactivation file (JSON text).</summary>
        public unsafe string DeactivateOffline()
        {
            return Locked(() =>
            {
                using (var r = Checked(Native.seal_client_deactivate_offline(_handle))) return TextOf(r);
            });
        }

        /// <summary>Decrypts data you encrypted for a feature, offline, with the saved lease. The content key stays in the native library.</summary>
        public unsafe byte[] Decrypt(string feature, byte[] data)
        {
            byte[] name = Utf8.Bytes(feature ?? throw new ArgumentNullException(nameof(feature)))!;
            if (data is null) throw new ArgumentNullException(nameof(data));
            return Locked(() =>
            {
                fixed (byte* pName = name, pData = data)
                using (var r = Checked(Native.seal_client_decrypt(_handle, pName, data.Length == 0 ? null : pData, (nuint)data.Length, NowMs())))
                {
                    ThrowIfError(r);
                    nuint len;
                    byte* plain = Native.seal_result_data(r, &len);
                    var copy = new byte[(int)len];
                    for (int i = 0; i < copy.Length; i++) copy[i] = plain[i];
                    return copy;
                }
            });
        }

        /// <summary>Frees the native client.</summary>
        public void Dispose()
        {
            _handle.Dispose();
            _gate.Dispose();
        }

        private T Locked<T>(Func<T> body)
        {
            _gate.Wait();
            try
            {
                return body();
            }
            finally
            {
                _gate.Release();
            }
        }

        private delegate ResultHandle Finish(int status, byte[] body, double nowMs);

        /// <summary>Begin, send the request when there is one, finish; under the client's lock so no other operation interleaves.</summary>
        private async Task<T> Run<T>(Func<ResultHandle> begin, Finish finish, Func<ResultHandle, T> read, CancellationToken cancellationToken)
        {
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                SealHttpRequest? request = null;
                using (var first = Checked(begin()))
                {
                    if (Native.seal_result_kind(first) != Native.ResultSend) return read(first);
                    request = RequestOf(first);
                }
                SealHttpResponse response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
                int status = response.Status >= 100 && response.Status <= 599 ? response.Status : 0;
                using (var second = Checked(finish(status, response.Body, NowMs()))) return read(second);
            }
            finally
            {
                _gate.Release();
            }
        }

        private async Task<SealHttpResponse> SendAsync(SealHttpRequest request, CancellationToken cancellationToken)
        {
            if (_options.Transport != null) return await _options.Transport(request, cancellationToken).ConfigureAwait(false);
            HttpClient http = _options.HttpClient ?? DefaultHttp.Value;
            using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            using (var message = new HttpRequestMessage(HttpMethod.Post, request.Url))
            {
                timeout.CancelAfter(_options.Timeout);
                message.Content = new StringContent(request.Body, Encoding.UTF8, "application/json");
                message.Headers.TryAddWithoutValidation("User-Agent", request.UserAgent);
                try
                {
                    using (HttpResponseMessage answer = await http.SendAsync(message, timeout.Token).ConfigureAwait(false))
                    {
                        int status = (int)answer.StatusCode;
                        // A redirect could take the license key to another address or to http:// (ASVS 4.1.2): never followed.
                        if (status >= 300 && status < 400) return SealHttpResponse.NoAnswer;
                        // An HttpClient of the app's that follows redirects has already followed one: its answer is not used.
                        Uri? answered = answer.RequestMessage?.RequestUri;
                        if (answered != null && answered != new Uri(request.Url)) return SealHttpResponse.NoAnswer;
                        byte[] body = await answer.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                        return new SealHttpResponse(status, body);
                    }
                }
                catch (HttpRequestException)
                {
                    return SealHttpResponse.NoAnswer;
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    return SealHttpResponse.NoAnswer; // the timeout, not the caller
                }
            }
        }

        private unsafe SealHttpRequest RequestOf(ResultHandle r) =>
            new SealHttpRequest(Utf8.Read(Native.seal_result_request_url(r)) ?? "", UserAgent, Utf8.Read(Native.seal_result_request_body(r)) ?? "");

        private static ResultHandle Checked(ResultHandle r)
        {
            if (r.IsInvalid)
            {
                r.Dispose();
                throw new ArgumentException("Carcha Seal: invalid argument.");
            }
            return r;
        }

        private static unsafe void ThrowIfError(ResultHandle r)
        {
            if (Native.seal_result_kind(r) == Native.ResultError)
                throw new LicenseException(Utf8.Read(Native.seal_result_error_code(r)) ?? "error", Utf8.Read(Native.seal_result_error_message(r)) ?? "");
        }

        private static unsafe string TextOf(ResultHandle r)
        {
            ThrowIfError(r);
            return Utf8.Read(Native.seal_result_text(r)) ?? "";
        }

        private static DateTimeOffset? Date(string? iso) =>
            iso is null ? (DateTimeOffset?)null : DateTimeOffset.Parse(iso, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

        private static unsafe LicenseState StateOf(ResultHandle r)
        {
            ThrowIfError(r);
            int status = Native.seal_state_status(r);
            var s = new LicenseState
            {
                Status = status switch
                {
                    1 => LicenseStatus.Valid,
                    2 => LicenseStatus.Grace,
                    3 => LicenseStatus.Invalid,
                    4 => LicenseStatus.Unlicensed,
                    5 => LicenseStatus.ClockSuspect,
                    _ => throw new InvalidOperationException("Carcha Seal: the result holds no license state."),
                },
                Offline = Native.seal_state_flag(r, Native.FlagOffline) == 1,
                StorageProtected = Native.seal_state_flag(r, Native.FlagStorageProtected) == 1,
                OfflineActivated = Native.seal_state_flag(r, Native.FlagOfflineActivated) == 1,
                Reason = Utf8.Read(Native.seal_state_text(r, Native.FieldReason)),
                Message = Utf8.Read(Native.seal_state_text(r, Native.FieldMessage)),
                Customer = Utf8.Read(Native.seal_state_text(r, Native.FieldCustomer)),
                ExpiresAt = Date(Utf8.Read(Native.seal_state_text(r, Native.FieldExpiresAt))),
                MaintenanceUntil = Date(Utf8.Read(Native.seal_state_text(r, Native.FieldMaintenanceUntil))),
                RevalidateBy = Date(Utf8.Read(Native.seal_state_text(r, Native.FieldRevalidateBy))),
                KeyHint = Utf8.Read(Native.seal_state_text(r, Native.FieldKeyHint)),
                NoticesJson = Utf8.Read(Native.seal_state_text(r, Native.FieldNoticesJson)),
            };
            nuint count = Native.seal_state_feature_count(r);
            var features = new List<string>((int)count);
            for (nuint i = 0; i < count; i++) features.Add(Utf8.Read(Native.seal_state_feature(r, i)) ?? "");
            s.Features = features;
            return s;
        }
    }
}
