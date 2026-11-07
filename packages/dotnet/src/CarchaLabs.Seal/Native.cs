// The native library's C interface (packages/native/include/seal.h). Every signature uses only pointers and
// numbers (blittable), so the same declarations work as LibraryImport (net10.0, source-generated, AOT) and
// DllImport (netstandard2.0, net462); strings are converted to and from UTF-8 by Utf8 below.
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace CarchaLabs.Seal
{
    internal static unsafe partial class Native
    {
        internal const string Library = "seal_native";

#if NETFRAMEWORK
        // Runs before the first call into the library: loads the copy for this process's CPU.
        static Native()
        {
            NetFrameworkLoader.Load();
        }
#endif

        internal const int ResultSend = 1;
        internal const int ResultDone = 2;
        internal const int ResultError = 3;

        internal const int FlagOffline = 1;
        internal const int FlagStorageProtected = 2;
        internal const int FlagOfflineActivated = 3;

        internal const int FieldReason = 1;
        internal const int FieldMessage = 2;
        internal const int FieldCustomer = 3;
        internal const int FieldExpiresAt = 4;
        internal const int FieldMaintenanceUntil = 5;
        internal const int FieldRevalidateBy = 6;
        internal const int FieldKeyHint = 7;
        internal const int FieldNoticesJson = 8;

        /// <summary>seal_client_options, field for field.</summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct ClientOptions
        {
            public byte* Product;
            public byte* ServerUrl;
            public byte* PublicKeys;
            public byte* StorageDir;
            public byte* AppVersion;
            public double GraceDays;
            public byte* SdkName;
            public byte* MachineId;
            public int Hardware;
        }

#if NET7_0_OR_GREATER
        [LibraryImport(Library)] internal static partial byte* seal_version();
        [LibraryImport(Library)] internal static partial void seal_client_options_init(ClientOptions* options);
        [LibraryImport(Library)] internal static partial byte* seal_client_options_error(ClientOptions* options);
        [LibraryImport(Library)] internal static partial ClientHandle seal_client_new(ClientOptions* options);
        [LibraryImport(Library)] internal static partial void seal_client_free(IntPtr client);
        [LibraryImport(Library)] internal static partial byte* seal_client_user_agent(ClientHandle client);
        [LibraryImport(Library)] internal static partial ResultHandle seal_client_activate_begin(ClientHandle client, byte* licenseKey, byte* machineName);
        [LibraryImport(Library)] internal static partial ResultHandle seal_client_activate_finish(ClientHandle client, int status, byte* body, nuint bodyLen, double nowMs);
        [LibraryImport(Library)] internal static partial ResultHandle seal_client_check_begin(ClientHandle client, double nowMs);
        [LibraryImport(Library)] internal static partial ResultHandle seal_client_check_finish(ClientHandle client, int status, byte* body, nuint bodyLen, double nowMs);
        [LibraryImport(Library)] internal static partial ResultHandle seal_client_deactivate_begin(ClientHandle client);
        [LibraryImport(Library)] internal static partial ResultHandle seal_client_deactivate_finish(ClientHandle client, int status, byte* body, nuint bodyLen);
        [LibraryImport(Library)] internal static partial ResultHandle seal_client_offline_request(ClientHandle client, byte* licenseKey, byte* machineName);
        [LibraryImport(Library)] internal static partial ResultHandle seal_client_activate_offline(ClientHandle client, byte* licenseFile, double nowMs);
        [LibraryImport(Library)] internal static partial ResultHandle seal_client_deactivate_offline(ClientHandle client);
        [LibraryImport(Library)] internal static partial ResultHandle seal_client_decrypt(ClientHandle client, byte* feature, byte* data, nuint dataLen, double nowMs);
        [LibraryImport(Library)] internal static partial void seal_result_free(IntPtr result);
        [LibraryImport(Library)] internal static partial int seal_result_kind(ResultHandle result);
        [LibraryImport(Library)] internal static partial byte* seal_result_request_url(ResultHandle result);
        [LibraryImport(Library)] internal static partial byte* seal_result_request_body(ResultHandle result);
        [LibraryImport(Library)] internal static partial byte* seal_result_error_code(ResultHandle result);
        [LibraryImport(Library)] internal static partial byte* seal_result_error_message(ResultHandle result);
        [LibraryImport(Library)] internal static partial byte* seal_result_text(ResultHandle result);
        [LibraryImport(Library)] internal static partial byte* seal_result_data(ResultHandle result, nuint* len);
        [LibraryImport(Library)] internal static partial int seal_state_status(ResultHandle result);
        [LibraryImport(Library)] internal static partial int seal_state_flag(ResultHandle result, int flag);
        [LibraryImport(Library)] internal static partial byte* seal_state_text(ResultHandle result, int field);
        [LibraryImport(Library)] internal static partial nuint seal_state_feature_count(ResultHandle result);
        [LibraryImport(Library)] internal static partial byte* seal_state_feature(ResultHandle result, nuint index);
#else
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern byte* seal_version();
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern void seal_client_options_init(ClientOptions* options);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern byte* seal_client_options_error(ClientOptions* options);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern ClientHandle seal_client_new(ClientOptions* options);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern void seal_client_free(IntPtr client);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern byte* seal_client_user_agent(ClientHandle client);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern ResultHandle seal_client_activate_begin(ClientHandle client, byte* licenseKey, byte* machineName);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern ResultHandle seal_client_activate_finish(ClientHandle client, int status, byte* body, UIntPtr bodyLen, double nowMs);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern ResultHandle seal_client_check_begin(ClientHandle client, double nowMs);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern ResultHandle seal_client_check_finish(ClientHandle client, int status, byte* body, UIntPtr bodyLen, double nowMs);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern ResultHandle seal_client_deactivate_begin(ClientHandle client);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern ResultHandle seal_client_deactivate_finish(ClientHandle client, int status, byte* body, UIntPtr bodyLen);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern ResultHandle seal_client_offline_request(ClientHandle client, byte* licenseKey, byte* machineName);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern ResultHandle seal_client_activate_offline(ClientHandle client, byte* licenseFile, double nowMs);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern ResultHandle seal_client_deactivate_offline(ClientHandle client);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern ResultHandle seal_client_decrypt(ClientHandle client, byte* feature, byte* data, UIntPtr dataLen, double nowMs);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern void seal_result_free(IntPtr result);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern int seal_result_kind(ResultHandle result);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern byte* seal_result_request_url(ResultHandle result);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern byte* seal_result_request_body(ResultHandle result);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern byte* seal_result_error_code(ResultHandle result);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern byte* seal_result_error_message(ResultHandle result);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern byte* seal_result_text(ResultHandle result);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern byte* seal_result_data(ResultHandle result, UIntPtr* len);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern int seal_state_status(ResultHandle result);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern int seal_state_flag(ResultHandle result, int flag);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern byte* seal_state_text(ResultHandle result, int field);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern UIntPtr seal_state_feature_count(ResultHandle result);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl)] internal static extern byte* seal_state_feature(ResultHandle result, UIntPtr index);
#endif
    }

    /// <summary>A seal_client, freed with seal_client_free.</summary>
    internal sealed class ClientHandle : SafeHandle
    {
        public ClientHandle() : base(IntPtr.Zero, ownsHandle: true) { }
        public override bool IsInvalid => handle == IntPtr.Zero;
        protected override bool ReleaseHandle()
        {
            Native.seal_client_free(handle);
            return true;
        }
    }

    /// <summary>A seal_result, freed with seal_result_free (which also overwrites decrypted data).</summary>
    internal sealed class ResultHandle : SafeHandle
    {
        public ResultHandle() : base(IntPtr.Zero, ownsHandle: true) { }
        public override bool IsInvalid => handle == IntPtr.Zero;
        protected override bool ReleaseHandle()
        {
            Native.seal_result_free(handle);
            return true;
        }
    }

    /// <summary>UTF-8 to and from the native library (netstandard2.0 has no UTF-8 string marshalling).</summary>
    internal static unsafe class Utf8
    {
        /// <summary>The string as NUL-terminated UTF-8; null stays null.</summary>
        internal static byte[]? Bytes(string? value)
        {
            if (value is null) return null;
            if (value.IndexOf('\0') >= 0) throw new ArgumentException("A string passed to Carcha Seal must not contain a NUL character.");
            var bytes = new byte[Encoding.UTF8.GetByteCount(value) + 1];
            Encoding.UTF8.GetBytes(value, 0, value.Length, bytes, 0);
            return bytes;
        }

        /// <summary>A NUL-terminated UTF-8 string the native library owns; null for NULL.</summary>
        internal static string? Read(byte* p)
        {
            if (p == null) return null;
            int len = 0;
            while (p[len] != 0) len++;
            return Encoding.UTF8.GetString(p, len);
        }
    }
}
