using System;
using System.Collections.Generic;
using System.Linq;

namespace CarchaLabs.Seal
{
    /// <summary>Where a license stands.</summary>
    public enum LicenseStatus
    {
        /// <summary>The lease is valid.</summary>
        Valid,
        /// <summary>Past the revalidation time but within the offline grace period: still usable.</summary>
        Grace,
        /// <summary>Not usable; <see cref="LicenseState.Reason"/> says why.</summary>
        Invalid,
        /// <summary>This device has no license.</summary>
        Unlicensed,
        /// <summary>The device clock looks wrong (set back, or behind the lease).</summary>
        ClockSuspect,
    }

    /// <summary>The license state, as the Electron SDK's LicenseState.</summary>
    public sealed class LicenseState
    {
        internal LicenseState() { }

        /// <summary>Where the license stands.</summary>
        public LicenseStatus Status { get; internal set; }
        /// <summary>The state comes from the saved lease because the server did not answer.</summary>
        public bool Offline { get; internal set; }
        /// <summary>The saved license is protected by the operating system.</summary>
        public bool StorageProtected { get; internal set; }
        /// <summary>The license came from an offline license file.</summary>
        public bool OfflineActivated { get; internal set; }
        /// <summary>Why the state is not valid, or "offline_grace": "expired", "wrong_device", "license_suspended", ...</summary>
        public string? Reason { get; internal set; }
        /// <summary>A message to show the user.</summary>
        public string? Message { get; internal set; }
        /// <summary>The customer the license was issued to.</summary>
        public string? Customer { get; internal set; }
        /// <summary>The licensed features.</summary>
        public IReadOnlyList<string> Features { get; internal set; } = Array.Empty<string>();
        /// <summary>When the license expires; null for a perpetual license or no license.</summary>
        public DateTimeOffset? ExpiresAt { get; internal set; }
        /// <summary>The end of maintenance (licensed updates), if any.</summary>
        public DateTimeOffset? MaintenanceUntil { get; internal set; }
        /// <summary>When the app must reach the server again (or, in grace, the end of the grace period).</summary>
        public DateTimeOffset? RevalidateBy { get; internal set; }
        /// <summary>The license key's start and end, for display ("LK-7K2M…YZ5S").</summary>
        public string? KeyHint { get; internal set; }
        /// <summary>The server's notices (sdk_update_recommended, app_update_recommended, ...) as a JSON array.</summary>
        public string? NoticesJson { get; internal set; }

        /// <summary>Valid or in its grace period.</summary>
        public bool IsUsable => Status == LicenseStatus.Valid || Status == LicenseStatus.Grace;

        /// <summary>True when the state is usable and grants the feature.</summary>
        public bool HasFeature(string feature) => IsUsable && Features.Contains(feature);
    }

    /// <summary>A refusal or failure, with the SDK's code and a message to show the user.</summary>
    public sealed class LicenseException : Exception
    {
        /// <summary>A refusal or failure.</summary>
        public LicenseException(string code, string message) : base(message)
        {
            Code = code;
        }

        /// <summary>"network", "activation_limit", "invalid_key", "wrong_device", "license_expired", ...</summary>
        public string Code { get; }
    }
}
