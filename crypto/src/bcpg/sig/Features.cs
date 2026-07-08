using System;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /// <summary>Signature Subpacket encoding which features are supported by the key-holders implementation.</summary>
    /// <remarks>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.24">RFC4880 - Features</see>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-features">RFC9580 - Features</see>
    /// </remarks>
    public class Features
        : SignatureSubpacket
    {
        /// <summary>Modification Detection (packets 18 and 19).</summary>
        public static readonly byte FEATURE_MODIFICATION_DETECTION = 0x01;

        /// <summary>
        /// AEAD Encrypted Data Packet (packet 20) and version 5 Symmetric-Key Encrypted Session Key Packets (packet 3).
        /// </summary>
        public static readonly byte FEATURE_AEAD_ENCRYPTED_DATA = 0x02;

        /// <summary>Version 5 Public-Key Packet format and corresponding new fingerprint format.</summary>
        public static readonly byte FEATURE_VERSION_5_PUBLIC_KEY = 0x04;

        /// <summary>Symmetrically Encrypted Integrity Protected Data packet version 2.</summary>
        public static readonly byte FEATURE_SEIPD_V2 = 0x08;

        private static byte[] FeatureToByteArray(byte feature) => new byte[1]{ feature };

        public Features(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.Features, critical, isLongLength, VerifyData(data))
        {
        }

        public Features(bool critical, byte features)
            : this(critical, false, FeatureToByteArray(features))
        {
        }

        public Features(bool critical, int features)
            : this(critical, false, FeatureToByteArray((byte)features))
        {
        }

        // RFC 9580 5.2.3.32: the Features body carries the feature flags; GetFeatures() and
        // SupportsFeature() read the first octet (data[0]), so at least one octet is required.
        private static byte[] VerifyData(byte[] data)
        {
            if (data.Length < 1)
                throw new ArgumentException("Truncated Features subpacket", nameof(data));

            return data;
        }

        public byte GetFeatures() => Data[0];

        public bool SupportsModificationDetection => SupportsFeature(FEATURE_MODIFICATION_DETECTION);

        public bool SupportsSeipdV2() => SupportsFeature(FEATURE_SEIPD_V2);

        /// <returns><c>true</c> iff the particular feature is supported.</returns>
        public bool SupportsFeature(byte feature) => (Data[0] & feature) != 0;
    }
}
