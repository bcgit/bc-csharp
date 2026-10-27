using System;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /// <summary>
    /// Signature Subpacket encoding the level and amount of trust the issuer places into the certified key or identity.
    /// </summary>
    /// <remarks>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.10">RFC4880 - Trust Packet</see>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-trust-signature">RFC9580 - Trust Signature</see>
    /// </remarks>
    public class TrustSignature
        : SignatureSubpacket
    {
        private static byte[] IntToByteArray(int v1, int v2) => new byte[2]{ (byte)v1, (byte)v2 };

        /// <summary>Create a new <see cref="TrustSignature"/>.</summary>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="isLongLength">true if the long length form is used, false otherwise.</param>
        /// <param name="data">The data.</param>
        public TrustSignature(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.TrustSig, critical, isLongLength, VerifyData(data))
        {
        }

        /// <summary>Create a new <see cref="TrustSignature"/>.</summary>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="depth">The depth.</param>
        /// <param name="trustAmount">The trust amount.</param>
        public TrustSignature(bool critical, int depth, int trustAmount)
            : base(SignatureSubpacketTag.TrustSig, critical, isLongLength: false, IntToByteArray(depth, trustAmount))
        {
        }

        // RFC 9580 5.2.3.21: the Trust Signature body is 1 octet of depth followed by 1 octet
        // of trust amount, so at least two octets are required.
        private static byte[] VerifyData(byte[] data)
        {
            if (data.Length < 2)
                throw new ArgumentException("Truncated trust signature subpacket", nameof(data));

            return data;
        }

        /// <summary>Gets the depth.</summary>
        public int Depth => Data[0];

        /// <summary>Gets the trust amount.</summary>
        public int TrustAmount => Data[1];
    }
}
