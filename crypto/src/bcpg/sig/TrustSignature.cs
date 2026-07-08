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

        public TrustSignature(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.TrustSig, critical, isLongLength, VerifyData(data))
        {
        }

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

        public int Depth => Data[0];

        public int TrustAmount => Data[1];
    }
}
