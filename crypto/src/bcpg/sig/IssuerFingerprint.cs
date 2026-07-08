using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /// <summary>Signature Subpacket containing the fingerprint of the issuers signing (sub-) key.</summary>
    /// <remarks>
    /// This packet supersedes the <see cref="IssuerKeyId"/> subpacket.
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-issuer-fingerprint">
    /// RFC9580 - Issuer Fingerprint
    /// </see>
    /// </para>
    /// </remarks>
    public class IssuerFingerprint
        : SignatureSubpacket
    {
        public IssuerFingerprint(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.IssuerFingerprint, critical, isLongLength, VerifyData(data))
        {
        }

        public IssuerFingerprint(bool critical, int keyVersion, byte[] fingerprint)
            : base(SignatureSubpacketTag.IssuerFingerprint, critical, isLongLength: false,
                Arrays.Prepend(fingerprint, (byte)keyVersion))
        {
        }

        private static byte[] VerifyData(byte[] data)
        {
            if (data.Length < 1)
                throw new ArgumentException("Data too short. Expect at least one octet of key version.", nameof(data));

            return data;
        }

        public int KeyVersion => Data[0];

        public byte[] GetFingerprint() => Arrays.CopyOfRange(Data, 1, Data.Length);

        public long GetKeyID() => FingerprintUtilities.KeyIDFromFingerprint(KeyVersion, GetFingerprint());
    }
}
