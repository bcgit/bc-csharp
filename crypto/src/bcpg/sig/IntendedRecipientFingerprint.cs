using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /// <summary>Signature Subpacket containing the fingerprint of the intended recipients primary key.</summary>
    /// <remarks>
    /// This packet can be used to prevent malicious forwarding/replay attacks.
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-intended-recipient-fingerpr">
    /// RFC9580 - Intended Recipient Fingerprint
    /// </see>
    /// </para>
    /// </remarks>
    public class IntendedRecipientFingerprint
        : SignatureSubpacket
    {
        public IntendedRecipientFingerprint(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.IntendedRecipientFingerprint, critical, isLongLength, VerifyData(data))
        {
        }

        public IntendedRecipientFingerprint(bool critical, int keyVersion, byte[] fingerprint)
            : base(SignatureSubpacketTag.IntendedRecipientFingerprint, critical, isLongLength: false,
                Arrays.Prepend(fingerprint, (byte)keyVersion))
        {
        }

        private static byte[] VerifyData(byte[] data)
        {
            if (data.Length < 1)
                throw new ArgumentException("Data too short. Expect at least one octet of key version number.",
                    nameof(data));

            return data;
        }

        public int KeyVersion => Data[0];

        public byte[] GetFingerprint() => Arrays.CopyOfRange(Data, 1, Data.Length);
    }
}
