using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
     * packet giving the intended recipient fingerprint.
     */
    public class IntendedRecipientFingerprint
        : SignatureSubpacket
    {
        public IntendedRecipientFingerprint(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.IntendedRecipientFingerprint, critical, isLongLength, data)
        {
        }

        public IntendedRecipientFingerprint(bool critical, int keyVersion, byte[] fingerprint)
            : base(SignatureSubpacketTag.IntendedRecipientFingerprint, critical, false,
                Arrays.Prepend(fingerprint, (byte)keyVersion))
        {
        }

        public int KeyVersion => data[0];

        public byte[] GetFingerprint() => Arrays.CopyOfRange(data, 1, data.Length);
    }
}
