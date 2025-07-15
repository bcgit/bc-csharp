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
            : base(SignatureSubpacketTag.IntendedRecipientFingerprint, critical, isLongLength: false,
                Arrays.Prepend(fingerprint, (byte)keyVersion))
        {
        }

        public int KeyVersion => Data[0];

        public byte[] GetFingerprint() => Arrays.CopyOfRange(Data, 1, Data.Length);
    }
}
