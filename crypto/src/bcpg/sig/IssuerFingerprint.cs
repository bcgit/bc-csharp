using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
     * packet giving the issuer key fingerprint.
     */
    public class IssuerFingerprint
        : SignatureSubpacket
    {
        public IssuerFingerprint(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.IssuerFingerprint, critical, isLongLength, data)
        {
        }

        public IssuerFingerprint(bool critical, int keyVersion, byte[] fingerprint)
            : base(SignatureSubpacketTag.IssuerFingerprint, critical, isLongLength: false,
                Arrays.Prepend(fingerprint, (byte)keyVersion))
        {
        }

        public int KeyVersion => Data[0];

        public byte[] GetFingerprint() => Arrays.CopyOfRange(Data, 1, Data.Length);
    }
}
