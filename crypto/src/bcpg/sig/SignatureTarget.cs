using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
     * RFC 4880, Section 5.2.3.25 - Signature Target subpacket.
     */
    public class SignatureTarget
        : SignatureSubpacket
    {
        public SignatureTarget(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.SignatureTarget, critical, isLongLength, data)
        {
        }

        public SignatureTarget(bool critical, int publicKeyAlgorithm, int hashAlgorithm, byte[] hashData)
            : base(SignatureSubpacketTag.SignatureTarget, critical, isLongLength: false,
                  Arrays.Concatenate(new byte[]{ (byte)publicKeyAlgorithm, (byte)hashAlgorithm }, hashData))
        {
        }

        public int PublicKeyAlgorithm => data[0];

        public int HashAlgorithm => data[1];

        public byte[] GetHashData() => Arrays.CopyOfRange(data, 2, data.Length);
    }
}
