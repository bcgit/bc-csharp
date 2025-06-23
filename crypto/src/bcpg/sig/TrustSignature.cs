namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
     * packet giving trust.
     */
    public class TrustSignature
        : SignatureSubpacket
    {
        private static byte[] IntToByteArray(int v1, int v2) => new byte[2]{ (byte)v1, (byte)v2 };

        public TrustSignature(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.TrustSig, critical, isLongLength, data)
        {
        }

        public TrustSignature(bool critical, int depth, int trustAmount)
            : base(SignatureSubpacketTag.TrustSig, critical, isLongLength: false, IntToByteArray(depth, trustAmount))
        {
        }

        public int Depth => data[0];

        public int TrustAmount => data[1];
    }
}
