using Org.BouncyCastle.Utilities;


namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    public class FalconPrivateKeyParameters
        : FalconKeyParameters
    {
        private byte[] pk;
        private byte[] f;
        private byte[] g;
        private byte[] F;

        public FalconPrivateKeyParameters(FalconParameters parameters, byte[] f, byte[] g, byte[] F, byte[] pk_encoded)
            : base(true, parameters)
        {
            this.f = Arrays.Clone(f);
            this.g = Arrays.Clone(g);
            this.F = Arrays.Clone(F);
            this.pk = Arrays.Clone(pk_encoded);
        }

        public byte[] GetEncoded()
        {
            return Arrays.ConcatenateAll(f, g, F);
        }
        
        public byte[] GetPublicKey()
        {
            return Arrays.Clone(pk);
        }

        public byte[] GetSpolyf()
        {
            return Arrays.Clone(f);
        }

        public byte[] GetG()
        {
            return Arrays.Clone(g);
        }

        public byte[] GetSpolyF()
        {
            return Arrays.Clone(F);
        }
    }
}
