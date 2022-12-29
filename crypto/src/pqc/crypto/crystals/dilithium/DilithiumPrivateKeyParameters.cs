using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
    public sealed class DilithiumPrivateKeyParameters
        : DilithiumKeyParameters
    {
        internal byte[] rho;
        internal byte[] k;
        internal byte[] tr;
        internal byte[] s1;
        internal byte[] s2;
        internal byte[] t0;
        
        private byte[] t1;

        public DilithiumPrivateKeyParameters(DilithiumParameters parameters,  byte[] rho, byte[] K, byte[] tr, byte[] s1, byte[] s2, byte[] t0, byte[] t1)
            : base(true, parameters)
        {
            this.rho = Arrays.Clone(rho);
            this.k = Arrays.Clone(K);
            this.tr = Arrays.Clone(tr);
            this.s1 = Arrays.Clone(s1);
            this.s2 = Arrays.Clone(s2);
            this.t0 = Arrays.Clone(t0);
            this.t1 = Arrays.Clone(t1);
        }
        
        public byte[] Rho => Arrays.Clone(rho);

        public byte[] K => Arrays.Clone(k);

        public byte[] Tr => Arrays.Clone(tr);

        public byte[] S1 => Arrays.Clone(s1);

        public byte[] S2 => Arrays.Clone(s2);
        

        public byte[] T0 => Arrays.Clone(t0);

        public byte[] T1 => t1;

        public byte[] GetEncoded()
        {
            return Arrays.ConcatenateAll(rho, k, tr, s1, s2, t0);
        }
    }
}