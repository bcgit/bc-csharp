using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
    public class DilithiumPublicKeyParameters
        : DilithiumKeyParameters
    {
        internal byte[] rho;
        internal byte[] t1;

        public DilithiumPublicKeyParameters(DilithiumParameters parameters, byte[] pkEncoded)
            : base(false, parameters)
        {
            this.rho = Arrays.CopyOfRange(pkEncoded, 0, DilithiumEngine.SeedBytes);
            this.t1 = Arrays.CopyOfRange(pkEncoded, DilithiumEngine.SeedBytes, pkEncoded.Length);
        }

        public DilithiumPublicKeyParameters(DilithiumParameters parameters, byte[] rho, byte[] t1)
            : base(false, parameters)
        {
            this.rho = Arrays.Clone(rho);
            this.t1 = Arrays.Clone(t1);
        }

        public byte[] GetEncoded()
        {
            return Arrays.Concatenate(rho, t1);
        }
        public byte[] GetRho()
        {
            return Arrays.Clone(rho);
        }
        public byte[] GetT1()
        {
            return Arrays.Clone(t1);
        }

    }
}