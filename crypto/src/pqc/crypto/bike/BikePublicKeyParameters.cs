using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    public sealed class BikePublicKeyParameters
        : BikeKeyParameters
    {
        private readonly byte[] publicKey;

        /**
         * Constructor.
         *
         * @param publicKey      byte
         */
        public BikePublicKeyParameters(BikeParameters param, byte[] publicKey)
            : base(false, param)
        {
            this.publicKey = Arrays.Clone(publicKey);
        }

        internal byte[] PublicKey => publicKey;

        public byte[] GetEncoded()
        {
            return Arrays.Clone(publicKey);
        }
    }
}
