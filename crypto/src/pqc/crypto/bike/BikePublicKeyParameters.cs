using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Text;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    public class BikePublicKeyParameters : BikeKeyParameters
    {
        byte[] publicKey;

        /**
         * Constructor.
         *
         * @param publicKey      byte
         */
        public BikePublicKeyParameters(BikeParameters param, byte[] publicKey) : base(false, param)
        {
            this.publicKey = Arrays.Clone(publicKey);
        }

       public byte[] PublicKey => Arrays.Clone(publicKey);
        public byte[] GetEncoded()
        {
            return PublicKey;
        }
    }
}
