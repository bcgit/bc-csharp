using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Text;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    public class BikePrivateKeyParameters : BikeKeyParameters
    {
        // h0
        private byte[] h0;

        // h1
        private byte[] h1;

        // sigma
        private byte[] sigma;

        /**
         * Constructor.
         *
         * @param h0    h0
         * @param h1    h1
         * @param sigma random bytes sigma
         */
        public BikePrivateKeyParameters(BikeParameters bikeParameters, byte[] h0, byte[] h1, byte[] sigma) : base(true, bikeParameters)
        {
            this.h0 = Arrays.Clone(h0);
            this.h1 = Arrays.Clone(h1);
            this.sigma = Arrays.Clone(sigma);
        }

        public byte[] GetH0()
        {
            return h0;
        }

        public byte[] GetH1()
        {
            return h1;
        }

        public byte[] GetSigma()
        {
            return sigma;
        }

        public byte[] PrivateKey => Arrays.Concatenate(Arrays.Concatenate(h0, h1), sigma);

        public byte[] GetEncoded()
        {
            return PrivateKey;
        }
    }
}
