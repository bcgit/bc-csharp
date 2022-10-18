using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Sike;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Text;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    public sealed class BikeKemExtractor
        : IEncapsulatedSecretExtractor
    {
        private readonly BikeKeyParameters key;

        public BikeKemExtractor(BikePrivateKeyParameters privParams)
        {
            this.key = privParams;
        }

        public byte[] ExtractSecret(byte[] encapsulation)
        {
            BikeParameters parameters = key.Parameters;
            BikeEngine engine = parameters.BikeEngine;
            int defaultKeySize = parameters.DefaultKeySize;

            byte[] session_key = new byte[engine.SessionKeySize];
            BikePrivateKeyParameters secretKey = (BikePrivateKeyParameters)key;

            // Extract c0, c1 from encapsulation c
            byte[] c0 = Arrays.CopyOfRange(encapsulation, 0, secretKey.Parameters.RByte);
            byte[] c1 = Arrays.CopyOfRange(encapsulation, secretKey.Parameters.RByte, encapsulation.Length);

            byte[] h0 = secretKey.GetH0();
            byte[] h1 = secretKey.GetH1();
            byte[] sigma = secretKey.GetSigma();

            engine.Decaps(session_key, h0, h1, sigma, c0, c1);
            return Arrays.CopyOfRange(session_key, 0, defaultKeySize / 8);
        }

        public int EncapsulationLength => key.Parameters.RByte + key.Parameters.LByte;
    }
}
