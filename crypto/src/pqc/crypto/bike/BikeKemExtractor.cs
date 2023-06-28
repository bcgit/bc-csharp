﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

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

            byte[] h0 = secretKey.m_h0;
            byte[] h1 = secretKey.m_h1;
            byte[] sigma = secretKey.m_sigma;

            engine.Decaps(session_key, h0, h1, sigma, c0, c1);
            return Arrays.CopyOfRange(session_key, 0, defaultKeySize / 8);
        }

        public int EncapsulationLength => key.Parameters.RByte + key.Parameters.LByte;
    }
}
