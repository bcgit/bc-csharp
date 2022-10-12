using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Text;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    public class BikeKemExtractor : IEncapsulatedSecretExtractor
    {
        private BikeEngine engine;

        private BikeKeyParameters key;
        private int defaultKeySize; 

        public BikeKemExtractor(BikePrivateKeyParameters privParams)
        {
            this.key = privParams;
            initCipher(key.Parameters);
        }

        private void initCipher(BikeParameters param)
        {
            engine = param.BIKEEngine;
            defaultKeySize = param.DefaultKeySize;
        }

        public byte[] ExtractSecret(byte[] encapsulation)
        {
            byte[] session_key = new byte[engine.GetSessionKeySize()];
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
