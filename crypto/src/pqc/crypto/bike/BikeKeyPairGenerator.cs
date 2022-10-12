using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Text;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    public class BikeKeyPairGenerator : IAsymmetricCipherKeyPairGenerator
    {
        private SecureRandom random;

        // block length
        private int r;

        // the row weight
        private int w;

        // Hamming weight of h0, h1
        private int hw;

        // the error weight
        private int t;

        //the shared secret size
        private int l;

        // number of iterations in BGF decoder
        private int nbIter;

        // tau
        private int tau;
        private int L_BYTE;
        private int R_BYTE;

        private BikeKeyGenerationParameters bikeKeyGenerationParameters;
        public void Init(KeyGenerationParameters param)
        {
            this.bikeKeyGenerationParameters = (BikeKeyGenerationParameters)param;
            this.random = param.Random;

            // get parameters
            this.r = this.bikeKeyGenerationParameters.Parameters.R;
            this.w = this.bikeKeyGenerationParameters.Parameters.W;
            this.l = this.bikeKeyGenerationParameters.Parameters.L;
            this.t = this.bikeKeyGenerationParameters.Parameters.T;
            this.nbIter = this.bikeKeyGenerationParameters.Parameters.NbIter;
            this.tau = this.bikeKeyGenerationParameters.Parameters.Tau;
            this.hw = w / 2;
            this.L_BYTE = l / 8;
            this.R_BYTE = (r + 7) / 8;
        }

        private AsymmetricCipherKeyPair GenKeyPair()
        {
            BikeEngine engine = bikeKeyGenerationParameters.Parameters.BIKEEngine;
            byte[] h0 = new byte[R_BYTE];
            byte[] h1 = new byte[R_BYTE];
            byte[] h = new byte[R_BYTE];
            byte[] sigma = new byte[L_BYTE];

            engine.GenKeyPair(h0, h1, sigma, h, random);

            // form keys
            BikePublicKeyParameters publicKey = new BikePublicKeyParameters(bikeKeyGenerationParameters.Parameters, h);
            BikePrivateKeyParameters privateKey = new BikePrivateKeyParameters(bikeKeyGenerationParameters.Parameters, h0, h1, sigma);

            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            return GenKeyPair();
        }
    }
}
