using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Text;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    public class BikeKeyGenerationParameters : KeyGenerationParameters
    {
        private BikeParameters param;

        public BikeKeyGenerationParameters(
                SecureRandom random,
                BikeParameters param) : base(random, 256)
        {
            this.param = param;
        }

        public BikeParameters Parameters => param;
    }
}
