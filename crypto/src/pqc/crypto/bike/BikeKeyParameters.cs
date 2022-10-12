using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Text;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    public class BikeKeyParameters : AsymmetricKeyParameter
    {
        private BikeParameters param;

        public BikeKeyParameters(
                bool isPrivate,
                BikeParameters param) : base(isPrivate)
        {
            this.param = param;
        }

        public BikeParameters Parameters => param;
    }
}
