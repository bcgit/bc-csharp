using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    public class HqcKeyParameters : AsymmetricKeyParameter
    {
        private HqcParameters param;

        public HqcKeyParameters(
            bool isPrivate,
            HqcParameters param) : base(isPrivate)
        {
            this.param = param;
        }

        public HqcParameters Parameters => param;
       
    }
}
