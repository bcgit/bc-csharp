using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    public class HqcPublicKeyParameters : HqcKeyParameters
    {
        private byte[] pk;

        public HqcPublicKeyParameters(HqcParameters param, byte[] pk) : base(false, param)
        {
            this.pk = Arrays.Clone(pk);
        }

        public byte[] PublicKey => Arrays.Clone(pk);

        public byte[] GetEncoded()
        {
            return PublicKey;
        }
    }
}
