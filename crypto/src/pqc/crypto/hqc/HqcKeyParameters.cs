using Org.BouncyCastle.Crypto;

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
