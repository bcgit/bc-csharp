using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.pqc.crypto.NtruP
{
    public class NtruPKeyParameters : AsymmetricKeyParameter
    {
        private NtruPParameters _pParameters;
        
        public NtruPKeyParameters(bool isPrivate, NtruPParameters pParameters) : base(isPrivate)
        {
            this._pParameters = pParameters;
        }

        public NtruPParameters PParameters => _pParameters;

    }
}