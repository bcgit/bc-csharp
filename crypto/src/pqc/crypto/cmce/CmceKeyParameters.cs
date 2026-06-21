using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Cmce
{
    /// <summary>Base class for Classic McEliece public and private keys, carrying the parameter set.</summary>
    public abstract class CmceKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly CmceParameters parameters;

        internal CmceKeyParameters(bool isPrivate, CmceParameters parameters)
            : base(isPrivate)
        {
            this.parameters = parameters;
        }

        /// <summary>The Classic McEliece parameter set this key belongs to.</summary>
        public CmceParameters Parameters => parameters;
    }
}
