using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    public abstract class BikeKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly BikeParameters m_parameters;

        internal BikeKeyParameters(bool isPrivate, BikeParameters parameters)
            : base(isPrivate)
        {
            this.m_parameters = parameters;
        }

        /// <summary>Gets the parameters.</summary>
        public BikeParameters Parameters => m_parameters;
    }
}
