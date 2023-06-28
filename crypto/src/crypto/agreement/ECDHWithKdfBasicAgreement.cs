using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Agreement
{
    // TODO[api] sealed
    public class ECDHWithKdfBasicAgreement
		: ECDHBasicAgreement
	{
		private readonly string m_algorithm;
		private readonly IDerivationFunction m_kdf;

		public ECDHWithKdfBasicAgreement(string algorithm, IDerivationFunction kdf)
		{
			m_algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
			m_kdf = kdf ?? throw new ArgumentNullException(nameof(kdf));
		}

		public override BigInteger CalculateAgreement(ICipherParameters pubKey)
		{
			BigInteger result = base.CalculateAgreement(pubKey);

			return BasicAgreementWithKdf.CalculateAgreementWithKdf(m_algorithm, m_kdf, GetFieldSize(), result);
		}
	}
}
