using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Agreement
{
    /**
     * P1363 7.2.2 ECSVDP-DHC
     *
     * ECSVDP-DHC is Elliptic Curve Secret Value Derivation Primitive,
     * Diffie-Hellman version with cofactor multiplication. It is based on
     * the work of [DH76], [Mil86], [Kob87], [LMQ98] and [Kal98a]. This
     * primitive derives a shared secret value from one party's private key
     * and another party's public key, where both have the same set of EC
     * domain parameters. If two parties correctly execute this primitive,
     * they will produce the same output. This primitive can be invoked by a
     * scheme to derive a shared secret key; specifically, it may be used
     * with the schemes ECKAS-DH1 and DL/ECKAS-DH2. It does not assume the
     * validity of the input public key (see also Section 7.2.1).
     * <p>
     * Note: As stated P1363 compatibility mode with ECDH can be preset, and
     * in this case the implementation doesn't have a ECDH compatibility mode
     * (if you want that just use ECDHBasicAgreement and note they both implement
     * BasicAgreement!).</p>
     */
    // TODO[api] sealed, rename to ECDhcBasicAgreement
    public class ECDHCBasicAgreement
        : IBasicAgreement
    {
        private ECPrivateKeyParameters m_privateKey;

        public virtual void Init(ICipherParameters parameters)
        {
            var kParam = ParameterUtilities.IgnoreRandom(parameters);

            if (!(kParam is ECPrivateKeyParameters ecPrivateKeyParameters))
                throw new ArgumentException($"{nameof(ECDHCBasicAgreement)} expects {nameof(ECPrivateKeyParameters)}");

            m_privateKey = ecPrivateKeyParameters;
        }

        public virtual int GetFieldSize() => m_privateKey.Parameters.Curve.FieldElementEncodingLength;

        public virtual BigInteger CalculateAgreement(ICipherParameters pubKey) =>
            CalculateAgreementFieldElement(m_privateKey, (ECPublicKeyParameters)pubKey).ToBigInteger();

        internal static ECFieldElement CalculateAgreementFieldElement(ECPrivateKeyParameters privateKey,
            ECPublicKeyParameters publicKey)
        {
            ECDomainParameters dp = privateKey.Parameters;
            if (!dp.Equals(publicKey.Parameters))
                throw new InvalidOperationException("ECDHC public key has wrong domain parameters");

            BigInteger hd = dp.H.Multiply(privateKey.D).Mod(dp.N);

            // Always perform calculations on the exact curve specified by our private key's parameters
            ECPoint pubPoint = ECAlgorithms.CleanPoint(dp.Curve, publicKey.Q);
            if (pubPoint.IsInfinity)
                throw new InvalidOperationException("Infinity is not a valid public key for ECDHC");

            ECPoint P = pubPoint.Multiply(hd).Normalize();
            if (P.IsInfinity)
                throw new InvalidOperationException("Infinity is not a valid agreement value for ECDHC");

            return P.AffineXCoord;
        }
    }
}
