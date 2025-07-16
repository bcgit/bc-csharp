using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /**
     * EC domain class for generating key pairs and performing key agreement.
     */
    // TODO[api] Make sealed
    public class BcTlsECDomain
        : TlsECDomain
    {
        public static BcTlsSecret CalculateECDHAgreement(BcTlsCrypto crypto, ECPrivateKeyParameters privateKey,
            ECPublicKeyParameters publicKey)
        {
            ECDHBasicAgreement basicAgreement = new ECDHBasicAgreement();
            basicAgreement.Init(privateKey);
            BigInteger agreementValue = basicAgreement.CalculateAgreement(publicKey);

            /*
             * RFC 4492 5.10. Note that this octet string (Z in IEEE 1363 terminology) as output by
             * FE2OSP, the Field Element to Octet String Conversion Primitive, has constant length for
             * any given field; leading zeros found in this octet string MUST NOT be truncated.
             */
            byte[] secret = BigIntegers.AsUnsignedByteArray(basicAgreement.GetFieldSize(), agreementValue);
            return crypto.AdoptLocalSecret(secret);
        }

        public static ECDomainParameters GetDomainParameters(TlsECConfig ecConfig)
        {
            return GetDomainParameters(ecConfig.NamedGroup) ??
                throw new ArgumentException("No EC configuration provided", nameof(ecConfig));
        }

        public static ECDomainParameters GetDomainParameters(int namedGroup)
        {
            if (!NamedGroup.RefersToASpecificCurve(namedGroup))
                return null;

            // Parameters are lazily created the first time a particular curve is accessed

            string curveName = NamedGroup.GetCurveName(namedGroup);

            return ECDomainParameters.LookupName(curveName);
        }

        protected readonly BcTlsCrypto m_crypto;
        // TODO[api] Remove
        protected readonly TlsECConfig m_config;
        protected readonly ECDomainParameters m_domainParameters;

        public BcTlsECDomain(BcTlsCrypto crypto, TlsECConfig ecConfig)
        {
            m_crypto = crypto;
            m_config = ecConfig;
            m_domainParameters = GetDomainParameters(ecConfig);
        }

        public virtual BcTlsSecret CalculateECDHAgreement(ECPrivateKeyParameters privateKey,
            ECPublicKeyParameters publicKey)
        {
            return CalculateECDHAgreement(m_crypto, privateKey, publicKey);
        }

        public virtual TlsAgreement CreateECDH()
        {
            return new BcTlsECDH(this);
        }

        public virtual ECPoint DecodePoint(byte[] encoding)
        {
            return m_domainParameters.Curve.DecodePoint(encoding);
        }

        /// <exception cref="IOException"/>
        public virtual ECPublicKeyParameters DecodePublicKey(byte[] encoding)
        {
            try
            {
                ECPoint point = DecodePoint(encoding);

                return new ECPublicKeyParameters(point, m_domainParameters);
            }
            catch (IOException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
            }
        }

        public virtual byte[] EncodePoint(ECPoint point)
        {
            return point.GetEncoded(false);
        }

        public virtual byte[] EncodePublicKey(ECPublicKeyParameters publicKey)
        {
            return EncodePoint(publicKey.Q);
        }

        public virtual AsymmetricCipherKeyPair GenerateKeyPair()
        {
            ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
            keyPairGenerator.Init(new ECKeyGenerationParameters(m_domainParameters, m_crypto.SecureRandom));
            return keyPairGenerator.GenerateKeyPair();
        }
    }
}
