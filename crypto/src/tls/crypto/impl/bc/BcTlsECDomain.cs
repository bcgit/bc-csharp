using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /**
     * EC domain class for generating key pairs and performing key agreement.
     */
    // TODO[api] Make sealed
    public class BcTlsECDomain
        : TlsECDomain
    {
        /// <summary>Calculate the ECDH agreement value.</summary>
        /// <param name="crypto">The crypto.</param>
        /// <param name="privateKey">The private key.</param>
        /// <param name="publicKey">The public key of the peer.</param>
        /// <returns>The agreement value as a secret.</returns>
        public static BcTlsSecret CalculateECDHAgreement(BcTlsCrypto crypto, ECPrivateKeyParameters privateKey,
            ECPublicKeyParameters publicKey)
        {
            /*
             * RFC 4492 5.10. Note that this octet string (Z in IEEE 1363 terminology) as output by
             * FE2OSP, the Field Element to Octet String Conversion Primitive, has constant length for
             * any given field; leading zeros found in this octet string MUST NOT be truncated.
             */
            var agreement = new ECDHRawAgreement();
            agreement.Init(privateKey);
            byte[] secret = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(publicKey, secret, 0);
            return crypto.AdoptLocalSecret(secret);
        }

        /// <summary>Get the elliptic curve domain parameters for a configuration or a named group.</summary>
        /// <param name="ecConfig">The configuration.</param>
        /// <returns>The parameters.</returns>
        public static ECDomainParameters GetDomainParameters(TlsECConfig ecConfig)
        {
            return GetDomainParameters(ecConfig.NamedGroup) ??
                throw new ArgumentException("No EC configuration provided", nameof(ecConfig));
        }

        /// <summary>Get the elliptic curve domain parameters for a configuration or a named group.</summary>
        /// <param name="namedGroup">The named group.</param>
        /// <returns>The parameters.</returns>
        public static ECDomainParameters GetDomainParameters(int namedGroup)
        {
            if (!NamedGroup.RefersToASpecificCurve(namedGroup))
                return null;

            // Parameters are lazily created the first time a particular curve is accessed

            string curveName = NamedGroup.GetCurveName(namedGroup);

            return ECDomainParameters.LookupName(curveName);
        }

        /// <summary>The crypto.</summary>
        protected readonly BcTlsCrypto m_crypto;
        /// <summary>The config.</summary>
        // TODO[api] Remove
        protected readonly TlsECConfig m_config;
        /// <summary>The domain parameters.</summary>
        protected readonly ECDomainParameters m_domainParameters;

        /// <summary>Create a new <see cref="BcTlsECDomain"/>.</summary>
        /// <param name="crypto">The crypto.</param>
        /// <param name="ecConfig">The ec config.</param>
        public BcTlsECDomain(BcTlsCrypto crypto, TlsECConfig ecConfig)
        {
            m_crypto = crypto;
            m_config = ecConfig;
            m_domainParameters = GetDomainParameters(ecConfig);
        }

        /// <summary>Calculate the ECDH agreement value.</summary>
        /// <param name="privateKey">The private key.</param>
        /// <param name="publicKey">The public key of the peer.</param>
        /// <returns>The agreement value as a secret.</returns>
        public virtual BcTlsSecret CalculateECDHAgreement(ECPrivateKeyParameters privateKey,
            ECPublicKeyParameters publicKey)
        {
            return CalculateECDHAgreement(m_crypto, privateKey, publicKey);
        }

        /// <inheritdoc/>
        public virtual TlsAgreement CreateECDH()
        {
            return new BcTlsECDH(this);
        }

        /// <summary>Decode a point.</summary>
        /// <param name="encoding">The encoding.</param>
        /// <returns>The point.</returns>
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

        /// <summary>Encode a point in uncompressed form.</summary>
        /// <param name="point">The point.</param>
        /// <returns>The encoding.</returns>
        public virtual byte[] EncodePoint(ECPoint point)
        {
            return point.GetEncoded(false);
        }

        /// <summary>Encode an EC public key.</summary>
        /// <param name="publicKey">The public key.</param>
        /// <returns>The encoding.</returns>
        public virtual byte[] EncodePublicKey(ECPublicKeyParameters publicKey)
        {
            return EncodePoint(publicKey.Q);
        }

        /// <summary>Generate an EC key pair.</summary>
        /// <returns>The key pair.</returns>
        public virtual AsymmetricCipherKeyPair GenerateKeyPair()
        {
            ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
            keyPairGenerator.Init(new ECKeyGenerationParameters(m_domainParameters, m_crypto.SecureRandom));
            return keyPairGenerator.GenerateKeyPair();
        }
    }
}
