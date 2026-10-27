using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cmp
{
    /// <summary>Builder for <see cref="RevocationDetails"/>.</summary>
    /// <remarks>Set the fields that identify the certificate to be revoked, then call <see cref="Build"/>.</remarks>
    public sealed class RevocationDetailsBuilder
    {
        private readonly CertTemplateBuilder m_templateBuilder = new CertTemplateBuilder();

        /// <summary>Set the public key of the certificate to be revoked.</summary>
        /// <param name="publicKey">The public key.</param>
        /// <returns>This builder.</returns>
        public RevocationDetailsBuilder SetPublicKey(AsymmetricKeyParameter publicKey) =>
            SetSubjectPublicKeyInfo(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey));

        /// <summary>Set the public key of the certificate to be revoked.</summary>
        /// <param name="publicKey">The public key.</param>
        /// <returns>This builder.</returns>
        [Obsolete("Use 'SetSubjectPublicKeyInfo' instead")]
        public RevocationDetailsBuilder SetPublicKey(SubjectPublicKeyInfo publicKey) =>
            SetSubjectPublicKeyInfo(spki: publicKey);

        /// <summary>Set the public key info of the certificate to be revoked; null is ignored.</summary>
        /// <param name="spki">The public key info.</param>
        /// <returns>This builder.</returns>
        public RevocationDetailsBuilder SetSubjectPublicKeyInfo(SubjectPublicKeyInfo spki)
        {
            if (spki != null)
            {
                m_templateBuilder.SetSubjectPublicKeyInfo(spki);
            }

            return this;
        }

        /// <summary>Set the issuer of the certificate to be revoked; null is ignored.</summary>
        /// <param name="issuer">The issuer name.</param>
        /// <returns>This builder.</returns>
        public RevocationDetailsBuilder SetIssuer(X509Name issuer)
        {
            if (issuer != null)
            {
                m_templateBuilder.SetIssuer(issuer);
            }

            return this;
        }

        /// <summary>Set the serial number of the certificate to be revoked; null is ignored.</summary>
        /// <param name="serialNumber">The serial number.</param>
        /// <returns>This builder.</returns>
        public RevocationDetailsBuilder SetSerialNumber(BigInteger serialNumber)
        {
            if (serialNumber != null)
            {
                m_templateBuilder.SetSerialNumber(new DerInteger(serialNumber));
            }

            return this;
        }

        /// <summary>Set the subject of the certificate to be revoked; null is ignored.</summary>
        /// <param name="subject">The subject name.</param>
        /// <returns>This builder.</returns>
        public RevocationDetailsBuilder SetSubject(X509Name subject)
        {
            if (subject != null)
            {
                m_templateBuilder.SetSubject(subject);
            }

            return this;
        }

        /// <summary>Build the revocation details.</summary>
        public RevocationDetails Build()
        {
            return new RevocationDetails(new RevDetails(m_templateBuilder.Build()));
        }
    }
}