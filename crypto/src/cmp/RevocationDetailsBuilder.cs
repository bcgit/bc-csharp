using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Cmp
{
    public sealed class RevocationDetailsBuilder
    {
        private readonly CertTemplateBuilder m_templateBuilder = new CertTemplateBuilder();

        public RevocationDetailsBuilder SetPublicKey(SubjectPublicKeyInfo publicKey)
        {
            if (publicKey != null)
            {
                m_templateBuilder.SetPublicKey(publicKey);
            }

            return this;
        }

        public RevocationDetailsBuilder SetIssuer(X509Name issuer)
        {
            if (issuer != null)
            {
                m_templateBuilder.SetIssuer(issuer);
            }

            return this;
        }

        public RevocationDetailsBuilder SetSerialNumber(BigInteger serialNumber)
        {
            if (serialNumber != null)
            {
                m_templateBuilder.SetSerialNumber(new DerInteger(serialNumber));
            }

            return this;
        }

        public RevocationDetailsBuilder SetSubject(X509Name subject)
        {
            if (subject != null)
            {
                m_templateBuilder.SetSubject(subject);
            }

            return this;
        }

        public RevocationDetails Build()
        {
            return new RevocationDetails(new RevDetails(m_templateBuilder.Build()));
        }
    }
}