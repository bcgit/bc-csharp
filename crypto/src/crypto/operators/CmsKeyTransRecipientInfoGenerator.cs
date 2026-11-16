using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Operators
{
    /// <deprecated>Use KeyTransRecipientInfoGenerator</deprecated>
    public class CmsKeyTransRecipientInfoGenerator
        : KeyTransRecipientInfoGenerator
    {
        /// <summary>Create a new <see cref="CmsKeyTransRecipientInfoGenerator"/>.</summary>
        /// <param name="recipCert">The recip cert.</param>
        /// <param name="keyWrapper">The key wrapper.</param>
        public CmsKeyTransRecipientInfoGenerator(X509Certificate recipCert, IKeyWrapper keyWrapper)
            : base(new Asn1.Cms.IssuerAndSerialNumber(recipCert.CertificateStructure), keyWrapper)
        {
        }

        /// <summary>Create a new <see cref="CmsKeyTransRecipientInfoGenerator"/>.</summary>
        /// <param name="issuerAndSerial">The issuer and serial.</param>
        /// <param name="keyWrapper">The key wrapper.</param>
        public CmsKeyTransRecipientInfoGenerator(IssuerAndSerialNumber issuerAndSerial, IKeyWrapper keyWrapper)
            : base(issuerAndSerial, keyWrapper)
        {
        }

        /// <summary>Create a new <see cref="CmsKeyTransRecipientInfoGenerator"/>.</summary>
        /// <param name="subjectKeyID">The subject key ID.</param>
        /// <param name="keyWrapper">The key wrapper.</param>
        public CmsKeyTransRecipientInfoGenerator(byte[] subjectKeyID, IKeyWrapper keyWrapper) : base(subjectKeyID, keyWrapper)
        {
        }
    }
}
