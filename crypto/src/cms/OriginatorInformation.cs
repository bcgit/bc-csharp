using System;

using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    public class OriginatorInformation
    {
        private readonly OriginatorInfo m_originatorInfo;

        public OriginatorInformation(OriginatorInfo originatorInfo)
        {
            m_originatorInfo = originatorInfo ?? throw new ArgumentNullException(nameof(originatorInfo));
        }

        /// <summary>Return the certificates stored in the underlying OriginatorInfo object.</summary>
        public virtual IStore<X509Certificate> GetCertificates() =>
            CmsSignedHelper.GetCertificates(m_originatorInfo.Certificates);

        /// <summary>Return the CRLs stored in the underlying OriginatorInfo object.</summary>
        public virtual IStore<X509Crl> GetCrls() => CmsSignedHelper.GetCrls(m_originatorInfo.Crls);

        /// <summary>Return the underlying ASN.1 object defining this OriginatorInformation object.</summary>
        public virtual OriginatorInfo ToAsn1Structure() => m_originatorInfo;
    }
}
