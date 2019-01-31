using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Operators
{
    public class CmsKeyTransRecipientInfoGenerator
        : KeyTransRecipientInfoGenerator
    {
        private readonly IKeyWrapper keyWrapper;

        public CmsKeyTransRecipientInfoGenerator(X509Certificate recipCert, IKeyWrapper keyWrapper)
            : base(new Asn1.Cms.IssuerAndSerialNumber(recipCert.IssuerDN, new DerInteger(recipCert.SerialNumber)))
        {
            this.keyWrapper = keyWrapper;
            this.RecipientCert = recipCert;
            this.RecipientPublicKey = recipCert.GetPublicKey();
        }

        public CmsKeyTransRecipientInfoGenerator(byte[] subjectKeyID, IKeyWrapper keyWrapper) : base(subjectKeyID)
        {
            this.keyWrapper = keyWrapper;
        }

        protected override AlgorithmIdentifier AlgorithmDetails
        {
            get { return (AlgorithmIdentifier)keyWrapper.AlgorithmDetails; }
        }

        protected override byte[] GenerateWrappedKey(Crypto.Parameters.KeyParameter contentKey)
        {
            return keyWrapper.Wrap(contentKey.GetKey()).Collect();
        }
    }
}
