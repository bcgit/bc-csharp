using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Cms;

namespace Org.BouncyCastle.Crmf
{
    public class PkiArchiveControl:IControl
    {
        public static readonly int encryptedPrivKey = PkiArchiveOptions.encryptedPrivKey;
        public static readonly int keyGenParameters = PkiArchiveOptions.keyGenParameters;
        public static readonly int archiveRemGenPrivKey = PkiArchiveOptions.archiveRemGenPrivKey;

        private static readonly DerObjectIdentifier type = CrmfObjectIdentifiers.id_regCtrl_pkiArchiveOptions;

        private readonly PkiArchiveOptions pkiArchiveOptions;

        public PkiArchiveControl(PkiArchiveOptions pkiArchiveOptions)
        {
            this.pkiArchiveOptions = pkiArchiveOptions;
        }

        public DerObjectIdentifier Type
        {
            get { return type; }
        }

        public Asn1Encodable Value
        {
            get { return pkiArchiveOptions; }
        }

        public int ArchiveType
        {
            get { return pkiArchiveOptions.Type; }
        }

        public bool EnvelopedData
        {
            get
            {
                EncryptedKey encKey = EncryptedKey.GetInstance(pkiArchiveOptions.Value);
                return !encKey.IsEncryptedValue;
            }
        }

        public CmsEnvelopedData GetEnvelopedData()
        {
            try
            {
                EncryptedKey encKey = EncryptedKey.GetInstance(pkiArchiveOptions.Value);
                EnvelopedData data = Org.BouncyCastle.Asn1.Cms.EnvelopedData.GetInstance(encKey.Value);

                return new CmsEnvelopedData(new ContentInfo(CmsObjectIdentifiers.EnvelopedData, data));
            }
            catch (CmsException e)
            {
                throw new CrmfException("CMS parsing error: " + e.Message, e);
            }
            catch (Exception e)
            {
                throw  new CrmfException("CRMF parsing error: "+e.Message, e);
            }
        }

    }
}
