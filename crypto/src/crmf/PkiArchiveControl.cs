using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Cms;

namespace Org.BouncyCastle.Crmf
{
    public class PkiArchiveControl
        : IControl
    {
        public static readonly int encryptedPrivKey = PkiArchiveOptions.encryptedPrivKey;
        public static readonly int keyGenParameters = PkiArchiveOptions.keyGenParameters;
        public static readonly int archiveRemGenPrivKey = PkiArchiveOptions.archiveRemGenPrivKey;

        private readonly PkiArchiveOptions m_pkiArchiveOptions;

        /// <summary>
        /// Basic constructor - build from an PKIArchiveOptions structure.
        /// </summary>
        /// <param name="pkiArchiveOptions">the ASN.1 structure that will underlie this control.</param>
        public PkiArchiveControl(PkiArchiveOptions pkiArchiveOptions)
        {
            m_pkiArchiveOptions = pkiArchiveOptions;
        }

        /// <summary>
        /// Return the type of this control.
        /// </summary>
        /// <returns>CRMFObjectIdentifiers.id_regCtrl_pkiArchiveOptions</returns>
        public DerObjectIdentifier Type => CrmfObjectIdentifiers.id_regCtrl_pkiArchiveOptions;

        /// <summary>
        /// Return the underlying ASN.1 object.
        /// </summary>
        /// <returns>a PKIArchiveOptions structure.</returns>    
        public Asn1Encodable Value => m_pkiArchiveOptions;

        /// <summary>
        /// Return the archive control type, one of: encryptedPrivKey,keyGenParameters,or archiveRemGenPrivKey.
        /// </summary>
        /// <returns>the archive control type.</returns>
        public int ArchiveType => m_pkiArchiveOptions.Type;

        /// <summary>
        /// Return whether this control contains enveloped data.
        /// </summary>
        /// <returns>true if the control contains enveloped data, false otherwise.</returns>
        [Obsolete("Use 'IsEnvelopedData' instead")]
        public bool EnvelopedData => IsEnvelopedData();

        /// <summary>
        /// Return whether this control contains enveloped data.
        /// </summary>
        /// <returns>true if the control contains enveloped data, false otherwise.</returns>
        public bool IsEnvelopedData()
        {
            EncryptedKey encKey = EncryptedKey.GetInstance(m_pkiArchiveOptions.Value);
            return !encKey.IsEncryptedValue;
        }

        /// <summary>
        /// Return the enveloped data structure contained in this control.
        /// </summary>
        /// <returns>a CMSEnvelopedData object.</returns>
        public CmsEnvelopedData GetEnvelopedData()
        {
            try
            {
                EncryptedKey encKey = EncryptedKey.GetInstance(m_pkiArchiveOptions.Value);
                EnvelopedData data = Asn1.Cms.EnvelopedData.GetInstance(encKey.Value);

                return new CmsEnvelopedData(new ContentInfo(CmsObjectIdentifiers.EnvelopedData, data));
            }
            catch (CmsException e)
            {
                throw new CrmfException("CMS parsing error: " + e.Message, e);
            }
            catch (Exception e)
            {
                throw new CrmfException("CRMF parsing error: " + e.Message, e);
            }
        }
    }
}
