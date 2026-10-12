using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crmf
{
    /// <summary>
    /// Carrier for a publication information control, saying whether and where the CA should publish the certificate it
    /// issues - RFC 4211 sec. 6.3.
    /// </summary>
    public class PkiPublicationInfoControl
        : IControl
    {
        /// <summary>
        /// Return a control asking the CA not to publish the certificate.
        /// </summary>
        /// <returns>A control carrying the dontPublish action.</returns>
        public static PkiPublicationInfoControl DontPublish() =>
            new PkiPublicationInfoControl(new PkiPublicationInfo(PkiPublicationInfo.DontPublish));

        private readonly PkiPublicationInfo m_publicationInfo;

        /// <summary>
        /// Basic constructor - build from the publication information to use.
        /// </summary>
        /// <param name="publicationInfo">The publication information for the certificate.</param>
        public PkiPublicationInfoControl(PkiPublicationInfo publicationInfo)
        {
            m_publicationInfo = publicationInfo ?? throw new ArgumentNullException(nameof(publicationInfo));
        }

        /// <summary>
        /// Basic constructor - build from the locations the certificate is to be published at, which asks for
        /// publication(pleasePublish). A null or empty array asks for publication without saying where("dontCare"); use
        /// <see cref="DontPublish"/> to ask for none.
        /// </summary>
        /// <param name="pubInfos">The locations to publish the certificate at.</param>
        public PkiPublicationInfoControl(SinglePubInfo[] pubInfos)
            : this(new PkiPublicationInfo(Arrays.IsNullOrEmpty(pubInfos) ? null : pubInfos))
        {
        }

        /// <summary>Return the type of this control.</summary>
        /// <returns><see cref="CrmfObjectIdentifiers.id_regCtrl_pkiPublicationInfo"/>.</returns>
        public DerObjectIdentifier Type => CrmfObjectIdentifiers.id_regCtrl_pkiPublicationInfo;

        /// <summary>Return the publication information associated with this control.</summary>
        /// <returns>A <see cref="PkiPublicationInfo"/> structure.</returns>
        public Asn1Encodable Value => m_publicationInfo;

        /// <summary>Return the publication information associated with this control.</summary>
        /// <returns>A <see cref="PkiPublicationInfo"/> structure.</returns>
        public PkiPublicationInfo PublicationInfo => m_publicationInfo;
    }
}
