using System;
using System.IO;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.IsisMtt.Ocsp
{
    /**
     * ISIS-MTT-Optional: The certificate requested by the client by inserting the
     * RetrieveIfAllowed extension in the request, will be returned in this
     * extension.
     * <p/>
     * ISIS-MTT-SigG: The signature act allows publishing certificates only then,
     * when the certificate owner gives his isExplicit permission. Accordingly, there
     * may be �nondownloadable� certificates, about which the responder must provide
     * status information, but MUST NOT include them in the response. Clients may
     * get therefore the following three kind of answers on a single request
     * including the RetrieveIfAllowed extension:
     * <ul>
     * <li> a) the responder supports the extension and is allowed to publish the
     * certificate: RequestedCertificate returned including the requested
     * certificate</li>
     * <li>b) the responder supports the extension but is NOT allowed to publish
     * the certificate: RequestedCertificate returned including an empty OCTET
     * STRING</li>
     * <li>c) the responder does not support the extension: RequestedCertificate is
     * not included in the response</li>
     * </ul>
     * Clients requesting RetrieveIfAllowed MUST be able to handle these cases. If
     * any of the OCTET STRING options is used, it MUST contain the DER encoding of
     * the requested certificate.
     * <p/>
     * <pre>
     *            RequestedCertificate ::= CHOICE {
     *              Certificate Certificate,
     *              publicKeyCertificate [0] EXPLICIT OCTET STRING,
     *              attributeCertificate [1] EXPLICIT OCTET STRING
     *            }
     * </pre>
     */
    public class RequestedCertificate
        : Asn1Encodable, IAsn1Choice
    {
        public enum Choice
        {
            Certificate = -1,
            PublicKeyCertificate = 0,
            AttributeCertificate = 1
        }

        public static RequestedCertificate GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        public static RequestedCertificate GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            Asn1Utilities.GetInstanceChoice(obj, isExplicit, GetInstance);

        public static RequestedCertificate GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is RequestedCertificate requestedCertificate)
                return requestedCertificate;

            X509CertificateStructure certificate = X509CertificateStructure.GetOptional(element);
            if (certificate != null)
                return new RequestedCertificate(certificate);

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                if (taggedObject.HasContextTag((int)Choice.PublicKeyCertificate) ||
                    taggedObject.HasContextTag((int)Choice.AttributeCertificate))
                {
                    return new RequestedCertificate(taggedObject);
                }
            }

            return null;
        }

        public static RequestedCertificate GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly X509CertificateStructure m_cert;
        private readonly Asn1OctetString m_publicKeyCert;
        private readonly Asn1OctetString m_attributeCert;

        private RequestedCertificate(Asn1TaggedObject tagged)
        {
            switch (tagged.TagNo)
            {
            case (int)Choice.AttributeCertificate:
                m_attributeCert = Asn1OctetString.GetInstance(tagged, true);
                break;
            case (int)Choice.PublicKeyCertificate:
                m_publicKeyCert = Asn1OctetString.GetInstance(tagged, true);
                break;
            default:
                throw new ArgumentException("unknown tag number: " + tagged.TagNo);
            }
        }

        /**
         * Constructor from a given details.
         * <p/>
         * Only one parameter can be given. All other must be <code>null</code>.
         *
         * @param certificate Given as Certificate
         */
        public RequestedCertificate(X509CertificateStructure certificate)
        {
            m_cert = certificate;
        }

        public RequestedCertificate(Choice type, byte[] certificateOctets)
            : this(new DerTaggedObject((int)type, DerOctetString.FromContents(certificateOctets)))
        {
        }

        public Choice Type
        {
            get
            {
                if (m_cert != null)
                    return Choice.Certificate;

                if (m_publicKeyCert != null)
                    return Choice.PublicKeyCertificate;

                return Choice.AttributeCertificate;
            }
        }

        public byte[] GetCertificateBytes()
        {
            if (m_cert != null)
            {
                try
                {
                    return m_cert.GetEncoded();
                }
                catch (IOException e)
                {
                    throw new InvalidOperationException("can't decode certificate: " + e);
                }
            }

            if (m_publicKeyCert != null)
                return m_publicKeyCert.GetOctets();

            return m_attributeCert.GetOctets();
        }

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <p/>
         * Returns:
         * <p/>
         * <pre>
         *            RequestedCertificate ::= CHOICE {
         *              Certificate Certificate,
         *              publicKeyCertificate [0] EXPLICIT OCTET STRING,
         *              attributeCertificate [1] EXPLICIT OCTET STRING
         *            }
         * </pre>
         *
         * @return an Asn1Object
         */
        public override Asn1Object ToAsn1Object()
        {
            if (m_publicKeyCert != null)
                return new DerTaggedObject(0, m_publicKeyCert);

            if (m_attributeCert != null)
                return new DerTaggedObject(1, m_attributeCert);

            return m_cert.ToAsn1Object();
        }
    }
}
