using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cms
{
    /**
    * <pre>
    * SignedData ::= SEQUENCE {
    *     version CMSVersion,
    *     digestAlgorithms DigestAlgorithmIdentifiers,
    *     encapContentInfo EncapsulatedContentInfo,
    *     certificates [0] IMPLICIT CertificateSet OPTIONAL,
    *     crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
    *     signerInfos SignerInfos
    *   }
    * </pre>
    */
    public class SignedDataParser
    {
        private readonly Asn1SequenceParser m_seq;
        private readonly DerInteger m_version;

        private object _nextObject;
        private bool _certsCalled;
        private bool _crlsCalled;

        /// <summary>Return an <see cref="SignedDataParser"/> from the given object.</summary>
        /// <param name="o">
        /// An <see cref="SignedDataParser"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="SignedDataParser"/>, or null if <paramref name="o"/> is null.</returns>
        public static SignedDataParser GetInstance(object o)
        {
            if (o is Asn1SequenceParser parser)
                return new SignedDataParser(parser);

            if (o is Asn1Sequence seq)
                return new SignedDataParser(seq.Parser);

            throw new IOException("unknown object encountered: " + Platform.GetTypeName(o));
        }

        /// <summary>Create a new <see cref="SignedDataParser"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        public SignedDataParser(Asn1SequenceParser seq)
        {
            m_seq = seq;
            m_version = (DerInteger)seq.ReadObject();
        }

        /// <summary>Gets the version.</summary>
        public DerInteger Version => m_version;

        /// <summary>Return the digest algorithms.</summary>
        public Asn1SetParser GetDigestAlgorithms()
        {
            return (Asn1SetParser)m_seq.ReadObject();
        }

        /// <summary>Return the encap content info.</summary>
        public ContentInfoParser GetEncapContentInfo()
        {
            return new ContentInfoParser((Asn1SequenceParser)m_seq.ReadObject());
        }

        /// <summary>Return the certificates.</summary>
        public Asn1SetParser GetCertificates()
        {
            _certsCalled = true;
            _nextObject = m_seq.ReadObject();

            if (_nextObject is Asn1TaggedObjectParser tagged && tagged.HasContextTag(0))
            {
                Asn1SetParser certs = (Asn1SetParser)tagged.ParseBaseUniversal(false, Asn1Tags.SetOf);
                _nextObject = null;
                return certs;
            }

            return null;
        }

        /// <summary>Return the crls.</summary>
        public Asn1SetParser GetCrls()
        {
            if (!_certsCalled)
                throw new IOException("GetCerts() has not been called.");

            _crlsCalled = true;

            if (_nextObject == null)
            {
                _nextObject = m_seq.ReadObject();
            }

            if (_nextObject is Asn1TaggedObjectParser tagged && tagged.HasContextTag(1))
            {
                Asn1SetParser crls = (Asn1SetParser)tagged.ParseBaseUniversal(false, Asn1Tags.SetOf);
                _nextObject = null;
                return crls;
            }

            return null;
        }

        /// <summary>Return the signer infos.</summary>
        public Asn1SetParser GetSignerInfos()
        {
            if (!_certsCalled || !_crlsCalled)
                throw new IOException("GetCerts() and/or GetCrls() has not been called.");

            if (_nextObject == null)
            {
                _nextObject = m_seq.ReadObject();
            }

            return (Asn1SetParser)_nextObject;
        }
    }
}
