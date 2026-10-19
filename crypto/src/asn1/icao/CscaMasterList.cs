using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Icao
{
    /**
     * The CscaMasterList object. This object can be wrapped in a
     * CMSSignedData to be published in LDAP.
     *
     * <pre>
     * CscaMasterList ::= SEQUENCE {
     *   version                CscaMasterListVersion,
     *   certList               SET OF Certificate }
     *
     * CscaMasterListVersion :: INTEGER {v0(0)}
     * </pre>
     */
    public class CscaMasterList
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CscaMasterList"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CscaMasterList"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CscaMasterList"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CscaMasterList GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CscaMasterList cscaMasterList)
                return cscaMasterList;
            return new CscaMasterList(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CscaMasterList"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CscaMasterList"/>.</returns>
        public static CscaMasterList GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CscaMasterList(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CscaMasterList"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CscaMasterList"/>.</returns>
        public static CscaMasterList GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CscaMasterList(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_version;
        private readonly X509CertificateStructure[] m_certList;

        private CscaMasterList(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_certList = Asn1Utilities.Read(seq, ref pos, Asn1Set.GetInstance).MapElements(X509CertificateStructure.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="CscaMasterList"/>.</summary>
        /// <param name="certStructs">The cert structs.</param>
        public CscaMasterList(X509CertificateStructure[] certStructs)
        {
            m_version = DerInteger.Zero;
            m_certList = CopyCertList(certStructs);
        }

        /// <summary>Gets the version.</summary>
        public virtual int Version => m_version.IntValueExact;

        /// <summary>Return the cert structs.</summary>
        public X509CertificateStructure[] GetCertStructs() => CopyCertList(m_certList);

        private static X509CertificateStructure[] CopyCertList(X509CertificateStructure[] orig) =>
            (X509CertificateStructure[])orig.Clone();

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_version, new DerSet(m_certList));
    }
}
