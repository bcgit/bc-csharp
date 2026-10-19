using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <summary>The IssuerSerial structure of RFC 5755.</summary>
    public class IssuerSerial
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="IssuerSerial"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="IssuerSerial"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="IssuerSerial"/>, or null if <paramref name="obj"/> is null.</returns>
        public static IssuerSerial GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is IssuerSerial issuerSerial)
                return issuerSerial;
            return new IssuerSerial(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="IssuerSerial"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="IssuerSerial"/>.</returns>
        public static IssuerSerial GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new IssuerSerial(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="IssuerSerial"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="IssuerSerial"/>, or null if <paramref name="element"/> is null.</returns>
        public static IssuerSerial GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is IssuerSerial issuerSerial)
                return issuerSerial;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new IssuerSerial(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="IssuerSerial"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="IssuerSerial"/>.</returns>
        public static IssuerSerial GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new IssuerSerial(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly GeneralNames m_issuer;
        private readonly DerInteger m_serial;
        private readonly DerBitString m_issuerUid;

        private IssuerSerial(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_issuer = Asn1Utilities.Read(seq, ref pos, GeneralNames.GetInstance);
            m_serial = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_issuerUid = Asn1Utilities.ReadOptional(seq, ref pos, DerBitString.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="IssuerSerial"/>.</summary>
        /// <param name="issuer">The issuer.</param>
        /// <param name="serial">The serial.</param>
        public IssuerSerial(X509Name issuer, DerInteger serial)
            : this(new GeneralNames(new GeneralName(issuer)), serial)
        {
        }

        /// <summary>Create a new <see cref="IssuerSerial"/>.</summary>
        /// <param name="issuer">The issuer.</param>
        /// <param name="serial">The serial.</param>
        public IssuerSerial(GeneralNames issuer, DerInteger serial)
            : this(issuer, serial, issuerUid: null)
        {
        }

        /// <summary>Create a new <see cref="IssuerSerial"/>.</summary>
        /// <param name="issuer">The issuer.</param>
        /// <param name="serial">The serial.</param>
        /// <param name="issuerUid">The issuer uid.</param>
        public IssuerSerial(GeneralNames issuer, DerInteger serial, DerBitString issuerUid)
        {
            m_issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
            m_serial = serial ?? throw new ArgumentNullException(nameof(serial));
            m_issuerUid = issuerUid;
        }

        /// <summary>Gets the issuer.</summary>
        public GeneralNames Issuer => m_issuer;

        /// <summary>Gets the serial.</summary>
        public DerInteger Serial => m_serial;

        /// <summary>Gets the issuer uid.</summary>
        public DerBitString IssuerUid => m_issuerUid;

        /// <summary>Produce an object suitable for an <see cref="Asn1OutputStream"/>.</summary>
        /// <remarks>
        /// <code>
        /// IssuerSerial ::= Sequence {
        ///     issuer      GeneralNames,
        ///     serial      CertificateSerialNumber,
        ///     issuerUid   UniqueIdentifier OPTIONAL
        /// }
        /// </code>
        /// </remarks>
        public override Asn1Object ToAsn1Object()
        {
            return m_issuerUid == null
                ? new DerSequence(m_issuer, m_serial)
                : new DerSequence(m_issuer, m_serial, m_issuerUid);
        }
    }
}
