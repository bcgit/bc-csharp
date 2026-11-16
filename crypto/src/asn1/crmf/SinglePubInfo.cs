using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
    /// <summary>The SinglePubInfo structure of RFC 4211: where a certificate is to be published.</summary>
    public class SinglePubInfo
        : Asn1Encodable
    {
        public static readonly DerInteger dontCare = DerInteger.ValueOf(0);
        public static readonly DerInteger x500 = DerInteger.ValueOf(1);
        public static readonly DerInteger web = DerInteger.ValueOf(2);
        public static readonly DerInteger ldap = DerInteger.ValueOf(3);

        /// <summary>Return an <see cref="SinglePubInfo"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="SinglePubInfo"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="SinglePubInfo"/>, or null if <paramref name="obj"/> is null.</returns>
        public static SinglePubInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SinglePubInfo singlePubInfo)
                return singlePubInfo;
            return new SinglePubInfo(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="SinglePubInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SinglePubInfo"/>.</returns>
        public static SinglePubInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SinglePubInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="SinglePubInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SinglePubInfo"/>.</returns>
        public static SinglePubInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SinglePubInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_pubMethod;
        private readonly GeneralName m_pubLocation;

        private SinglePubInfo(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_pubMethod = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);

            if (pos < count)
            {
                m_pubLocation = Asn1Utilities.Read(seq, ref pos, GeneralName.GetInstance);
            }

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public SinglePubInfo(DerInteger pubMethod, GeneralName pubLocation)
        {
            m_pubMethod = pubMethod ?? throw new ArgumentNullException(nameof(pubMethod));
            m_pubLocation = pubLocation;
        }

        /// <summary>Gets the pub location.</summary>
        public virtual GeneralName PubLocation => m_pubLocation;

        /// <remarks>
        /// <code>
        /// SinglePubInfo::= SEQUENCE {
        ///     pubMethod INTEGER {
        ///         dontCare(0),
        ///         x500(1),
        ///         web(2),
        ///         ldap(3)
        ///     },
        ///     pubLocation GeneralName OPTIONAL
        /// }
        /// </code>
        /// </remarks>
        public override Asn1Object ToAsn1Object()
        {
            return m_pubLocation == null
                ?  new DerSequence(m_pubMethod)
                :  new DerSequence(m_pubMethod, m_pubLocation);
        }
    }
}
