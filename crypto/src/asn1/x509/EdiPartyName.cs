using System;

using Org.BouncyCastle.Asn1.X500;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <remarks>
    /// <code>
    /// EDIPartyName ::= Sequence {
    ///     nameAssigner    [0] DirectoryString OPTIONAL,
    ///     partyName       [1] DirectoryString }
    /// </code>
    /// </remarks>
    public class EdiPartyName
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="EdiPartyName"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="EdiPartyName"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="EdiPartyName"/>, or null if <paramref name="obj"/> is null.</returns>
        public static EdiPartyName GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EdiPartyName ediPartyName)
                return ediPartyName;
            return new EdiPartyName(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="EdiPartyName"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="EdiPartyName"/>.</returns>
        public static EdiPartyName GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EdiPartyName(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DirectoryString m_nameAssigner;
        private readonly DirectoryString m_partyName;

        private EdiPartyName(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            // DirectoryString is a CHOICE type, so use explicit tagging despite IMPLICIT TAGS
            m_nameAssigner = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, DirectoryString.GetTagged);
            m_partyName = Asn1Utilities.ReadContextTagged(seq, ref pos, 1, true, DirectoryString.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="EdiPartyName"/>.</summary>
        /// <param name="nameAssigner">The name assigner.</param>
        /// <param name="partyName">The party name.</param>
        public EdiPartyName(DirectoryString nameAssigner, DirectoryString partyName)
        {
            m_nameAssigner = nameAssigner;
            m_partyName = partyName ?? throw new ArgumentNullException(nameof(partyName));
        }

        /// <summary>Gets the name assigner.</summary>
        public DirectoryString NameAssigner => m_nameAssigner;

        /// <summary>Gets the party name.</summary>
        public DirectoryString PartyName => m_partyName;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            // DirectoryString is a CHOICE type, so use explicit tagging despite IMPLICIT TAGS
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.AddOptionalTagged(true, 0, m_nameAssigner);
            v.AddTagged(true, 1, m_partyName);
            return new DerSequence(v);
        }
    }
}
