using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Misc
{
    /// <summary>The parameters of IDEA in CBC mode: an optional initialization vector.</summary>
    public class IdeaCbcPar
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="IdeaCbcPar"/> from the given object.</summary>
        /// <param name="o">An <see cref="IdeaCbcPar"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="IdeaCbcPar"/>, or null if <paramref name="o"/> is null.</returns>
        public static IdeaCbcPar GetInstance(object o)
        {
            if (o == null)
                return null;
            if (o is IdeaCbcPar ideaCbcPar)
                return ideaCbcPar;
            return new IdeaCbcPar(Asn1Sequence.GetInstance(o));
        }

        /// <summary>Return an <see cref="IdeaCbcPar"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="IdeaCbcPar"/>.</returns>
        public static IdeaCbcPar GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new IdeaCbcPar(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="IdeaCbcPar"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="IdeaCbcPar"/>.</returns>
        public static IdeaCbcPar GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new IdeaCbcPar(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_iv;

        private IdeaCbcPar(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 0 || count > 1)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_iv = Asn1Utilities.ReadOptional(seq, ref pos, Asn1OctetString.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="IdeaCbcPar"/>.</summary>
        public IdeaCbcPar()
            : this(iv: null)
        {
        }

        /// <summary>Create a new <see cref="IdeaCbcPar"/>.</summary>
        /// <param name="iv">The initialization vector.</param>
        public IdeaCbcPar(byte[] iv)
        {
            m_iv = DerOctetString.FromContentsOptional(iv);
        }

        /// <summary>Gets the IV.</summary>
        public Asn1OctetString IV => m_iv;

        /// <summary>Return the IV.</summary>
        public byte[] GetIV() => Arrays.Clone(m_iv?.GetOctets());

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * IDEA-CBCPar ::= Sequence {
         *                      iv    OCTET STRING OPTIONAL -- exactly 8 octets
         *                  }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            return m_iv == null
                ?  DerSequence.Empty
                :  new DerSequence(m_iv);
        }
    }
}
