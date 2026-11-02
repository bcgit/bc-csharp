using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Asn1
{
    /**
     * See https://datatracker.ietf.org/doc/draft-uni-qsckeys-sphincsplus/00/ for details.
     * ASN.1 Encoding for a
     * SphincsPlus public key for fully populated:
     * <pre>
     *   SPHINCSPPLUSPublicKey := SEQUENCE {
     *     pkseed          OCTET STRING,     --n-byte public key seed
     *     pkroot          OCTET STRING      --n-byte public hypertree root
     *   }
     * </pre>
     */
    [Obsolete("Use SLH-DSA instead")]
    public sealed class SphincsPlusPublicKey
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="SphincsPlusPublicKey"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="SphincsPlusPublicKey"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="SphincsPlusPublicKey"/>, or null if <paramref name="obj"/> is null.</returns>
        public static SphincsPlusPublicKey GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SphincsPlusPublicKey sphincsPlusPublicKey)
                return sphincsPlusPublicKey;
            return new SphincsPlusPublicKey(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="SphincsPlusPublicKey"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SphincsPlusPublicKey"/>.</returns>
        public static SphincsPlusPublicKey GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SphincsPlusPublicKey(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="SphincsPlusPublicKey"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="SphincsPlusPublicKey"/>, or null if <paramref name="element"/> is null.</returns>
        public static SphincsPlusPublicKey GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is SphincsPlusPublicKey sphincsPlusPublicKey)
                return sphincsPlusPublicKey;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new SphincsPlusPublicKey(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="SphincsPlusPublicKey"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SphincsPlusPublicKey"/>.</returns>
        public static SphincsPlusPublicKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SphincsPlusPublicKey(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_pkseed;
        private readonly Asn1OctetString m_pkroot;

        /// <summary>Create a new <see cref="SphincsPlusPublicKey"/>.</summary>
        /// <param name="pkseed">The pkseed.</param>
        /// <param name="pkroot">The pkroot.</param>
        public SphincsPlusPublicKey(byte[] pkseed, byte[] pkroot)
        {
            m_pkseed = DerOctetString.FromContents(pkseed);
            m_pkroot = DerOctetString.FromContents(pkroot);
        }

        private SphincsPlusPublicKey(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_pkseed = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_pkroot = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Return the pkroot.</summary>
        public byte[] GetPkroot() => Arrays.Clone(m_pkroot.GetOctets());

        /// <summary>Return the pkseed.</summary>
        public byte[] GetPkseed() => Arrays.Clone(m_pkseed.GetOctets());

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_pkseed, m_pkroot);
    }
}
