using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * DHBMParameter ::= SEQUENCE {
     * owf                 AlgorithmIdentifier,
     * -- AlgId for a One-Way Function (SHA-1 recommended)
     * mac                 AlgorithmIdentifier
     * -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
     * }   -- or HMAC [RFC2104, RFC2202])
     */
    public class DhbmParameter
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="DhbmParameter"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="DhbmParameter"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="DhbmParameter"/>, or null if <paramref name="obj"/> is null.</returns>
        public static DhbmParameter GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DhbmParameter dhbmParameter)
                return dhbmParameter;
            return new DhbmParameter(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="DhbmParameter"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DhbmParameter"/>.</returns>
        public static DhbmParameter GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DhbmParameter(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="DhbmParameter"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DhbmParameter"/>.</returns>
        public static DhbmParameter GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DhbmParameter(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_owf;
        private readonly AlgorithmIdentifier m_mac;

        private DhbmParameter(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_owf = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_mac = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="DhbmParameter"/>.</summary>
        /// <param name="owf">The owf.</param>
        /// <param name="mac">The MAC.</param>
        public DhbmParameter(AlgorithmIdentifier owf, AlgorithmIdentifier mac)
        {
            m_owf = owf ?? throw new ArgumentNullException(nameof(owf));
            m_mac = mac ?? throw new ArgumentNullException(nameof(mac));
        }

        /// <summary>Gets the owf.</summary>
        public virtual AlgorithmIdentifier Owf => m_owf;

        /// <summary>Gets the mac.</summary>
        public virtual AlgorithmIdentifier Mac => m_mac;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_owf, m_mac);
    }
}
