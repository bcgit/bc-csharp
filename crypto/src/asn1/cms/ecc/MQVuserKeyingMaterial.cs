using System;

namespace Org.BouncyCastle.Asn1.Cms.Ecc
{
    /// <summary>The MQVuserKeyingMaterial structure of RFC 5753.</summary>
    public class MQVuserKeyingMaterial
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="MQVuserKeyingMaterial"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="MQVuserKeyingMaterial"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="MQVuserKeyingMaterial"/>, or null if <paramref name="obj"/> is null.</returns>
        public static MQVuserKeyingMaterial GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is MQVuserKeyingMaterial mqvUserKeyingMaterial)
                return mqvUserKeyingMaterial;
            return new MQVuserKeyingMaterial(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="MQVuserKeyingMaterial"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="MQVuserKeyingMaterial"/>.</returns>
        public static MQVuserKeyingMaterial GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new MQVuserKeyingMaterial(Asn1Sequence.GetInstance(obj, isExplicit));

        /// <summary>Return an <see cref="MQVuserKeyingMaterial"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="MQVuserKeyingMaterial"/>.</returns>
        public static MQVuserKeyingMaterial GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new MQVuserKeyingMaterial(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly OriginatorPublicKey m_ephemeralPublicKey;
        private readonly Asn1OctetString m_addedukm;

        /// <summary>Create a new <see cref="MQVuserKeyingMaterial"/>.</summary>
        /// <param name="ephemeralPublicKey">The ephemeral public key.</param>
        /// <param name="addedukm">The addedukm.</param>
        public MQVuserKeyingMaterial(OriginatorPublicKey ephemeralPublicKey, Asn1OctetString addedukm)
        {
            m_ephemeralPublicKey = ephemeralPublicKey ?? throw new ArgumentNullException(nameof(ephemeralPublicKey));
            m_addedukm = addedukm;
        }

        private MQVuserKeyingMaterial(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_ephemeralPublicKey = Asn1Utilities.Read(seq, ref pos, OriginatorPublicKey.GetInstance);
            m_addedukm = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Asn1OctetString.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the ephemeral public key.</summary>
        public OriginatorPublicKey EphemeralPublicKey => m_ephemeralPublicKey;

        /// <summary>Gets the added ukm.</summary>
        public Asn1OctetString AddedUkm => m_addedukm;

        /// <summary>Produce an object suitable for an <see cref="Asn1OutputStream"/>.</summary>
        /// <remarks>
        /// <code>
        /// MQVuserKeyingMaterial::= SEQUENCE {
        ///     ephemeralPublicKey  OriginatorPublicKey,
        ///     addedukm            [0] EXPLICIT UserKeyingMaterial OPTIONAL
        /// }
        /// </code>
        /// </remarks>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.Add(m_ephemeralPublicKey);
            v.AddOptionalTagged(true, 0, m_addedukm);
            return new DerSequence(v);
        }
    }
}
