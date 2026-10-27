using System;

namespace Org.BouncyCastle.Asn1.X9
{
    /// <summary>A Diffie-Hellman public key, as defined by ANSI X9.42.</summary>
    public class DHPublicKey
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="DHPublicKey"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="DHPublicKey"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="DHPublicKey"/>, or null if <paramref name="obj"/> is null.</returns>
        public static DHPublicKey GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DHPublicKey dhPublicKey)
                return dhPublicKey;
            return new DHPublicKey(DerInteger.GetInstance(obj));
        }

        /// <summary>Return an <see cref="DHPublicKey"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DHPublicKey"/>.</returns>
        public static DHPublicKey GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new DHPublicKey(DerInteger.GetInstance(obj, isExplicit));

        /// <summary>Return an <see cref="DHPublicKey"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DHPublicKey"/>.</returns>
        public static DHPublicKey GetTagged(Asn1TaggedObject obj, bool isExplicit) =>
            new DHPublicKey(DerInteger.GetTagged(obj, isExplicit));

        private readonly DerInteger m_y;

        /// <summary>Create a new <see cref="DHPublicKey"/>.</summary>
        /// <param name="y">The second operand.</param>
        public DHPublicKey(DerInteger y)
        {
            m_y = y ?? throw new ArgumentNullException(nameof(y));
        }

        /// <summary>Gets the y.</summary>
        public DerInteger Y => m_y;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => m_y;
    }
}
