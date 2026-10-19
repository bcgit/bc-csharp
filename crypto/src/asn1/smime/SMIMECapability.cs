using System;

using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;

namespace Org.BouncyCastle.Asn1.Smime
{
    /// <summary>The SMIMECapability structure of RFC 8551.</summary>
    public class SmimeCapability
        : Asn1Encodable
    {
        /**
         * general preferences
         */
        public static readonly DerObjectIdentifier PreferSignedData = PkcsObjectIdentifiers.PreferSignedData;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.15.2</c>.</summary>
        public static readonly DerObjectIdentifier CannotDecryptAny = PkcsObjectIdentifiers.CannotDecryptAny;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.15.3</c>.</summary>
        public static readonly DerObjectIdentifier SmimeCapabilitiesVersions = PkcsObjectIdentifiers.SmimeCapabilitiesVersions;

        /**
         * encryption algorithms preferences
         */
        public static readonly DerObjectIdentifier DesCbc = OiwObjectIdentifiers.DesCbc;
        /// <summary>The object identifier <c>1.2.840.113549.3.7</c>.</summary>
        public static readonly DerObjectIdentifier DesEde3Cbc = PkcsObjectIdentifiers.DesEde3Cbc;
        /// <summary>The object identifier <c>1.2.840.113549.3.2</c>.</summary>
        public static readonly DerObjectIdentifier RC2Cbc = PkcsObjectIdentifiers.RC2Cbc;

        /// <summary>Return an <see cref="SmimeCapability"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="SmimeCapability"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="SmimeCapability"/>, or null if <paramref name="obj"/> is null.</returns>
        public static SmimeCapability GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SmimeCapability smimeCapability)
                return smimeCapability;
#pragma warning disable CS0618 // Type or member is obsolete
            return new SmimeCapability(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="SmimeCapability"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SmimeCapability"/>.</returns>
        public static SmimeCapability GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new SmimeCapability(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="SmimeCapability"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SmimeCapability"/>.</returns>
        public static SmimeCapability GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new SmimeCapability(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerObjectIdentifier m_capabilityID;
        private readonly Asn1Encodable m_parameters;

        /// <summary>Create a new <see cref="SmimeCapability"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public SmimeCapability(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_capabilityID = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            // TODO[asn1] Asn1Utilities helper method for this type of situation
            m_parameters = Asn1Utilities.ReadOptional(seq, ref pos, element => element);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="SmimeCapability"/>.</summary>
        /// <param name="capabilityID">The capability ID.</param>
        /// <param name="parameters">The parameters.</param>
        public SmimeCapability(DerObjectIdentifier capabilityID, Asn1Encodable parameters)
        {
            m_capabilityID = capabilityID ?? throw new ArgumentNullException(nameof(capabilityID));
            m_parameters = parameters;
        }

        /// <summary>Gets the capability ID.</summary>
        public DerObjectIdentifier CapabilityID => m_capabilityID;

        /// <summary>Gets the parameters.</summary>
        // TODO[api] return Asn1Encodable
        public Asn1Object Parameters => m_parameters?.ToAsn1Object();

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * SMIMECapability ::= Sequence {
         *     capabilityID OBJECT IDENTIFIER,
         *     parameters ANY DEFINED BY capabilityID OPTIONAL
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            return m_parameters == null
                ?  new DerSequence(m_capabilityID)
                :  new DerSequence(m_capabilityID, m_parameters);
        }
    }
}
