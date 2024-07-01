using System;

using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;

namespace Org.BouncyCastle.Asn1.Smime
{
    public class SmimeCapability
        : Asn1Encodable
    {
        /**
         * general preferences
         */
        public static readonly DerObjectIdentifier PreferSignedData = PkcsObjectIdentifiers.PreferSignedData;
        public static readonly DerObjectIdentifier CannotDecryptAny = PkcsObjectIdentifiers.CannotDecryptAny;
        public static readonly DerObjectIdentifier SmimeCapabilitiesVersions = PkcsObjectIdentifiers.SmimeCapabilitiesVersions;

		/**
         * encryption algorithms preferences
         */
        public static readonly DerObjectIdentifier DesCbc = OiwObjectIdentifiers.DesCbc;
        public static readonly DerObjectIdentifier DesEde3Cbc = PkcsObjectIdentifiers.DesEde3Cbc;
        public static readonly DerObjectIdentifier RC2Cbc = PkcsObjectIdentifiers.RC2Cbc;

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

        public static SmimeCapability GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new SmimeCapability(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static SmimeCapability GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new SmimeCapability(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerObjectIdentifier m_capabilityID;
        private readonly Asn1Encodable m_parameters;

        [Obsolete("Use 'GetInstance' instead")]
        public SmimeCapability(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_capabilityID = DerObjectIdentifier.GetInstance(seq[0]);

            if (seq.Count > 1)
            {
                m_parameters = seq[1];
            }
        }

        public SmimeCapability(DerObjectIdentifier capabilityID, Asn1Encodable parameters)
        {
            m_capabilityID = capabilityID ?? throw new ArgumentNullException(nameof(capabilityID));
            m_parameters = parameters;
        }

        public DerObjectIdentifier CapabilityID => m_capabilityID;

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
