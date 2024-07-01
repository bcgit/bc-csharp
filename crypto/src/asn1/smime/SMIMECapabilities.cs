using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1.Misc;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Smime
{
    /**
     * Handler class for dealing with S/MIME Capabilities
     */
    public class SmimeCapabilities
        : Asn1Encodable
    {
        /**
         * general preferences
         */
        public static readonly DerObjectIdentifier PreferSignedData = PkcsObjectIdentifiers.PreferSignedData;
        public static readonly DerObjectIdentifier CannotDecryptAny = PkcsObjectIdentifiers.CannotDecryptAny;
        public static readonly DerObjectIdentifier SmimeCapabilitesVersions = PkcsObjectIdentifiers.SmimeCapabilitiesVersions;

		/**
         * encryption algorithms preferences
         */
        public static readonly DerObjectIdentifier Aes256Cbc = NistObjectIdentifiers.IdAes256Cbc;
        public static readonly DerObjectIdentifier Aes192Cbc = NistObjectIdentifiers.IdAes192Cbc;
        public static readonly DerObjectIdentifier Aes128Cbc = NistObjectIdentifiers.IdAes128Cbc;
        public static readonly DerObjectIdentifier IdeaCbc = MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC;
        public static readonly DerObjectIdentifier Cast5Cbc = MiscObjectIdentifiers.cast5CBC;
        public static readonly DerObjectIdentifier DesCbc = OiwObjectIdentifiers.DesCbc;
        public static readonly DerObjectIdentifier DesEde3Cbc = PkcsObjectIdentifiers.DesEde3Cbc;
        public static readonly DerObjectIdentifier RC2Cbc = PkcsObjectIdentifiers.RC2Cbc;

        public static SmimeCapabilities GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SmimeCapabilities smimeCapabilities)
                return smimeCapabilities;

            // TODO[api] Remove this handler
            if (obj is AttributeX509 attributeX509)
                return new SmimeCapabilities((Asn1Sequence)attributeX509.AttrValues[0]);

            return new SmimeCapabilities(Asn1Sequence.GetInstance(obj));
        }

        public static SmimeCapabilities GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SmimeCapabilities(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static SmimeCapabilities GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SmimeCapabilities(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_capabilities;

        public SmimeCapabilities(Asn1Sequence seq)
        {
            m_capabilities = seq ?? throw new ArgumentNullException(nameof(seq));
        }

        /**
         * returns an ArrayList with 0 or more objects of all the capabilities
         * matching the passed in capability Oid. If the Oid passed is null the
         * entire set is returned.
         */
        public IList<SmimeCapability> GetCapabilitiesForOid(DerObjectIdentifier capability)
        {
            var list = new List<SmimeCapability>();
            DoGetCapabilitiesForOid(capability, list);
			return list;
        }

        private void DoGetCapabilitiesForOid(DerObjectIdentifier capability, List<SmimeCapability> list)
        {
            foreach (var element in m_capabilities)
            {
                SmimeCapability smimeCapability = SmimeCapability.GetInstance(element);
                if (smimeCapability.CapabilityID.Equals(capability))
                {
                    list.Add(smimeCapability);
                }
            }
        }

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * SMIMECapabilities ::= Sequence OF SMIMECapability
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => m_capabilities;
    }
}
