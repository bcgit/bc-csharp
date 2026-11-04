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
        /// <summary>The object identifier <c>1.2.840.113549.1.9.15.2</c>.</summary>
        public static readonly DerObjectIdentifier CannotDecryptAny = PkcsObjectIdentifiers.CannotDecryptAny;
        /// <summary>The object identifier <c>1.2.840.113549.1.9.15.3</c>.</summary>
        public static readonly DerObjectIdentifier SmimeCapabilitesVersions = PkcsObjectIdentifiers.SmimeCapabilitiesVersions;

        /**
         * encryption algorithms preferences
         */
        public static readonly DerObjectIdentifier Aes256Cbc = NistObjectIdentifiers.IdAes256Cbc;
        /// <summary>The object identifier <c>2.16.840.1.101.3.4.1.22</c>.</summary>
        public static readonly DerObjectIdentifier Aes192Cbc = NistObjectIdentifiers.IdAes192Cbc;
        /// <summary>The object identifier <c>2.16.840.1.101.3.4.1.2</c>.</summary>
        public static readonly DerObjectIdentifier Aes128Cbc = NistObjectIdentifiers.IdAes128Cbc;
        /// <summary>The object identifier <c>1.3.6.1.4.1.188.7.1.1.2</c>.</summary>
        public static readonly DerObjectIdentifier IdeaCbc = MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC;
        /// <summary>The object identifier <c>1.2.840.113533.7.66.10</c>.</summary>
        public static readonly DerObjectIdentifier Cast5Cbc = MiscObjectIdentifiers.cast5CBC;
        /// <summary>The object identifier <c>1.3.14.3.2.7</c>.</summary>
        public static readonly DerObjectIdentifier DesCbc = OiwObjectIdentifiers.DesCbc;
        /// <summary>The object identifier <c>1.2.840.113549.3.7</c>.</summary>
        public static readonly DerObjectIdentifier DesEde3Cbc = PkcsObjectIdentifiers.DesEde3Cbc;
        /// <summary>The object identifier <c>1.2.840.113549.3.2</c>.</summary>
        public static readonly DerObjectIdentifier RC2Cbc = PkcsObjectIdentifiers.RC2Cbc;

        /// <summary>Return an <see cref="SmimeCapabilities"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="SmimeCapabilities"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="SmimeCapabilities"/>, or null if <paramref name="obj"/> is null.</returns>
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

        /// <summary>Return an <see cref="SmimeCapabilities"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SmimeCapabilities"/>.</returns>
        public static SmimeCapabilities GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SmimeCapabilities(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="SmimeCapabilities"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SmimeCapabilities"/>.</returns>
        public static SmimeCapabilities GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SmimeCapabilities(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_capabilities;

        /// <summary>Create a new <see cref="SmimeCapabilities"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
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
