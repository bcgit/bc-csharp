using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.OpenSsl
{
    public class CertificateTrustBlock
    {
        private readonly Asn1Sequence m_uses;
        private readonly Asn1Sequence m_prohibitions;
        private readonly DerUtf8String m_alias;

        public CertificateTrustBlock(ISet<DerObjectIdentifier> uses)
            : this(alias: null, uses, prohibitions: null)
        {
        }

        public CertificateTrustBlock(string alias, ISet<DerObjectIdentifier> uses)
            : this(alias, uses, prohibitions: null)
        {
        }

        public CertificateTrustBlock(string alias, ISet<DerObjectIdentifier> uses, ISet<DerObjectIdentifier> prohibitions)
        {
            m_uses = ToSequence(uses);
            m_prohibitions = ToSequence(prohibitions);
            m_alias = alias == null ? null : new DerUtf8String(alias);
        }

        internal CertificateTrustBlock(byte[] encoded)
        {
            Asn1Sequence uses = null, prohibitions = null;
            DerUtf8String alias = null;

            foreach (var element in Asn1Sequence.GetInstance(encoded))
            {
                if (element is Asn1Sequence sequence)
                {
                    uses = sequence;
                }
                else if (element is Asn1TaggedObject taggedObject)
                {
                    prohibitions = Asn1Sequence.GetInstance(taggedObject, declaredExplicit: false);
                }
                else if (element is DerUtf8String utf8String)
                {
                    alias = utf8String;
                }
            }

            m_uses = uses;
            m_prohibitions = prohibitions;
            m_alias = alias;
        }

        public string GetAlias() => m_alias.GetString();

        public ISet<DerObjectIdentifier> GetUses() => ToSet(m_uses);

        public ISet<DerObjectIdentifier> GetProhibitions() => ToSet(m_prohibitions);

        internal Asn1Sequence ToAsn1Sequence()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.AddOptional(m_uses);
            v.AddOptionalTagged(false, 0, m_prohibitions);
            v.AddOptional(m_alias);
            return new DerSequence(v);
        }

        private static ISet<DerObjectIdentifier> ToSet(Asn1Sequence seq)
        {
            return seq == null
                ?  new HashSet<DerObjectIdentifier>()
                :  new HashSet<DerObjectIdentifier>(CollectionUtilities.Select(seq, DerObjectIdentifier.GetInstance));
        }

        private static Asn1Sequence ToSequence(ISet<DerObjectIdentifier> oids)
        {
            if (CollectionUtilities.IsNullOrEmpty(oids))
                return null;

            var v = new Asn1EncodableVector(oids.Count);
            v.AddAll(oids);
            return new DerSequence(v);
        }
    }
}
