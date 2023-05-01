using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Crypto.Utilities
{
    /**
     * Builder and holder class for preparing SP 800-56A compliant OtherInfo. The data is ultimately encoded as a DER SEQUENCE.
     * Empty octet strings are used to represent nulls in compulsory fields.
     */
    public sealed class DerOtherInfo
    {
        /**
         * Builder to create OtherInfo
         */
        public sealed class Builder
        {
            private readonly AlgorithmIdentifier m_algorithmID;
            private readonly Asn1OctetString m_partyUInfo;
            private readonly Asn1OctetString m_partyVInfo;

            private Asn1TaggedObject m_suppPubInfo;
            private Asn1TaggedObject m_suppPrivInfo;

            /**
             * Create a basic builder with just the compulsory fields.
             *
             * @param algorithmID the algorithm associated with this invocation of the KDF.
             * @param partyUInfo  sender party info.
             * @param partyVInfo  receiver party info.
             */
            public Builder(AlgorithmIdentifier algorithmID, byte[] partyUInfo, byte[] partyVInfo)
            {
                m_algorithmID = algorithmID;
                m_partyUInfo = DerUtilities.GetOctetString(partyUInfo);
                m_partyVInfo = DerUtilities.GetOctetString(partyVInfo);
            }

            /**
             * Add optional supplementary public info (DER tagged, implicit, 0).
             *
             * @param suppPubInfo supplementary public info.
             * @return  the current builder instance.
             */
            public Builder WithSuppPubInfo(byte[] suppPubInfo)
            {
                m_suppPubInfo = new DerTaggedObject(false, 0, DerUtilities.GetOctetString(suppPubInfo));
                return this;
            }

            /**
             * Add optional supplementary private info (DER tagged, implicit, 1).
             *
             * @param suppPrivInfo supplementary private info.
             * @return the current builder instance.
             */
            public Builder WithSuppPrivInfo(byte[] suppPrivInfo)
            {
                m_suppPrivInfo = new DerTaggedObject(false, 1, DerUtilities.GetOctetString(suppPrivInfo));
                return this;
            }

            /**
             * Build the KTSOtherInfo.
             *
             * @return an KTSOtherInfo containing the data.
             */
            public DerOtherInfo Build()
            {
                Asn1EncodableVector v = new Asn1EncodableVector(5);

                v.Add(m_algorithmID);
                v.Add(m_partyUInfo);
                v.Add(m_partyVInfo);
                v.AddOptional(m_suppPubInfo);
                v.AddOptional(m_suppPrivInfo);

                return new DerOtherInfo(new DerSequence(v));
            }
        }

        private readonly DerSequence m_sequence;

        private DerOtherInfo(DerSequence sequence)
        {
            m_sequence = sequence;
        }

        public byte[] GetEncoded() => m_sequence.GetEncoded();
    }
}
