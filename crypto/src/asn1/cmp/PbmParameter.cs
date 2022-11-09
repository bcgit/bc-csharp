﻿using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     *  PBMParameter ::= SEQUENCE {
     *          salt                OCTET STRING,
     *          -- note:  implementations MAY wish to limit acceptable sizes
     *          -- of this string to values appropriate for their environment
     *          -- in order to reduce the risk of denial-of-service attacks
     *          owf                 AlgorithmIdentifier,
     *          -- AlgId for a One-Way Function (SHA-1 recommended)
     *          iterationCount      INTEGER,
     *          -- number of times the OWF is applied
     *          -- note:  implementations MAY wish to limit acceptable sizes
     *          -- of this integer to values appropriate for their environment
     *          -- in order to reduce the risk of denial-of-service attacks
     *          mac                 AlgorithmIdentifier
     *          -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
     *      }   -- or HMAC [RFC2104, RFC2202])
     */
    public class PbmParameter
        : Asn1Encodable
    {
        public static PbmParameter GetInstance(object obj)
        {
            if (obj is PbmParameter pbmParameter)
                return pbmParameter;

            if (obj != null)
                return new PbmParameter(Asn1Sequence.GetInstance(obj));

            return null;
        }

        private readonly Asn1OctetString m_salt;
        private readonly AlgorithmIdentifier m_owf;
        private readonly DerInteger m_iterationCount;
        private readonly AlgorithmIdentifier m_mac;

        private PbmParameter(Asn1Sequence seq)
        {
            m_salt = Asn1OctetString.GetInstance(seq[0]);
            m_owf = AlgorithmIdentifier.GetInstance(seq[1]);
            m_iterationCount = DerInteger.GetInstance(seq[2]);
            m_mac = AlgorithmIdentifier.GetInstance(seq[3]);
        }

        public PbmParameter(byte[] salt, AlgorithmIdentifier owf, int iterationCount, AlgorithmIdentifier mac)
            : this(new DerOctetString(salt), owf, new DerInteger(iterationCount), mac)
        {
        }

        public PbmParameter(Asn1OctetString salt, AlgorithmIdentifier owf, DerInteger iterationCount,
            AlgorithmIdentifier mac)
        {
            m_salt = salt;
            m_owf = owf;
            m_iterationCount = iterationCount;
            m_mac = mac;
        }

        public virtual DerInteger IterationCount => m_iterationCount;

        public virtual AlgorithmIdentifier Mac => m_mac;

        public virtual AlgorithmIdentifier Owf => m_owf;

        public virtual Asn1OctetString Salt => m_salt;

        /**
         * <pre>
         *  PbmParameter ::= SEQUENCE {
         *                        salt                OCTET STRING,
         *                        -- note:  implementations MAY wish to limit acceptable sizes
         *                        -- of this string to values appropriate for their environment
         *                        -- in order to reduce the risk of denial-of-service attacks
         *                        owf                 AlgorithmIdentifier,
         *                        -- AlgId for a One-Way Function (SHA-1 recommended)
         *                        iterationCount      INTEGER,
         *                        -- number of times the OWF is applied
         *                        -- note:  implementations MAY wish to limit acceptable sizes
         *                        -- of this integer to values appropriate for their environment
         *                        -- in order to reduce the risk of denial-of-service attacks
         *                        mac                 AlgorithmIdentifier
         *                        -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
         *    }   -- or HMAC [RFC2104, RFC2202])
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            return new DerSequence(m_salt, m_owf, m_iterationCount, m_mac);
        }
    }
}
