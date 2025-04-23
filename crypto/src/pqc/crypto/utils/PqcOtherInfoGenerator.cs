using System;
using System.IO;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Pqc.Crypto.Ntru;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Utilities
{
    /**
     * OtherInfo Generator for which can be used for populating the SuppPrivInfo field used to provide shared
     * secret data used with NIST SP 800-56A agreement algorithms.
     */
    public abstract class PqcOtherInfoGenerator
    {
        protected readonly DerOtherInfo.Builder m_otherInfoBuilder;
        protected readonly SecureRandom m_random;

        protected bool m_used = false;

        /**
         * Create a basic builder with just the compulsory fields.
         *
         * @param algorithmID the algorithm associated with this invocation of the KDF.
         * @param partyUInfo  sender party info.
         * @param partyVInfo  receiver party info.
         * @param random a source of randomness.
         */
        internal PqcOtherInfoGenerator(AlgorithmIdentifier algorithmID, byte[] partyUInfo, byte[] partyVInfo,
            SecureRandom random)
        {
            m_otherInfoBuilder = new DerOtherInfo.Builder(algorithmID, partyUInfo, partyVInfo);
            m_random = random;
        }

        /**
         * Party U (initiator) generation.
         */
        public sealed class PartyU
            : PqcOtherInfoGenerator
        {
            private AsymmetricCipherKeyPair m_aKp;
            private IEncapsulatedSecretExtractor m_encSE;

            /**
             * Create a basic builder with just the compulsory fields for the initiator.
             *
             * @param kemParams the key type parameters for populating the private info field.
             * @param algorithmID the algorithm associated with this invocation of the KDF.
             * @param partyUInfo  sender party info.
             * @param partyVInfo  receiver party info.
             * @param random a source of randomness.
             */
            public PartyU(IKemParameters kemParams, AlgorithmIdentifier algorithmID, byte[] partyUInfo,
                byte[] partyVInfo, SecureRandom random)
                : base(algorithmID, partyUInfo, partyVInfo, random)
            {
                //if (kemParams is MLKemParameters mlKemParameters)
                //{
                //    MLKemKeyPairGenerator kpg = new MLKemKeyPairGenerator();
                //    kpg.Init(new MLKemKeyGenerationParameters(random, mlKemParameters));

                //    m_aKp = kpg.GenerateKeyPair();

                //    m_encSE = new MLKemExtractor((MLKemPrivateKeyParameters)m_aKp.Private);
                //}
                //else
                if (kemParams is NtruParameters ntruParameters)
                {
                    NtruKeyPairGenerator kpg = new NtruKeyPairGenerator();
                    kpg.Init(new NtruKeyGenerationParameters(random, ntruParameters));

                    m_aKp = kpg.GenerateKeyPair();

                    m_encSE = new NtruKemExtractor((NtruPrivateKeyParameters)m_aKp.Private);
                }
                else
                {
                    throw new ArgumentException("unknown IKemParameters");
                }
            }

            /**
             * Add optional supplementary public info (DER tagged, implicit, 0).
             *
             * @param suppPubInfo supplementary public info.
             * @return the current builder instance.
             */
            public PqcOtherInfoGenerator WithSuppPubInfo(byte[] suppPubInfo)
            {
                m_otherInfoBuilder.WithSuppPubInfo(suppPubInfo);
                return this;
            }

            public byte[] GetSuppPrivInfoPartA()
            {
                return GetEncoded(m_aKp.Public);
            }

            public DerOtherInfo Generate(byte[] suppPrivInfoPartB)
            {
                m_otherInfoBuilder.WithSuppPrivInfo(m_encSE.ExtractSecret(suppPrivInfoPartB));

                return m_otherInfoBuilder.Build();
            }
        }

        /**
         * Party V (responder) generation.
         */
        public sealed class PartyV
            : PqcOtherInfoGenerator
        {
            private IEncapsulatedSecretGenerator m_encSG;

            /**
             * Create a basic builder with just the compulsory fields for the responder.
             *
             * @param kemParams the key type parameters for populating the private info field.
             * @param algorithmID the algorithm associated with this invocation of the KDF.
             * @param partyUInfo  sender party info.
             * @param partyVInfo  receiver party info.
             * @param random a source of randomness.
             */
            public PartyV(IKemParameters kemParams, AlgorithmIdentifier algorithmID, byte[] partyUInfo,
                byte[] partyVInfo, SecureRandom random)
                : base(algorithmID, partyUInfo, partyVInfo, random)
            {
                //if (kemParams is MLKemParameters)
                //{
                //    m_encSG = new MLKemGenerator(random);
                //}
                //else
                if (kemParams is NtruParameters)
                {
                    m_encSG = new NtruKemGenerator(random);
                }
                else
                {
                    throw new ArgumentException("unknown IKemParameters");
                }
            }

            /**
             * Add optional supplementary public info (DER tagged, implicit, 0).
             *
             * @param suppPubInfo supplementary public info.
             * @return the current builder instance.
             */
            public PqcOtherInfoGenerator WithSuppPubInfo(byte[] suppPubInfo)
            {
                m_otherInfoBuilder.WithSuppPubInfo(suppPubInfo);
                return this;
            }

            public byte[] GetSuppPrivInfoPartB(byte[] suppPrivInfoPartA)
            {
                m_used = false;

                try
                {
                    ISecretWithEncapsulation bEp = m_encSG.GenerateEncapsulated(GetPublicKey(suppPrivInfoPartA));

                    m_otherInfoBuilder.WithSuppPrivInfo(bEp.GetSecret());

                    return bEp.GetEncapsulation();
                }
                catch (IOException e)
                {
                    throw new ArgumentException("cannot decode public key", e);
                }
            }

            public DerOtherInfo Generate()
            {
                if (m_used)
                    throw new InvalidOperationException("builder already used");

                m_used = true;

                return m_otherInfoBuilder.Build();
            }
        }

        private static byte[] GetEncoded(AsymmetricKeyParameter pubKey)
        {
            try
            {
                return PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey).GetEncoded();
            }
            catch (IOException)
            {
                return null;
            }
        }

        private static AsymmetricKeyParameter GetPublicKey(byte[] enc)
        {
            return PqcPublicKeyFactory.CreateKey(enc);
        }
    }
}
