using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
    /// <summary>
    /// Signer implementation for the CRYSTALS-Dilithium post-quantum signature algorithm.
    /// </summary>
    /// <remarks>
    /// Dilithium is part of the CRYSTALS (Cryptographic Suite for Algebraic Lattices) family.
    /// This implementation corresponds to the submission to the NIST PQC project.
    /// Note: Users are encouraged to migrate to ML-DSA (FIPS 204) as the standardized version.
    /// </remarks>
    [Obsolete("Use ML-DSA instead")]
    public class DilithiumSigner 
        : IMessageSigner
    {
        private DilithiumPrivateKeyParameters privKey;
        private DilithiumPublicKeyParameters pubKey;

        private SecureRandom random;

        /// <summary>
        /// Default constructor.
        /// </summary>
        public DilithiumSigner()
        {
        }

        /// <summary>
        /// Initialise the Dilithium signer.
        /// </summary>
        /// <param name="forSigning">True if initializing for signing, false for verification.</param>
        /// <param name="param">The parameters for the signer (typically <see cref="DilithiumPrivateKeyParameters"/> or <see cref="DilithiumPublicKeyParameters"/>).</param>
        public void Init(bool forSigning, ICipherParameters param)
        {
            if (forSigning)
            {
                if (param is ParametersWithRandom withRandom)
                {
                    privKey = (DilithiumPrivateKeyParameters)withRandom.Parameters;
                    random = withRandom.Random;
                }
                else
                {
                    privKey = (DilithiumPrivateKeyParameters)param;
                    random = null;
                }
            }
            else
            {
                pubKey = (DilithiumPublicKeyParameters)param;
                random = null;
            }
        }

        /// <summary>
        /// Generate a signature for the given message.
        /// </summary>
        /// <param name="message">The message bytes to sign.</param>
        /// <returns>The generated signature byte array.</returns>
        public byte[] GenerateSignature(byte[] message)
        {
            DilithiumEngine engine = privKey.Parameters.GetEngine(random);
            byte[] sig = new byte[engine.CryptoBytes];
            engine.Sign(sig, sig.Length, message, 0, message.Length, privKey.m_rho, privKey.m_k, privKey.m_tr,
                privKey.m_t0, privKey.m_s1, privKey.m_s2, legacy: true);
            return sig;
        }

        /// <summary>
        /// Verify a signature for the given message.
        /// </summary>
        /// <param name="message">The original message bytes.</param>
        /// <param name="signature">The signature bytes to verify.</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        public bool VerifySignature(byte[] message, byte[] signature)
        {
            var engine = pubKey.Parameters.GetEngine(random);
            var tr = DilithiumEngine.CalculatePublicKeyHash(pubKey.m_rho, pubKey.m_t1);
            return engine.VerifyInternal(signature, signature.Length, message, 0, message.Length, pubKey.m_rho,
                pubKey.m_t1, tr);
        }
    }
}
