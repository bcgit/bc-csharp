using System;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// Test-only stand-ins for the stateful XMSS key holder the known-answer and state tests were written against,
    /// built on the key pair generator and <see cref="XmssSigner"/>. Not a test fixture itself.
    /// </summary>
    /// <remarks>
    /// The XMSS^MT half of the Java class arrives with the XMSS^MT signer.
    /// </remarks>
    internal static class XmssHarnessTests
    {
        internal static byte[] Sign(XmssSigner signer, byte[] message)
        {
            signer.BlockUpdate(message, 0, message.Length);

            return signer.GenerateSignature();
        }

        internal static bool Verify(XmssSigner signer, byte[] message, byte[] signature)
        {
            signer.BlockUpdate(message, 0, message.Length);

            return signer.VerifySignature(signature);
        }

        /// <summary>The index a signature, or a stored private key, opens with: 4 bytes big-endian.</summary>
        internal static int IndexOf(byte[] encoding) =>
            (int)Org.BouncyCastle.Crypto.Utilities.Pack.BE_To_UInt32(encoding, 0);

        /// <summary>An XMSS key pair that is signed with in place.</summary>
        internal sealed class Xmss
        {
            private readonly XmssParameters m_params;
            private readonly SecureRandom m_prng;

            private XmssPrivateKeyParameters m_privateKey;
            private XmssPublicKeyParameters m_publicKey;

            internal Xmss(XmssParameters parameters, SecureRandom prng)
            {
                m_params = parameters ?? throw new ArgumentNullException(nameof(parameters), "params == null");
                m_prng = prng;
            }

            internal void GenerateKeys()
            {
                XmssKeyPairGenerator kpGen = new XmssKeyPairGenerator();

                kpGen.Init(new XmssKeyGenerationParameters(m_prng, m_params));

                AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

                m_privateKey = (XmssPrivateKeyParameters)kp.Private;
                m_publicKey = (XmssPublicKeyParameters)kp.Public;
            }

            internal void ImportState(XmssPrivateKeyParameters privateKey, XmssPublicKeyParameters publicKey)
            {
                CheckMatch(privateKey.GetRoot(), publicKey.GetRoot(), privateKey.GetPublicSeed(),
                    publicKey.GetPublicSeed());

                m_privateKey = privateKey;
                m_publicKey = publicKey;
            }

            internal void ImportState(byte[] privateKey, byte[] publicKey)
            {
                if (privateKey == null)
                    throw new ArgumentNullException(nameof(privateKey), "privateKey == null");
                if (publicKey == null)
                    throw new ArgumentNullException(nameof(publicKey), "publicKey == null");

                ImportState(new XmssPrivateKeyParameters.Builder(m_params).WithPrivateKey(privateKey).Build(),
                    new XmssPublicKeyParameters.Builder(m_params).WithPublicKey(publicKey).Build());
            }

            internal byte[] Sign(byte[] message)
            {
                if (message == null)
                    throw new ArgumentNullException(nameof(message), "message == null");

                XmssSigner signer = new XmssSigner();

                signer.Init(true, m_privateKey);

                byte[] signature = XmssHarnessTests.Sign(signer, message);

                m_privateKey = (XmssPrivateKeyParameters)signer.GetUpdatedPrivateKey();

                return signature;
            }

            internal bool VerifySignature(byte[] message, byte[] signature, byte[] publicKey)
            {
                if (message == null)
                    throw new ArgumentNullException(nameof(message), "message == null");
                if (signature == null)
                    throw new ArgumentNullException(nameof(signature), "signature == null");
                if (publicKey == null)
                    throw new ArgumentNullException(nameof(publicKey), "publicKey == null");

                XmssSigner signer = new XmssSigner();

                signer.Init(false, new XmssPublicKeyParameters.Builder(m_params).WithPublicKey(publicKey).Build());

                return Verify(signer, message, signature);
            }

            internal XmssPrivateKeyParameters ExportPrivateKey() => m_privateKey;

            internal XmssPublicKeyParameters ExportPublicKey() => m_publicKey;

            internal XmssPrivateKeyParameters PrivateKey => m_privateKey;

            internal XmssParameters Params => m_params;

            internal byte[] GetRoot() => m_privateKey.GetRoot();

            internal int Index => m_privateKey.Index;

            internal byte[] GetPublicSeed() => m_privateKey.GetPublicSeed();
        }

        /// <summary>A "random" source that hands out zeros, for reproducible keys.</summary>
        internal sealed class NullPrng
            : SecureRandom
        {
            internal NullPrng()
                : base(null)
            {
            }

            public override void NextBytes(byte[] buf) => NextBytes(buf, 0, buf.Length);

            public override void NextBytes(byte[] buf, int off, int len) => Array.Clear(buf, off, len);

#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public override void NextBytes(Span<byte> buffer) => buffer.Clear();
#endif
        }

        private static void CheckMatch(byte[] privRoot, byte[] pubRoot, byte[] privSeed, byte[] pubSeed)
        {
            if (!Arrays.AreEqual(privRoot, pubRoot))
                throw new InvalidOperationException("root of private key and public key do not match");
            if (!Arrays.AreEqual(privSeed, pubSeed))
                throw new InvalidOperationException("public seed of private key and public key do not match");
        }
    }
}
