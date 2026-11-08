using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <summary>
    /// An X25519 / X448 agreement with a low-order peer key yields the all-zero secret and is refused. The
    /// caller's output buffer must be left as it was, so a caller that mishandles the exception does not end up
    /// holding an all-zero "shared secret" that anyone can predict.
    /// </summary>
    [TestFixture]
    public class XdhAgreementFailureTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private const byte Fill = 0xAA;

        [Test]
        public void X25519LowOrderPeerLeavesBufferUnchanged()
        {
            var agreement = new X25519Agreement();
            agreement.Init(new X25519PrivateKeyParameters(Random));
            var lowOrder = new X25519PublicKeyParameters(new byte[X25519PublicKeyParameters.KeySize]);

            byte[] buf = Filled(agreement.AgreementSize + 7);
            Assert.Throws<InvalidOperationException>(() => agreement.CalculateAgreement(lowOrder, buf, 7));
            Assert.IsTrue(Arrays.AreEqual(Filled(buf.Length), buf));

#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            buf = Filled(agreement.AgreementSize);
            Assert.Throws<InvalidOperationException>(() => agreement.CalculateAgreement(lowOrder, buf.AsSpan()));
            Assert.IsTrue(Arrays.AreEqual(Filled(buf.Length), buf));
#endif
        }

        [Test]
        public void X448LowOrderPeerLeavesBufferUnchanged()
        {
            var agreement = new X448Agreement();
            agreement.Init(new X448PrivateKeyParameters(Random));
            var lowOrder = new X448PublicKeyParameters(new byte[X448PublicKeyParameters.KeySize]);

            byte[] buf = Filled(agreement.AgreementSize + 7);
            Assert.Throws<InvalidOperationException>(() => agreement.CalculateAgreement(lowOrder, buf, 7));
            Assert.IsTrue(Arrays.AreEqual(Filled(buf.Length), buf));

#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            buf = Filled(agreement.AgreementSize);
            Assert.Throws<InvalidOperationException>(() => agreement.CalculateAgreement(lowOrder, buf.AsSpan()));
            Assert.IsTrue(Arrays.AreEqual(Filled(buf.Length), buf));
#endif
        }

        [Test]
        public void X25519AgreementStillMatches()
        {
            var a = new X25519PrivateKeyParameters(Random);
            var b = new X25519PrivateKeyParameters(Random);

            byte[] sa = new byte[X25519PrivateKeyParameters.SecretSize + 3];
            byte[] sb = new byte[X25519PrivateKeyParameters.SecretSize];
            a.GenerateSecret(b.GeneratePublicKey(), sa, 3);
            b.GenerateSecret(a.GeneratePublicKey(), sb, 0);

            Assert.IsTrue(Arrays.AreEqual(sb, Arrays.CopyOfRange(sa, 3, sa.Length)));
            Assert.IsFalse(Arrays.AreAllZeroes(sb, 0, sb.Length));
        }

        [Test]
        public void X448AgreementStillMatches()
        {
            var a = new X448PrivateKeyParameters(Random);
            var b = new X448PrivateKeyParameters(Random);

            byte[] sa = new byte[X448PrivateKeyParameters.SecretSize + 3];
            byte[] sb = new byte[X448PrivateKeyParameters.SecretSize];
            a.GenerateSecret(b.GeneratePublicKey(), sa, 3);
            b.GenerateSecret(a.GeneratePublicKey(), sb, 0);

            Assert.IsTrue(Arrays.AreEqual(sb, Arrays.CopyOfRange(sa, 3, sa.Length)));
            Assert.IsFalse(Arrays.AreAllZeroes(sb, 0, sb.Length));
        }

        private static byte[] Filled(int length)
        {
            byte[] buf = new byte[length];
            Arrays.Fill(buf, Fill);
            return buf;
        }
    }
}
