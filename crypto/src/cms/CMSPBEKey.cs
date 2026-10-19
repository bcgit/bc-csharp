using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

//import javax.crypto.interfaces.PBEKey;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// Base class for password-based keys used with CMS enveloped-data recipients. Passed to
    /// <see cref="CmsEnvelopedGenerator.AddPasswordRecipient"/>.
    /// </summary>
    public abstract class CmsPbeKey
        // TODO Create an equivalent interface somewhere?
        // : PBEKey
        : ICipherParameters
    {
        internal readonly char[] password;
        internal readonly byte[] salt;
        internal readonly int iterationCount;

        /// <summary>Creates a PBE key from explicit password, salt, and iteration count.</summary>
        /// <param name="password">The password characters.</param>
        /// <param name="salt">The PBKDF2 salt.</param>
        /// <param name="iterationCount">The PBKDF2 iteration count.</param>
        public CmsPbeKey(
            char[] password,
            byte[] salt,
            int iterationCount)
        {
            this.password = (char[])password.Clone();
            this.salt = Arrays.Clone(salt);
            this.iterationCount = iterationCount;
        }

        /// <summary>Creates a PBE key from a password and PBKDF2 AlgorithmIdentifier.</summary>
        /// <param name="password">The password characters.</param>
        /// <param name="keyDerivationAlgorithm">The PBKDF2 algorithm identifier.</param>
        /// <exception cref="ArgumentException">The key derivation algorithm is not PBKDF2.</exception>
        public CmsPbeKey(
            char[] password,
            AlgorithmIdentifier keyDerivationAlgorithm)
        {
            if (!keyDerivationAlgorithm.Algorithm.Equals(PkcsObjectIdentifiers.IdPbkdf2))
                throw new ArgumentException("Unsupported key derivation algorithm: "
                    + keyDerivationAlgorithm.Algorithm);

            Pbkdf2Params kdfParams = Pbkdf2Params.GetInstance(
                keyDerivationAlgorithm.Parameters.ToAsn1Object());

            this.password = (char[])password.Clone();
            this.salt = kdfParams.GetSalt();
            // The count is attacker-supplied and unauthenticated (CMS EnvelopedData has no integrity gate before
            // the KEK is derived), so bound it before deriving; CPU-DoS guard shared with the PKCS#8/PBES2 path.
            this.iterationCount = PbeUtilities.CheckPbeIterationCount(kdfParams.IterationCountObject);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Creates a PBE key from explicit password, salt, and iteration count.</summary>
        public CmsPbeKey(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt, int iterationCount)
        {
            this.password = password.ToArray();
            this.salt = salt.ToArray();
            this.iterationCount = iterationCount;
        }

        /// <summary>Creates a PBE key from a password and PBKDF2 AlgorithmIdentifier.</summary>
        /// <exception cref="ArgumentException">The key derivation algorithm is not PBKDF2.</exception>
        public CmsPbeKey(ReadOnlySpan<char> password, AlgorithmIdentifier keyDerivationAlgorithm)
        {
            if (!keyDerivationAlgorithm.Algorithm.Equals(PkcsObjectIdentifiers.IdPbkdf2))
                throw new ArgumentException("Unsupported key derivation algorithm: "
                    + keyDerivationAlgorithm.Algorithm);

            Pbkdf2Params kdfParams = Pbkdf2Params.GetInstance(keyDerivationAlgorithm.Parameters.ToAsn1Object());

            this.password = password.ToArray();
            this.salt = kdfParams.GetSalt();
            // The count is attacker-supplied and unauthenticated (CMS EnvelopedData has no integrity gate before
            // the KEK is derived), so bound it before deriving; CPU-DoS guard shared with the PKCS#8/PBES2 path.
            this.iterationCount = PbeUtilities.CheckPbeIterationCount(kdfParams.IterationCountObject);
        }
#endif

        ~CmsPbeKey()
        {
            // ZeroMemory (not Array.Clear) so the JIT cannot elide the wipe of the secret password
            // as a dead store; see the CLAUDE.md constant-time/zeroization guidance.
            Arrays.ZeroMemory(this.password);
        }

        /// <summary>Gets a copy of the PBKDF2 salt.</summary>
        public byte[] Salt
        {
            get { return Arrays.Clone(salt); }
        }

        /// <summary>Gets the PBKDF2 iteration count.</summary>
        public int IterationCount
        {
            get { return iterationCount; }
        }

        /// <summary>Gets the key algorithm name (<c>PKCS5S2</c>).</summary>
        public string Algorithm
        {
            get { return "PKCS5S2"; }
        }

        /// <summary>Gets the encoding format name (<c>RAW</c>).</summary>
        public string Format
        {
            get { return "RAW"; }
        }

        /// <summary>Returns null; raw encoding is not supported.</summary>
        /// <returns>Always null.</returns>
        public byte[] GetEncoded()
        {
            return null;
        }

        internal abstract KeyParameter GetEncoded(DerObjectIdentifier algorithmOid);
    }
}
