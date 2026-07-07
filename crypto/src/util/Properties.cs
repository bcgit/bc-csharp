using System;
using System.Collections.Generic;
using System.Threading;

namespace Org.BouncyCastle.Utilities
{
    /// <summary>Utility methods for managing properties.</summary>
    /// <remarks>Properties may be thread properties, managed by this class, or environment variables
    /// visible only when the corresponding thread property is not set. This API has no facilities for modifying
    /// environment variables, though it may read them.
    /// </remarks>
    public static class Properties
    {
        /// <summary>
        /// The maximum permitted memory exponent (i.e. <c>memory &lt;= (1 &lt;&lt; MaxMemoryExp)</c>.
        /// </summary>
        /// <remarks>
        /// Defaults to 24 (16 GiB); the property may be raised up to a ceiling of 30.
        /// </remarks>
        public static readonly string Argon2MaxMemoryExp = "Org.BouncyCastle.Argon2.MaxMemoryExp";

        /// <summary>
        /// The maximum number of Argon2 passes (iterations) accepted when a key is derived from untrusted cost
        /// parameters.
        /// </summary>
        /// <remarks>
        /// Defaults to 10.
        /// </remarks>
        public static readonly string Argon2MaxPasses = "Org.BouncyCastle.Argon2.MaxPasses";

        /// <summary>
        /// The maximum Argon2 parallelism (lanes) accepted when a key is derived from untrusted cost parameters.
        /// </summary>
        /// <remarks>
        /// Defaults to 16.
        /// </remarks>
        public static readonly string Argon2MaxParallelism = "Org.BouncyCastle.Argon2.MaxParallelism";

        public static readonly string Asn1AllowUnsafeInteger = "Org.BouncyCastle.Asn1.AllowUnsafeInteger";

        public static readonly string Asn1MaxDepth = "Org.BouncyCastle.Asn1.MaxDepth";

        public static readonly string Asn1MaxLimit = "Org.BouncyCastle.Asn1.MaxLimit";

        public static readonly string DHMaxSize = "Org.BouncyCastle.DH.MaxSize";

        public static readonly string DsaMaxSize = "Org.BouncyCastle.Dsa.MaxSize";

        public static readonly string ECF2mMaxSize = "Org.BouncyCastle.EC.F2m_MaxSize";

        public static readonly string ECFpMaxSize = "Org.BouncyCastle.EC.Fp_MaxSize";

        public static readonly string ECFpCertainty = "Org.BouncyCastle.EC.Fp_Certainty";

        public static readonly string FpeDisable = "Org.BouncyCastle.Fpe.Disable";

        public static readonly string FpeDisableFf1 = "Org.BouncyCastle.Fpe.Disable_Ff1";

        /// <summary>
        /// Upper bound on the PBKDF2 iteration count honoured when decrypting a PBES2-protected PKCS#8/PEM private key.
        /// </summary>
        /// <remarks>
        /// The key-derivation parameters travel inside the (unauthenticated) encrypted-key container, so an unbounded
        /// count makes decrypting attacker-supplied key material a CPU-exhaustion vector. Default 5,000,000.
        /// </remarks>
        public static readonly string PbeMaxIterationCount = "Org.BouncyCastle.Pbe.MaxIterationCount";

        /// <summary>
        /// Upper bound, in bytes, on the scrypt working memory (~128 * N * r) honoured when decrypting a
        /// PBES2-protected PKCS#8 / PEM private key.
        /// </summary>
        /// <remarks>
        /// As with <see cref="PbeMaxIterationCount"/> the scrypt cost travels in the unauthenticated container, so an
        /// unbounded cost is a memory-exhaustion vector. Default 1073741824 (1 GiB).
        /// </remarks>
        public static readonly string PbeMaxScryptMemory = "Org.BouncyCastle.Pbe.MaxScryptMemory";

        /// <summary>
        /// When set to <c>true</c>, suppresses the error raised when loading a PKCS12 store with a password, for data
        /// that does not require a password.
        /// </summary>
        public static readonly string Pkcs12IgnoreUselessPassword = "Org.BouncyCastle.Pkcs12.IgnoreUselessPassword";

        /// <summary>
        /// If set, a PKCS12 file with a larger iteration count on PBE processing will be rejected. Default 5,000,000.
        /// </summary>
        public static readonly string Pkcs12MaxIterationCount = "Org.BouncyCastle.Pkcs12.MaxIterationCount";

        public static readonly string Pkcs1NotStrict = "Org.BouncyCastle.Pkcs1.NotStrict";

        /// <summary>
        /// Upper bound on the RFC 4211 PKMAC / CMP password-based-MAC iteration count honoured when no explicit ceiling
        /// is supplied.
        /// </summary>
        /// <remarks>
        /// The count travels in the (unauthenticated) PBMParameter of an incoming CMP message and drives an iterated
        /// hash, so an unbounded count makes verifying an attacker-supplied message a CPU-exhaustion vector. Default
        /// 1,000,000.
        /// </remarks>
        public static readonly string PKMacMaxIterationCount = "Org.BouncyCastle.PKMac.MaxIterationCount";

        public static readonly string RsaAllowUnsafeModulus = "Org.BouncyCastle.Rsa.AllowUnsafeModulus";

        public static readonly string RsaMaxMRTests = "Org.BouncyCastle.Rsa.MaxMRTests";

        public static readonly string RsaMaxSize = "Org.BouncyCastle.Rsa.MaxSize";

        public static readonly string X509AllowNonDerTbsCertificate = "Org.BouncyCastle.X509.Allow_Non-DER_TBSCert";

        public static readonly string X509MaxPolicyNodes = "Org.BouncyCastle.X509.MaxPolicyNodes";

        /// <summary>
        /// Opt in to the relaxed directoryName name-constraint matching required by GSMA SGP.22 v2.5 (Remote SIM
        /// Provisioning), sections 4.5.2.1.0.2 / 4.5.2.1.0.3. When set, a permitted-subtree RDN is satisfied by any
        /// matching subject RDN regardless of position, additional subject attributes beyond those named in the subtree
        /// are tolerated, and a serialNumber RDN is matched with a <c>StartsWith</c> comparison wherever it appears.
        /// This is deliberately looser than the contiguous-prefix DN matching mandated by RFC 5280 7.1, so it defaults
        /// to off and must be enabled explicitly; BC's default validation remains RFC 5280 strict.
        /// </summary>
        public static readonly string X509Sgp22NameConstraints = "Org.BouncyCastle.X509.Sgp22NameConstraints";

        /// <summary>
        /// Fall back to the legacy lenient parsing of rfc822Name values in X.509 name-constraint checks. By default the
        /// validator is strict about rfc822Name conformance; today that means a tested rfc822Name with more than one
        /// '@' is rejected as ambiguous when email constraints apply (RFC 5321 sec. 4.1.2 allows '@' inside a quoted
        /// local part, so the domain is not simply the text after the first '@', and a wrong split could evade a
        /// constraint). When set, that strictness (and any future rfc822Name conformance strictness) is disabled and
        /// the historical permissive parsing is used instead. Strict is the default; set this only to restore the old
        /// behaviour. This is a safety valve, not a recommended mode.
        /// </summary>
        public static readonly string X509AllowLenientRfc822Name = "Org.BouncyCastle.X509.AllowLenientRfc822Name";

        /// <summary>
        /// Salvage a non-contiguous iPAddress name-constraint subnet mask instead of rejecting it. An iPAddress
        /// name constraint carries a subnet mask expected to be CIDR (a run of leading 1-bits); a non-contiguous
        /// mask is malformed per RFC 4632 and also lets the subtree set-algebra mint new ranges (a super-linear
        /// blow-up on hostile input). By default such a constraint is rejected (fail-closed). When set, the mask
        /// is instead rounded to the most-restrictive contiguous mask for its context - a permitted subtree is
        /// narrowed (fill up to the last 1-bit; under-permit), an excluded subtree is broadened (keep only the
        /// leading 1-bits; over-exclude) - so validation can only get stricter, never laxer. Strict rejection is
        /// the default; this is a safety valve, not a recommended mode.
        /// </summary>
        public static readonly string X509AllowLenientIPAddressMask =
            "Org.BouncyCastle.X509.AllowLenientIPAddressMask";

        private static readonly ThreadLocal<Dictionary<string, string>> ThreadProperties =
            new ThreadLocal<Dictionary<string, string>>();

        public static void Clear() => ThreadProperties.Value = null;

        public static void ClearThreadProperties() => ThreadProperties.Value?.Clear();

        public static bool GetBoolean(string propertyName, bool defaultValue) =>
            TryGetBoolean(propertyName, out bool propertyValue) ? propertyValue : defaultValue;

        public static int GetInt32(string propertyName, int defaultValue) =>
            TryGetInt32(propertyName, out int propertyValue) ? propertyValue : defaultValue;

        public static long GetInt64(string propertyName, long defaultValue) =>
            TryGetInt64(propertyName, out long propertyValue) ? propertyValue : defaultValue;

        /// <summary>
        /// Return the <c>string</c> value of the property <paramref name="name"/>.
        /// </summary>
        /// <remarks>
        /// Property evaluation order is thread properties first, then environment variables.
        /// </remarks>
        /// <param name="name">The name of the property.</param>
        /// <returns>
        /// The <c>string</c> value of the <paramref name="name"/> property, or <c>null</c> if not defined.
        /// </returns>
        public static string GetProperty(string name) =>
            GetThreadProperty(name) ?? Platform.GetEnvironmentVariable(name);

        /// <summary>
        /// Return the <c>string</c> value of the property <paramref name="name"/>, or
        /// <paramref name="defaultValue"/> if that property is not defined.
        /// </summary>
        /// <remarks>
        /// Property evaluation order is thread properties first, then environment variables.
        /// </remarks>
        /// <param name="name">The name of the property.</param>
        /// <param name="defaultValue">The default value to return in case the property is not defined.</param>
        /// <returns>
        /// The <c>string</c> value of the <paramref name="name"/> property, or <paramref name="defaultValue"/>
        /// if not defined.
        /// </returns>
        public static string GetProperty(string name, string defaultValue) => GetProperty(name) ?? defaultValue;

        public static string GetThreadProperty(string name)
        {
            if (name == null)
                throw new ArgumentNullException(nameof(name));

            var threadProperties = ThreadProperties.Value;
            if (threadProperties != null && threadProperties.TryGetValue(name, out var value))
                return value;

            return null;
        }

        public static bool RemoveThreadProperty(string name)
        {
            if (name == null)
                throw new ArgumentNullException(nameof(name));

            var threadProperties = ThreadProperties.Value;
            if (threadProperties != null)
                return threadProperties.Remove(name);

            return false;
        }

        public static void SetThreadBoolean(string propertyName, bool propertyValue) =>
            SetThreadProperty(propertyName, propertyValue.ToString());

        public static void SetThreadInt32(string propertyName, int propertyValue) =>
            SetThreadProperty(propertyName, propertyValue.ToString());

        public static void SetThreadInt64(string propertyName, long propertyValue) =>
            SetThreadProperty(propertyName, propertyValue.ToString());

        public static void SetThreadProperty(string name, string value)
        {
            if (name == null)
                throw new ArgumentNullException(nameof(name));
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            var threadProperties = ThreadProperties.Value ?? InitThreadProperties();

            threadProperties[name] = value;
        }

        public static bool TryGetBoolean(string propertyName, out bool propertyValue) =>
            bool.TryParse(GetProperty(propertyName), out propertyValue);

        public static bool TryGetInt32(string propertyName, out int propertyValue) =>
            int.TryParse(GetProperty(propertyName), out propertyValue);

        public static bool TryGetInt64(string propertyName, out long propertyValue) =>
            long.TryParse(GetProperty(propertyName), out propertyValue);

        public static void WithThreadProperty(string name, string value, Action action) =>
            WithThreadProperty<object, object>(name, value, arg: null, (object ignore) => { action(); return null; });

        public static TResult WithThreadProperty<TResult>(string name, string value, Func<TResult> func) =>
            WithThreadProperty<object, TResult>(name, value, arg: null, (object ignore) => func());

        public static TResult WithThreadProperty<TArg, TResult>(string name, string value, TArg arg,
            Func<TArg, TResult> func)
        {
            if (name == null)
                throw new ArgumentNullException(nameof(name));
            if (value == null)
                throw new ArgumentNullException(nameof(value));
            if (func == null)
                throw new ArgumentNullException(nameof(func));

            string previousValue = GetThreadProperty(name);

            SetThreadProperty(name, value);

            try
            {
                return func.Invoke(arg);
            }
            finally
            {
                if (previousValue == null)
                {
                    RemoveThreadProperty(name);
                }
                else
                {
                    SetThreadProperty(name, previousValue);
                }
            }
        }

        private static Dictionary<string, string> InitThreadProperties()
        {
            var threadProperties = new Dictionary<string, string>();
            ThreadProperties.Value = threadProperties;
            return threadProperties;
        }
    }
}
