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
        /// count makes decrypting attacker-supplied key material a CPU-exhaustion vector. Default 10,000,000.
        /// </remarks>
        public static readonly string PbeMaxIterationCount = "Org.BouncyCastle.Pbe.MaxIterationCount";

        /// <summary>
        /// When set to <c>true</c>, suppresses the error raised when loading a PKCS12 store with a password, for data
        /// that does not require a password.
        /// </summary>
        public static readonly string Pkcs12IgnoreUselessPassword = "Org.BouncyCastle.Pkcs12.IgnoreUselessPassword";

        /// <summary>If set, a PKCS12 file with a larger iteration count on PBE processing will be rejected.</summary>
        public static readonly string Pkcs12MaxIterationCount = "Org.BouncyCastle.Pkcs12.MaxIterationCount";

        public static readonly string Pkcs1NotStrict = "Org.BouncyCastle.Pkcs1.NotStrict";

        /// <summary>
        /// Upper bound on the RFC 4211 PKMAC / CMP password-based-MAC iteration count honoured when no explicit ceiling
        /// is supplied.
        /// </summary>
        /// <remarks>
        /// The count travels in the (unauthenticated) PBMParameter of an incoming CMP message and drives an iterated
        /// hash, so an unbounded count makes verifying an attacker-supplied message a CPU-exhaustion vector. Default
        /// 10,000,000.
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
