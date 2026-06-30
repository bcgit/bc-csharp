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
        private static readonly ThreadLocal<Dictionary<string, string>> ThreadProperties =
            new ThreadLocal<Dictionary<string, string>>();

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
            WithThreadProperty<object, object>(name, value, arg: 0, (object ignore) => { action(); return null; });

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
