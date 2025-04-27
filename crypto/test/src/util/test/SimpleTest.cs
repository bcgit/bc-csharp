using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Threading;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Utilities.Test
{
    public abstract class SimpleTest
        : ITest
    {
        private static readonly string DataDirName = "bc-test-data";

        internal static readonly string NewLine = Environment.NewLine;

        private static string m_testDataPath;

        public abstract string Name { get; }

		private ITestResult Success() => SimpleTestResult.Successful(this, "Okay");

        internal void Fail(string message) => throw new TestFailedException(SimpleTestResult.Failed(this, message));

        internal void Fail(string message, Exception throwable) =>
            throw new TestFailedException(SimpleTestResult.Failed(this, message, throwable));

		internal void Fail(string message, object expected, object found) =>
            throw new TestFailedException(SimpleTestResult.Failed(this, message, expected, found));

        internal void FailIf(string message, bool condition)
        {
            if (condition)
            {
                Fail(message);
            }
        }

        internal void IsTrue(bool value) => IsTrue("no message", value);

        internal void IsTrue(string message, bool value) => FailIf(message, !value);

        internal void IsEquals(bool a, bool b) => IsEquals("no message", a, b);

        internal void IsEquals(int a, int b) => IsEquals("no message", a, b);

        internal void IsEquals(long a, long b) => IsEquals("no message", a, b);

        internal void IsEquals(object a, object b) => IsEquals("no message", a, b);

        internal void IsEquals(string message, bool a, bool b) => FailIf(message, a != b);

        internal void IsEquals(string message, int a, int b) => FailIf(message, a != b);

        internal void IsEquals(string message, long a, long b) => FailIf(message, a != b);

        internal void IsEquals(string message, object a, object b) => FailIf(message, !Objects.Equals(a, b));

        internal bool AreEqual(byte[] a, byte[] b) => Arrays.AreEqual(a, b);

        internal bool AreEqual(byte[] a, int aFromIndex, int aToIndex, byte[] b, int bFromIndex, int bToIndex) =>
            Arrays.AreEqual(a, aFromIndex, aToIndex, b, bFromIndex, bToIndex);

		public virtual ITestResult Perform()
        {
            try
            {
                PerformTest();

				return Success();
            }
            catch (TestFailedException e)
            {
                return e.Result;
            }
            catch (Exception e)
            {
                return SimpleTestResult.Failed(this, "Exception: " +  e, e);
            }
        }

		internal static void RunTest(ITest test) => RunTest(test, Console.Out);

		internal static void RunTest(ITest test, TextWriter outStream)
        {
            ITestResult result = test.Perform();

			outStream.WriteLine(result.ToString());
            if (result.GetException() != null)
            {
                outStream.WriteLine(result.GetException().StackTrace);
            }
        }

        internal static byte[] GetTestData(string name) => Streams.ReadAll(GetTestDataAsStream(name));

        internal static Stream GetTestDataAsStream(string name) =>
            GetAssembly().GetManifestResourceStream(GetFullName(name));

		internal static string[] GetTestDataEntries(string prefix)
		{
			string fullPrefix = GetFullName(prefix);

			var result = new List<string>();
			string[] fullNames = GetAssembly().GetManifestResourceNames();
			foreach (string fullName in fullNames)
			{
				if (fullName.StartsWith(fullPrefix))
				{
					string name = GetShortName(fullName);
					result.Add(name);
				}
			}
            return result.ToArray();
		}

        private static Assembly GetAssembly() => typeof(SimpleTest).Assembly;

        private static string GetFullName(string name) => "Org.BouncyCastle.data." + name;

        private static string GetShortName(string fullName) => fullName.Substring("Org.BouncyCastle.data.".Length);

		public abstract void PerformTest();

        public static DateTime MakeUtcDateTime(int year, int month, int day, int hour, int minute, int second) =>
            new DateTime(year, month, day, hour, minute, second, DateTimeKind.Utc);

        public static DateTime MakeUtcDateTime(int year, int month, int day, int hour, int minute, int second,
            int millisecond)
        {
            return new DateTime(year, month, day, hour, minute, second, millisecond, DateTimeKind.Utc);
        }

        public static void TestBitStringConstant(int bitNo, int value)
        {
            int expectedValue = 1 << ((bitNo | 7) - (bitNo & 7));
            if (expectedValue != value)
                throw new ArgumentException("bit value " + bitNo + " wrong");
        }

        internal static TValue EnsureSingletonInitialized<TValue>(ref TValue value, Func<TValue> initialize)
            where TValue : class
        {
            TValue currentValue = Volatile.Read(ref value);
            if (null != currentValue)
                return currentValue;

            TValue candidateValue = initialize();

            return Interlocked.CompareExchange(ref value, candidateValue, null) ?? candidateValue;
        }

        private static string FindTestDataPath()
        {
            string wrkDirPath = Directory.GetCurrentDirectory();
            string dataDirPath;
            while (!Directory.Exists(dataDirPath = Path.Combine(wrkDirPath, DataDirName)))
            {
                wrkDirPath = Path.GetDirectoryName(wrkDirPath) ??
                    throw new DirectoryNotFoundException("Test data directory " + DataDirName + " not found." + NewLine +
                        "Test data available from: https://github.com/bcgit/bc-test-data.git");
            }
            return dataDirPath;
        }

        internal static Stream FindTestResource(string path) =>
            File.OpenRead(Path.Combine(GetTestDataPath(), path));

        internal static Stream FindTestResource(string path1, string path2) =>
            File.OpenRead(Path.Combine(GetTestDataPath(), path1, path2));

        internal static Stream FindTestResource(string path1, string path2, string path3) =>
            File.OpenRead(Path.Combine(GetTestDataPath(), path1, path2, path3));

        private static string GetTestDataPath() => EnsureSingletonInitialized(ref m_testDataPath, FindTestDataPath);
    }
}
