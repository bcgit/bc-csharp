using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;

// Deliberately outside any namespace: a SetUpFixture covers its namespace and everything below it, so here that is
// the whole assembly.
[SetUpFixture]
public class EnvironmentSetUp
{
    private readonly HashSet<string> m_providedDefaults = new HashSet<string>();

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        ProvideDefault(Properties.Pkcs12StoreIterationCount, "4096");
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        foreach (string name in m_providedDefaults)
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }

    // Leave an externally supplied value alone, so a run can still opt back into library defaults.
    private void ProvideDefault(string name, string value)
    {
        if (Environment.GetEnvironmentVariable(name) == null)
        {
            Environment.SetEnvironmentVariable(name, value);
            m_providedDefaults.Add(name);
        }
    }
}
