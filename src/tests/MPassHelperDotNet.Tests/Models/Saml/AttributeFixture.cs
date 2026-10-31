using System;
using System.Collections.Generic;

namespace MPassHelperDotNet.Tests.Models.Saml
{
    internal sealed class AttributeFixture
    {
        public AttributeFixture(string name, params string[] values)
        {
            Name = name;
            Values = new List<string>(values ?? Array.Empty<string>());
        }

        public string Name { get; set; }

        public List<string> Values { get; }

        public bool ValuesAsMarkup { get; set; }
    }
}
