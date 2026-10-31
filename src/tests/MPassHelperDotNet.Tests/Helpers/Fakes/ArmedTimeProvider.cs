using System;
using System.Threading;
using Microsoft.Extensions.Time.Testing;

namespace MPassHelperDotNet.Tests.Helpers.Fakes
{
    internal sealed class ArmedTimeProvider : FakeTimeProvider
    {
        private Action _armed;

        internal ArmedTimeProvider(DateTimeOffset start) : base(start)
        {
        }

        internal bool Fired { get; private set; }

        internal void Arm(Action action) => Volatile.Write(ref _armed, action);

        public override DateTimeOffset GetUtcNow()
        {
            var action = Interlocked.Exchange(ref _armed, null);
            if (action != null)
            {
                Fired = true;
                action();
            }

            return base.GetUtcNow();
        }
    }
}
