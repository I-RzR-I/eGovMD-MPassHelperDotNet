using System;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using MPassHelperDotNet.XDependencyInjection;
using MPassHelperDotNet.Tests.Helpers.Certificates;
using MPassHelperDotNet.Tests.Helpers.Logging;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Models.Hosting;

namespace MPassHelperDotNet.Tests.Helpers.Hosting
{
    internal static class ServiceFactory
    {
        internal static MPassTestContext Create(
            MPassTestSettings settings = null,
            Action<IServiceCollection> configureBefore = null,
            Action<IServiceCollection> configureAfter = null,
            FakeTimeProvider time = null)
        {
            settings = settings ?? new MPassTestSettings();
            time = time ?? TestClock.CreateFake();
            var logs = new LogCapture();
            var files = new TestCertificateFiles();
            try
            {
                var configuration = new ConfigurationBuilder()
                    .AddInMemoryCollection(settings.ToConfiguration(files))
                    .Build();

                var services = new ServiceCollection();
                RegisterTestInfrastructure(services, time, logs);
                configureBefore?.Invoke(services);
                services.AddMPassService(configuration);
                configureAfter?.Invoke(services);

                var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });

                return new MPassTestContext(settings, files, time, logs, configuration, provider);
            }
            catch
            {
                files.Dispose();
                throw;
            }
        }

        internal static IHost CreateHost(
            MPassTestSettings settings,
            TestCertificateFiles files,
            LogCapture logs = null,
            FakeTimeProvider time = null,
            Action<IServiceCollection> configureBefore = null,
            Action<IServiceCollection> configureAfter = null)
        {
            var builder = new HostApplicationBuilder(new HostApplicationBuilderSettings
            {
                DisableDefaults = true,
                ApplicationName = "MPassHelperDotNet.Tests",
                EnvironmentName = "Test",
                ContentRootPath = files.DirectoryPath
            });

            builder.Configuration.AddInMemoryCollection(settings.ToConfiguration(files));
            RegisterTestInfrastructure(builder.Services, time ?? TestClock.CreateFake(), logs ?? new LogCapture());
            configureBefore?.Invoke(builder.Services);
            builder.Services.AddMPassService(builder.Configuration);
            configureAfter?.Invoke(builder.Services);

            return builder.Build();
        }

        private static void RegisterTestInfrastructure(IServiceCollection services, FakeTimeProvider time, LogCapture logs)
        {
            services.AddLogging(logging =>
            {
                logging.ClearProviders();
                logging.SetMinimumLevel(LogLevel.Trace);
                logging.AddProvider(logs);
            });
            services.AddSingleton<TimeProvider>(time);
        }
    }
}
