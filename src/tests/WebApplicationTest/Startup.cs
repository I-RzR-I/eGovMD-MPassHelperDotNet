// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.WebApplicationTest
//  Author           : RzR
//  Created On       : 2023-06-25 01:34
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-30 14:07
// ***********************************************************************
//  <copyright file="Startup.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.OpenApi.Models;
using MPassHelperDotNet.XDependencyInjection;

#endregion

namespace WebApplicationTest
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo {Title = "WebApplicationTest", Version = "v1"});
            });

            services.AddMPassService(Configuration);
            services.AddHealthChecks()
                .AddMPassCertificateHealthCheck("MPass");
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "WebApplicationTest v1"));
            }

            app.UseStaticFiles();
            app.UseHealthChecks("/health");

            app.UseRouting();

            app.UseAuthorization();

            app.UseEndpoints(endpoints => { endpoints.MapControllers(); });
        }
    }
}