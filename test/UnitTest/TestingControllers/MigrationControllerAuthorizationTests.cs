#nullable disable

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Altinn.Common.AccessToken.Constants;
using Altinn.Common.AccessToken.Services;
using Altinn.Common.PEP.Interfaces;
using Altinn.Platform.Storage.Clients;
using Altinn.Platform.Storage.Controllers;
using Altinn.Platform.Storage.Filters;
using Altinn.Platform.Storage.Models;
using Altinn.Platform.Storage.Repository;
using Altinn.Platform.Storage.UnitTest.Fixture;
using Altinn.Platform.Storage.UnitTest.Mocks;
using Altinn.Platform.Storage.UnitTest.Mocks.Authentication;
using Altinn.Platform.Storage.UnitTest.Mocks.Clients;
using Altinn.Platform.Storage.UnitTest.Mocks.Repository;
using Altinn.Platform.Storage.UnitTest.Utils;
using Altinn.Platform.Storage.Wrappers;
using AltinnCore.Authentication.JwtCookie;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Wolverine;
using Xunit;

namespace Altinn.Platform.Storage.UnitTest.TestingControllers;

public class MigrationControllerAuthorizationTests(
    MigrationControllerAuthorizationTests.MigrationHostFixture fixture
) : IClassFixture<MigrationControllerAuthorizationTests.MigrationHostFixture>
{
    private const string _allowedIp = "10.0.0.1";
    private const string _deletePath = "storage/api/v1/migration/delete/";
    private const string _testRemoteIpHeader = "X-Test-Remote-Ip";

    private readonly HttpClient _client = fixture.Client;

    [Fact]
    public async Task Delete_NoAccessTokenAndNoForwardedHeader_Rejected()
    {
        using HttpRequestMessage request = CreateRequest(_allowedIp);

        HttpResponseMessage response = await _client.SendAsync(request);

        AssertRejected(response);
    }

    [Fact]
    public async Task Delete_NoAccessTokenWithSpoofedForwardedHeader_Rejected()
    {
        using HttpRequestMessage request = CreateRequest("203.0.113.7");
        request.Headers.Add("X-Forwarded-For", $"{_allowedIp}, 203.0.113.7");

        HttpResponseMessage response = await _client.SendAsync(request);

        AssertRejected(response);
    }

    [Fact]
    public async Task Delete_AccessTokenFromNonPlatformIssuer_Rejected()
    {
        using HttpRequestMessage request = CreateRequest(_allowedIp);
        request.Headers.Add("PlatformAccessToken", CreatePlatformSignedToken("ttd"));

        HttpResponseMessage response = await _client.SendAsync(request);

        AssertRejected(response);
    }

    [Theory]
    [InlineData("203.0.113.7", null)]
    [InlineData("203.0.113.7", _allowedIp)]
    [InlineData("110.0.0.12", "110.0.0.12")]
    public async Task Delete_PlatformAccessTokenFromIpNotInSafelist_Forbidden(
        string remoteIp,
        string forwardedFor
    )
    {
        using HttpRequestMessage request = CreateRequest(remoteIp);
        request.Headers.Add("PlatformAccessToken", PrincipalUtil.GetAccessToken());
        if (forwardedFor is not null)
        {
            request.Headers.Add("X-Forwarded-For", forwardedFor);
        }

        HttpResponseMessage response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Delete_PlatformAccessTokenFromSafelistedIp_ReachesAction()
    {
        using HttpRequestMessage request = CreateRequest(_allowedIp);
        request.Headers.Add("PlatformAccessToken", PrincipalUtil.GetAccessToken());

        HttpResponseMessage response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private static void AssertRejected(HttpResponseMessage response)
    {
        Assert.Contains(
            response.StatusCode,
            new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden }
        );
    }

    private static string CreatePlatformSignedToken(string issuer)
    {
        X509Certificate2 cert = X509CertificateLoader.LoadPkcs12FromFile(
            "platform-org.pfx",
            string.Empty
        );
        SecurityTokenDescriptor descriptor = new()
        {
            Subject = new ClaimsIdentity([
                new Claim(AccessTokenClaimTypes.App, "some-app", ClaimValueTypes.String, issuer),
            ]),
            Expires = DateTime.UtcNow.AddMinutes(1),
            SigningCredentials = new X509SigningCredentials(cert, SecurityAlgorithms.RsaSha256),
            Audience = "altinn.no",
            Issuer = issuer,
        };
        JwtSecurityTokenHandler handler = new();
        return handler.WriteToken(handler.CreateToken(descriptor));
    }

    private static HttpRequestMessage CreateRequest(string remoteIp)
    {
        HttpRequestMessage request = new(HttpMethod.Post, _deletePath + Guid.NewGuid());
        request.Headers.Add(_testRemoteIpHeader, remoteIp);
        return request;
    }

    public sealed class MigrationHostFixture : IDisposable
    {
        private readonly WebApplicationFactory<MigrationController> _factory;

        public MigrationHostFixture()
        {
            Mock<IInstanceRepository> instanceRepository = new();
            instanceRepository
                .Setup(r => r.GetOne(It.IsAny<Guid>(), false, It.IsAny<CancellationToken>()))
                .ReturnsAsync((InstanceInternal)null);

            _factory = new TestApplicationFactory<MigrationController>().WithWebHostBuilder(
                builder =>
                {
                    builder.ConfigureTestServices(services =>
                    {
                        services.AddMockRepositories();
                        services.AddSingleton(instanceRepository.Object);
                        services.AddSingleton(new Mock<IA2Repository>().Object);
                        services.AddSingleton(new Mock<IKeyVaultClientWrapper>().Object);
                        services.AddSingleton(new Mock<IMessageBus>().Object);
                        services.AddSingleton<
                            IPartiesWithInstancesClient,
                            PartiesWithInstancesClientMock
                        >();
                        services.AddSingleton<IPDP, PepWithPDPAuthorizationMockSI>();
                        services.AddSingleton<
                            IPostConfigureOptions<JwtCookieOptions>,
                            JwtCookiePostConfigureOptionsStub
                        >();
                        services.AddSingleton<IPublicSigningKeyProvider, PlatformKeyForAnyIssuer>();
                        services.AddSingleton(
                            new ClientIpCheckActionFilterAttribute { Safelist = _allowedIp }
                        );
                        services.AddSingleton<IStartupFilter, RemoteIpStartupFilter>();
                    });
                }
            );
            Client = _factory.CreateClient();
        }

        public HttpClient Client { get; }

        public void Dispose()
        {
            Client.Dispose();
            _factory.Dispose();
        }
    }

    private sealed class PlatformKeyForAnyIssuer : IPublicSigningKeyProvider
    {
        private readonly PublicSigningKeyProviderMock _inner = new();

        public Task<IEnumerable<SecurityKey>> GetSigningKeys(string issuer) =>
            _inner.GetSigningKeys("platform");
    }

    private sealed class RemoteIpStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) =>
            app =>
            {
                app.Use(
                    (context, nextMiddleware) =>
                    {
                        context.Connection.RemoteIpAddress = IPAddress.Parse(
                            context.Request.Headers[_testRemoteIpHeader]
                        );
                        return nextMiddleware();
                    }
                );
                next(app);
            };
    }
}
