#nullable disable

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
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
using Altinn.Platform.Storage.Interface.Models;
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
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Wolverine;
using Xunit;

namespace Altinn.Platform.Storage.UnitTest.TestingControllers;

public class CleanupControllerAuthorizationTests(
    CleanupControllerAuthorizationTests.CleanupHostFixture fixture
) : IClassFixture<CleanupControllerAuthorizationTests.CleanupHostFixture>
{
    private const string _basePath = "storage/api/v1/cleanup/";

    public static TheoryData<string> CleanupRoutes =>
        new()
        {
            "cleanupinstances",
            "cleanupinstancemutationidempotency",
            "cleanupinstancesforapp/ttd/some-app",
            "cleanupdataelements",
        };

    [Theory]
    [MemberData(nameof(CleanupRoutes))]
    public async Task Delete_NoAccessToken_UnauthorizedAndNothingDeleted(string route)
    {
        fixture.ResetMocks();
        using HttpRequestMessage request = new(HttpMethod.Delete, _basePath + route);

        HttpResponseMessage response = await fixture.Client.SendAsync(request);

        AssertRejected(response);
        fixture.VerifyRepositoriesNotUsed();
    }

    [Theory]
    [MemberData(nameof(CleanupRoutes))]
    public async Task Delete_AccessTokenFromNonPlatformIssuer_RejectedAndNothingDeleted(
        string route
    )
    {
        fixture.ResetMocks();
        using HttpRequestMessage request = new(HttpMethod.Delete, _basePath + route);
        request.Headers.Add("PlatformAccessToken", CreatePlatformSignedToken("ttd"));

        HttpResponseMessage response = await fixture.Client.SendAsync(request);

        AssertRejected(response);
        fixture.VerifyRepositoriesNotUsed();
    }

    [Theory]
    [MemberData(nameof(CleanupRoutes))]
    public async Task Delete_PlatformAccessToken_ReachesAction(string route)
    {
        fixture.ResetMocks();
        using HttpRequestMessage request = new(HttpMethod.Delete, _basePath + route);
        request.Headers.Add("PlatformAccessToken", PrincipalUtil.GetAccessToken());

        HttpResponseMessage response = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
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

    public sealed class CleanupHostFixture : IDisposable
    {
        private readonly WebApplicationFactory<CleanupController> _factory;

        public CleanupHostFixture()
        {
            ResetMocks();

            _factory = new TestApplicationFactory<CleanupController>().WithWebHostBuilder(
                builder =>
                {
                    builder.ConfigureTestServices(services =>
                    {
                        services.AddMockRepositories();
                        services.AddTransient(_ => InstanceRepository.Object);
                        services.AddTransient(_ => ApplicationRepository.Object);
                        services.AddTransient(_ => BlobRepository.Object);
                        services.AddTransient(_ => DataRepository.Object);
                        services.AddTransient(_ => InstanceEventRepository.Object);
                        services.AddTransient(_ => InstanceMutationRepository.Object);
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
                    });
                }
            );
            Client = _factory.CreateClient();
        }

        public HttpClient Client { get; }

        public Mock<IInstanceRepository> InstanceRepository { get; private set; }

        public Mock<IApplicationRepository> ApplicationRepository { get; private set; }

        public Mock<IBlobRepository> BlobRepository { get; private set; }

        public Mock<IDataRepository> DataRepository { get; private set; }

        public Mock<IInstanceEventRepository> InstanceEventRepository { get; private set; }

        public Mock<IInstanceMutationRepository> InstanceMutationRepository { get; private set; }

        public void ResetMocks()
        {
            InstanceRepository = new Mock<IInstanceRepository>();
            InstanceRepository
                .Setup(r => r.GetHardDeletedInstances(It.IsAny<CancellationToken>()))
                .ReturnsAsync([]);
            InstanceRepository
                .Setup(r => r.GetHardDeletedDataElements(It.IsAny<CancellationToken>()))
                .ReturnsAsync([]);
            InstanceRepository
                .Setup(r =>
                    r.GetInstancesFromQuery(
                        It.IsAny<InstanceQueryParameters>(),
                        It.IsAny<CancellationToken>()
                    )
                )
                .ReturnsAsync(new InstanceQueryResult());

            ApplicationRepository = new Mock<IApplicationRepository>();
            ApplicationRepository.Setup(r => r.FindAll()).ReturnsAsync(new List<Application>());

            BlobRepository = new Mock<IBlobRepository>();
            DataRepository = new Mock<IDataRepository>();
            InstanceEventRepository = new Mock<IInstanceEventRepository>();
            InstanceMutationRepository = new Mock<IInstanceMutationRepository>();
        }

        public void VerifyRepositoriesNotUsed()
        {
            InstanceRepository.VerifyNoOtherCalls();
            ApplicationRepository.VerifyNoOtherCalls();
            BlobRepository.VerifyNoOtherCalls();
            DataRepository.VerifyNoOtherCalls();
            InstanceEventRepository.VerifyNoOtherCalls();
            InstanceMutationRepository.VerifyNoOtherCalls();
        }

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
}
