#nullable disable

using System.Collections.Generic;
using System.Net;
using Altinn.Platform.Storage.Filters;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Xunit;

namespace Altinn.Platform.Storage.UnitTest.Filters;

public class ClientIpCheckActionFilterAttributeTests
{
    [Fact]
    public void OnActionExecuting_NoHeaderAndNoRemoteIp_ForbidsRequest()
    {
        // Arrange
        ClientIpCheckActionFilterAttribute filter = new() { Safelist = "10.0.0.1" };
        ActionExecutingContext context = CreateContext();

        // Act
        filter.OnActionExecuting(context);

        // Assert
        Assert.IsType<ForbidResult>(context.Result);
    }

    [Fact]
    public void OnActionExecuting_NoHeaderAndSafelistedRemoteIp_AllowsRequest()
    {
        // Arrange
        ClientIpCheckActionFilterAttribute filter = new() { Safelist = "10.0.0.1" };
        ActionExecutingContext context = CreateContext(remoteIpAddress: "10.0.0.1");

        // Act
        filter.OnActionExecuting(context);

        // Assert
        Assert.Null(context.Result);
    }

    [Fact]
    public void OnActionExecuting_SafelistedForwardedIp_AllowsRequest()
    {
        // Arrange
        ClientIpCheckActionFilterAttribute filter = new()
        {
            Safelist = "10.0.0.1;10.0.0.2",
        };
        ActionExecutingContext context = CreateContext(forwardedFor: "10.0.0.1");

        // Act
        filter.OnActionExecuting(context);

        // Assert
        Assert.Null(context.Result);
    }

    [Fact]
    public void OnActionExecuting_SafelistedPrependedForwardedIp_ForbidsRequest()
    {
        // Arrange
        ClientIpCheckActionFilterAttribute filter = new() { Safelist = "10.0.0.1" };
        ActionExecutingContext context = CreateContext(
            forwardedFor: "10.0.0.1, 203.0.113.9"
        );

        // Act
        filter.OnActionExecuting(context);

        // Assert
        Assert.IsType<ForbidResult>(context.Result);
    }

    [Fact]
    public void OnActionExecuting_SafelistedRightmostForwardedIp_AllowsRequest()
    {
        // Arrange
        ClientIpCheckActionFilterAttribute filter = new() { Safelist = "10.0.0.1" };
        ActionExecutingContext context = CreateContext(
            forwardedFor: "203.0.113.9, 10.0.0.1"
        );

        // Act
        filter.OnActionExecuting(context);

        // Assert
        Assert.Null(context.Result);
    }

    [Fact]
    public void OnActionExecuting_SubstringOfSafelistedIp_ForbidsRequest()
    {
        // Arrange
        ClientIpCheckActionFilterAttribute filter = new() { Safelist = "10.0.0.1" };
        ActionExecutingContext context = CreateContext(forwardedFor: "10.0.0.10");

        // Act
        filter.OnActionExecuting(context);

        // Assert
        Assert.IsType<ForbidResult>(context.Result);
    }

    [Fact]
    public void OnActionExecuting_SafelistedForwardedIpWithPort_AllowsRequest()
    {
        // Arrange
        ClientIpCheckActionFilterAttribute filter = new() { Safelist = "10.0.0.1" };
        ActionExecutingContext context = CreateContext(forwardedFor: "10.0.0.1:12345");

        // Act
        filter.OnActionExecuting(context);

        // Assert
        Assert.Null(context.Result);
    }

    [Fact]
    public void OnActionExecuting_EmptySafelist_ForbidsRequest()
    {
        // Arrange
        ClientIpCheckActionFilterAttribute filter = new() { Safelist = string.Empty };
        ActionExecutingContext context = CreateContext(forwardedFor: "10.0.0.1");

        // Act
        filter.OnActionExecuting(context);

        // Assert
        Assert.IsType<ForbidResult>(context.Result);
    }

    [Fact]
    public void OnActionExecuting_InvalidForwardedIp_ForbidsRequest()
    {
        // Arrange
        ClientIpCheckActionFilterAttribute filter = new() { Safelist = "10.0.0.1" };
        ActionExecutingContext context = CreateContext(forwardedFor: "garbage");

        // Act
        filter.OnActionExecuting(context);

        // Assert
        Assert.IsType<ForbidResult>(context.Result);
    }

    private static ActionExecutingContext CreateContext(
        string remoteIpAddress = null,
        string forwardedFor = null
    )
    {
        DefaultHttpContext httpContext = new();
        if (remoteIpAddress is not null)
        {
            httpContext.Connection.RemoteIpAddress = IPAddress.Parse(remoteIpAddress);
        }

        if (forwardedFor is not null)
        {
            httpContext.Request.Headers["X-Forwarded-For"] = forwardedFor;
        }

        ActionContext actionContext = new(httpContext, new RouteData(), new ActionDescriptor());
        return new ActionExecutingContext(
            actionContext,
            new List<IFilterMetadata>(),
            new Dictionary<string, object>(),
            new object()
        );
    }
}
