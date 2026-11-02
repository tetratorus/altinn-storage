#nullable disable

using System;
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
    public void OnActionExecuting_NoRemoteIpAndNoHeader_Forbidden()
    {
        ClientIpCheckActionFilterAttribute filter = new() { Safelist = "10.0.0.1" };
        ActionExecutingContext context = CreateContext(null);

        filter.OnActionExecuting(context);

        Assert.IsType<ForbidResult>(context.Result);
    }

    [Fact]
    public void OnActionExecuting_SpoofedAllowlistedXForwardedFor_Forbidden()
    {
        ClientIpCheckActionFilterAttribute filter = new() { Safelist = "10.0.0.1" };
        ActionExecutingContext context = CreateContext("203.0.113.7", "10.0.0.1, 203.0.113.7");

        filter.OnActionExecuting(context);

        Assert.IsType<ForbidResult>(context.Result);
    }

    [Theory]
    [InlineData("110.0.0.12")]
    [InlineData("10.0.0.12")]
    [InlineData("10.0.0.10")]
    public void OnActionExecuting_SuperstringOfAllowlistedIp_Forbidden(string remoteIp)
    {
        ClientIpCheckActionFilterAttribute filter = new() { Safelist = "10.0.0.1" };
        ActionExecutingContext context = CreateContext(remoteIp, remoteIp);

        filter.OnActionExecuting(context);

        Assert.IsType<ForbidResult>(context.Result);
    }

    [Theory]
    [InlineData("")]
    [InlineData(";")]
    [InlineData(" ; ")]
    [InlineData(null)]
    public void OnActionExecuting_EmptySafelist_Forbidden(string safelist)
    {
        ClientIpCheckActionFilterAttribute filter = new() { Safelist = safelist };
        ActionExecutingContext context = CreateContext("10.0.0.1", "10.0.0.1");

        filter.OnActionExecuting(context);

        Assert.IsType<ForbidResult>(context.Result);
    }

    [Theory]
    [InlineData("10.0.0.1")]
    [InlineData("::ffff:10.0.0.1")]
    [InlineData("192.168.1.20")]
    public void OnActionExecuting_RemoteIpInSafelist_Allowed(string remoteIp)
    {
        ClientIpCheckActionFilterAttribute filter = new() { Safelist = "10.0.0.1; 192.168.1.20" };
        ActionExecutingContext context = CreateContext(remoteIp);

        filter.OnActionExecuting(context);

        Assert.Null(context.Result);
    }

    [Theory]
    [InlineData("10.0.0")]
    [InlineData("10")]
    [InlineData("not-an-ip")]
    [InlineData("10.0.0.1/24")]
    public void Safelist_InvalidEntry_Throws(string safelist)
    {
        ClientIpCheckActionFilterAttribute filter = new();

        Assert.Throws<FormatException>(() => filter.Safelist = safelist);
    }

    private static ActionExecutingContext CreateContext(string remoteIp, string forwardedFor = null)
    {
        DefaultHttpContext httpContext = new();
        if (remoteIp is not null)
        {
            httpContext.Connection.RemoteIpAddress = IPAddress.Parse(remoteIp);
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
            controller: null
        );
    }
}
